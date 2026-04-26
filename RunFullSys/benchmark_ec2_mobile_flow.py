#!/usr/bin/env python3
import argparse
import csv
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MDU_DIR = ROOT / "MDU"
MDU_APP_DIR = MDU_DIR / "app"
MDU_BUILD_DIR = MDU_APP_DIR / "build-wsl"
MDU_RUNTIME_DIR = MDU_APP_DIR / "runtime"
RESULTS_DIR = ROOT / "experiment_results"
RESULTS_DIR.mkdir(exist_ok=True)

DEFAULT_KEYWORD_COUNTS = [20, 300, 500, 1000]
DEFAULT_RUNS = 5
DEFAULT_POLICY_ATTRS = [f"attr_{index:04d}" for index in range(1, 6)]


def ensure_exists(path: Path):
    if not path.exists():
        raise RuntimeError(f"Missing required path: {path}")


def http_request(url: str, *, method: str = "GET", body: bytes | None = None, headers: dict | None = None,
                 timeout: int = 300) -> tuple[int, bytes, str]:
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(), response.headers.get_content_type()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get_content_type()


def http_json(url: str, *, payload: dict | None = None, timeout: int = 300) -> tuple[int, dict]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    status, response_body, _ = http_request(url, method="POST" if payload is not None else "GET", body=body,
                                            headers=headers, timeout=timeout)
    parsed = json.loads(response_body.decode("utf-8") or "{}")
    return status, parsed


def wait_for_health(base_url: str, timeout_s: float = 20.0):
    deadline = time.time() + timeout_s
    last_error = None
    while time.time() < deadline:
        try:
            status, payload = http_json(f"{base_url.rstrip('/')}/health")
            if status == 200 and payload.get("status") == "ok":
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.3)
    raise RuntimeError(f"Timed out waiting for {base_url}/health: {last_error}")


def untar_bytes(payload: bytes, destination: Path):
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        tar.extractall(destination)


def tar_directory(directory: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for child in sorted(directory.iterdir()):
            tar.add(child, arcname=child.name)
    return buffer.getvalue()


def load_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def rewrite_local_credential(cred_path: Path):
    gid = cred_path.stem
    user_key_path = MDU_RUNTIME_DIR / "users" / f"{gid}_userkey.bin"
    lines = cred_path.read_text(encoding="utf-8").splitlines()
    updated: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith("user_key_path="):
            updated.append(f"user_key_path={user_key_path}")
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(f"user_key_path={user_key_path}")
    cred_path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def sync_mdu_runtime_from_ta(ta_url: str):
    MDU_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

    status, state_archive, _ = http_request(f"{ta_url.rstrip('/')}/state/latest.tar.gz")
    if status != 200:
        raise RuntimeError(f"Failed to sync TA state archive: HTTP {status}")

    with tempfile.TemporaryDirectory(prefix="pqabse-bench-state-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        untar_bytes(state_archive, temp_dir)
        for child_name in ("abse", "state", "cloud"):
            target = MDU_RUNTIME_DIR / child_name
            source = temp_dir / child_name
            if target.exists():
                shutil.rmtree(target)
            if source.exists():
                shutil.copytree(source, target)

    status, users_archive, _ = http_request(f"{ta_url.rstrip('/')}/users/all.tar.gz")
    if status != 200:
        raise RuntimeError(f"Failed to sync TA users archive: HTTP {status}")

    with tempfile.TemporaryDirectory(prefix="pqabse-bench-users-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        untar_bytes(users_archive, temp_dir)
        (MDU_RUNTIME_DIR / "users").mkdir(parents=True, exist_ok=True)
        (MDU_RUNTIME_DIR / "state" / "update_tokens").mkdir(parents=True, exist_ok=True)
        for user_file in sorted((temp_dir / "users").glob("*")) if (temp_dir / "users").exists() else []:
            shutil.copy2(user_file, MDU_RUNTIME_DIR / "users" / user_file.name)
        update_token_dir = temp_dir / "state" / "update_tokens"
        if update_token_dir.exists():
            for token_file in sorted(update_token_dir.glob("*.token")):
                shutil.copy2(token_file, MDU_RUNTIME_DIR / "state" / "update_tokens" / token_file.name)

    for cred_path in sorted((MDU_RUNTIME_DIR / "users").glob("*.cred")):
        rewrite_local_credential(cred_path)


def run_checked(cmd: list[str], cwd: Path):
    ensure_exists(Path(cmd[0]))
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            f"cwd: {cwd}\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def read_timing(path: Path) -> float:
    return float(path.read_text(encoding="utf-8").strip())


def keyword_list(count: int) -> list[str]:
    return [f"kw_{index:04d}" for index in range(1, count + 1)]


def append_csv(path: Path, row: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row.keys()))
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def register_user(ta_url: str, gid: str, attributes: list[str]):
    status, payload = http_json(f"{ta_url.rstrip('/')}/mobile/register", payload={"gid": gid, "attributes": attributes})
    if status != 200 or payload.get("status") != "ok":
        raise RuntimeError(f"Register failed for {gid}: HTTP {status} payload={json.dumps(payload)}")
    return payload


def encrypt_bundle(edge_url: str, owner_gid: str, label: str, plaintext: str, keywords: list[str], policy_attrs: list[str]) -> tuple[dict, float]:
    payload = {
        "owner_gid": owner_gid,
        "label": label,
        "plaintext": plaintext,
        "keywords": keywords,
        "policy_type": "and",
        "threshold": 1,
        "policy_attrs": policy_attrs,
    }
    start = time.perf_counter()
    status, response = http_json(f"{edge_url.rstrip('/')}/mobile/encrypt", payload=payload, timeout=600)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    if status != 200 or response.get("status") != "ok":
        raise RuntimeError(f"Edge encrypt failed: HTTP {status} payload={json.dumps(response)}")
    return response, elapsed_ms


def import_bundle(cs_url: str, bundle_payload: dict):
    status, response = http_json(f"{cs_url.rstrip('/')}/mobile/import-bundle", payload={"bundle": bundle_payload}, timeout=300)
    if status != 200 or response.get("status") != "ok":
        raise RuntimeError(f"CS bundle import failed: HTTP {status} payload={json.dumps(response)}")
    return response


def run_mdu_prepare_query(gid: str, label: str, keywords: list[str], request_dir: Path, trapdoor_timing_path: Path):
    if request_dir.exists():
        shutil.rmtree(request_dir)
    request_dir.mkdir(parents=True, exist_ok=True)
    if trapdoor_timing_path.exists():
        trapdoor_timing_path.unlink()
    cmd = [
        str(MDU_BUILD_DIR / "mdu_prepare_query"),
        "--gid", gid,
        "--label", label,
        "--out-dir", str(request_dir),
        "--trapdoor-timing-out", str(trapdoor_timing_path),
    ]
    for keyword in keywords:
        cmd.extend(["--query-keyword", keyword])
    run_checked(cmd, MDU_APP_DIR)


def submit_query_archive(cs_url: str, request_id: str, archive_bytes: bytes) -> tuple[bytes, float]:
    start = time.perf_counter()
    status, response_body, content_type = http_request(
        f"{cs_url.rstrip('/')}/query/{request_id}",
        method="POST",
        body=archive_bytes,
        headers={"Content-Type": "application/gzip", "Accept": "application/gzip, application/json"},
        timeout=600,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    if status != 200:
        raise RuntimeError(f"CS query failed: HTTP {status} body={response_body.decode('utf-8', errors='replace')}")
    if content_type != "application/gzip":
        raise RuntimeError(f"Expected gzip query response, got content-type={content_type}")
    return response_body, elapsed_ms


def run_mdu_decrypt(gid: str, request_dir: Path, response_dir: Path, decrypt_timing_path: Path):
    if decrypt_timing_path.exists():
        decrypt_timing_path.unlink()
    cmd = [
        str(MDU_BUILD_DIR / "mdu_decrypt_response"),
        "--gid", gid,
        "--request-dir", str(request_dir),
        "--response-dir", str(response_dir),
        "--decrypt-timing-out", str(decrypt_timing_path),
    ]
    run_checked(cmd, MDU_APP_DIR)


def average(values: list[float]) -> float:
    return sum(values) / len(values)


def main():
    parser = argparse.ArgumentParser(description="Benchmark the EC2/mobile HTTP flow with local MDU query prep and decrypt.")
    parser.add_argument("--ta-url", default="http://127.0.0.1:8081")
    parser.add_argument("--edge-url", default="http://127.0.0.1:8082")
    parser.add_argument("--cs-url", default="http://127.0.0.1:8083")
    parser.add_argument("--keyword-counts", nargs="+", type=int, default=DEFAULT_KEYWORD_COUNTS)
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--owner-prefix", default="bench_owner")
    parser.add_argument("--user-prefix", default="bench_user")
    parser.add_argument("--csv-prefix", default="ec2_mobile_flow")
    parser.add_argument("--plaintext", default="benchmark payload")
    args = parser.parse_args()

    ensure_exists(MDU_BUILD_DIR / "mdu_prepare_query")
    ensure_exists(MDU_BUILD_DIR / "mdu_decrypt_response")

    wait_for_health(args.ta_url)
    wait_for_health(args.edge_url)
    wait_for_health(args.cs_url)

    runs_csv = RESULTS_DIR / f"{args.csv_prefix}_runs.csv"
    avg_csv = RESULTS_DIR / f"{args.csv_prefix}_avg.csv"
    if runs_csv.exists():
        runs_csv.unlink()
    if avg_csv.exists():
        avg_csv.unlink()

    for keyword_count in args.keyword_counts:
        encrypt_values: list[float] = []
        decrypt_values: list[float] = []
        trapdoor_values: list[float] = []
        query_roundtrip_values: list[float] = []

        for run_index in range(1, args.runs + 1):
            owner_gid = f"{args.owner_prefix}_{keyword_count}_{run_index}"
            user_gid = f"{args.user_prefix}_{keyword_count}_{run_index}"
            bundle_label = f"bundle_{keyword_count}_{run_index}_{int(time.time() * 1000)}"
            request_id = f"bench-{keyword_count}-{run_index}-{int(time.time() * 1000)}"
            keywords = keyword_list(keyword_count)

            register_user(args.ta_url, owner_gid, DEFAULT_POLICY_ATTRS)
            register_user(args.ta_url, user_gid, DEFAULT_POLICY_ATTRS)
            sync_mdu_runtime_from_ta(args.ta_url)

            encrypt_response, encrypt_ms = encrypt_bundle(
                args.edge_url,
                owner_gid=owner_gid,
                label=bundle_label,
                plaintext=args.plaintext,
                keywords=keywords,
                policy_attrs=DEFAULT_POLICY_ATTRS,
            )
            import_bundle(args.cs_url, encrypt_response["bundle"])

            request_dir = MDU_RUNTIME_DIR / "service" / "requests" / request_id
            response_dir = MDU_RUNTIME_DIR / "service" / "responses" / request_id
            trapdoor_timing_path = MDU_RUNTIME_DIR / "experiments" / f"{request_id}_trapdoor.txt"
            decrypt_timing_path = MDU_RUNTIME_DIR / "experiments" / f"{request_id}_decrypt.txt"
            response_dir.mkdir(parents=True, exist_ok=True)

            run_mdu_prepare_query(user_gid, bundle_label, keywords, request_dir, trapdoor_timing_path)
            request_archive = tar_directory(request_dir)
            response_archive, query_roundtrip_ms = submit_query_archive(args.cs_url, request_id, request_archive)
            untar_bytes(response_archive, response_dir)
            run_mdu_decrypt(user_gid, request_dir, response_dir, decrypt_timing_path)

            trapdoor_ms = read_timing(trapdoor_timing_path)
            decrypt_ms = read_timing(decrypt_timing_path)

            encrypt_values.append(encrypt_ms)
            decrypt_values.append(decrypt_ms)
            trapdoor_values.append(trapdoor_ms)
            query_roundtrip_values.append(query_roundtrip_ms)

            append_csv(
                runs_csv,
                {
                    "keyword_count": keyword_count,
                    "run": run_index,
                    "owner_gid": owner_gid,
                    "user_gid": user_gid,
                    "bundle_label": bundle_label,
                    "edge_encrypt_bundle_roundtrip_ms": f"{encrypt_ms:.3f}",
                    "mdu_trapdoor_ms": f"{trapdoor_ms:.3f}",
                    "cs_query_roundtrip_ms": f"{query_roundtrip_ms:.3f}",
                    "mdu_decrypt_ms": f"{decrypt_ms:.3f}",
                },
            )
            print(
                f"keyword_count={keyword_count} run={run_index} "
                f"encrypt_ms={encrypt_ms:.3f} trapdoor_ms={trapdoor_ms:.3f} "
                f"query_ms={query_roundtrip_ms:.3f} decrypt_ms={decrypt_ms:.3f}"
            )

        append_csv(
            avg_csv,
            {
                "keyword_count": keyword_count,
                "runs": args.runs,
                "avg_edge_encrypt_bundle_roundtrip_ms": f"{average(encrypt_values):.3f}",
                "avg_mdu_trapdoor_ms": f"{average(trapdoor_values):.3f}",
                "avg_cs_query_roundtrip_ms": f"{average(query_roundtrip_values):.3f}",
                "avg_mdu_decrypt_ms": f"{average(decrypt_values):.3f}",
            },
        )
        print(
            f"AVERAGE keyword_count={keyword_count} runs={args.runs} "
            f"encrypt_ms={average(encrypt_values):.3f} "
            f"decrypt_ms={average(decrypt_values):.3f}"
        )

    print(f"Per-run CSV: {runs_csv}")
    print(f"Averages CSV: {avg_csv}")


if __name__ == "__main__":
    main()
