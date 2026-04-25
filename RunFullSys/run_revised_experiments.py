#!/usr/bin/env python3
import base64
import csv
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "experiment_results"
RESULTS_DIR.mkdir(exist_ok=True)

ROLE_DIRS = {
    "ta": ROOT / "TA+IA+Blockchain",
    "edge": ROOT / "Edge node",
    "cs": ROOT / "CS",
    "mdo": ROOT / "MDO",
    "mdu": ROOT / "MDU",
}

KEYGEN_ATTR_COUNTS = [10, 20, 30, 40, 50]
KEYWORD_COUNTS = [20, 300, 500, 1000, 2000, 4000]
REVOCATION_USER_COUNTS = [10, 20, 30, 40, 50]
RUNS_PER_POINT = 5
SEARCH_FILE_COUNT = 100

FIXED_POLICIES = [
    ("and", 1, [f"attr_{i:04d}" for i in range(1, 6)]),
    ("or", 1, [f"attr_{i:04d}" for i in range(1, 6)]),
    ("threshold", 2, [f"attr_{i:04d}" for i in range(1, 6)]),
    ("threshold", 3, [f"attr_{i:04d}" for i in range(1, 6)]),
    ("threshold", 4, [f"attr_{i:04d}" for i in range(1, 6)]),
]


def keywords(count: int) -> list[str]:
    return [f"kw_{i:04d}" for i in range(1, count + 1)]


def attrs(count: int) -> list[str]:
    return [f"attr_{i:04d}" for i in range(1, count + 1)]


def role_app_dir(role: str) -> Path:
    return ROLE_DIRS[role] / "app"


def role_build_dir(role: str) -> Path:
    return role_app_dir(role) / "build-wsl"


def role_runtime_dir(role: str) -> Path:
    return role_app_dir(role) / "runtime"


def exe(role: str, name: str) -> Path:
    return role_build_dir(role) / name


def ensure_exists(path: Path):
    if not path.exists():
        raise RuntimeError(f"Missing required path: {path}")


def run(cmd: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    ensure_exists(Path(cmd[0]))
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=True, env=env)


def reset_role_runtime(role: str):
    runtime_dir = role_runtime_dir(role)
    if not runtime_dir.exists():
        return
    for child in runtime_dir.iterdir():
        if child.name == "experiments":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def reset_all_runtimes():
    for role in ROLE_DIRS:
        reset_role_runtime(role)


def write_timing_path(role: str, name: str) -> Path:
    path = role_runtime_dir(role) / "experiments" / f"{name}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    return path


def read_timing(path: Path) -> float:
    return float(path.read_text(encoding="utf-8").strip())


def append_csv(path: Path, row: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row.keys()))
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def print_average(label: str, scale_label: str, scale_value: int, values: list[float]):
    average = sum(values) / len(values)
    print(f"{label}: {scale_label}={scale_value} runs={len(values)} avg_ms={average:.3f}")


def http_json(url: str, payload: dict | None = None) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if payload is not None else "GET")
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_health(url: str, timeout_s: float = 20.0):
    deadline = time.time() + timeout_s
    last_error = None
    while time.time() < deadline:
        try:
            payload = http_json(url)
            if payload.get("status") == "ok":
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def setup_role(role: str):
    run([str(exe(role, "phase1_setup"))], cwd=role_app_dir(role))


def register_user(role: str, gid: str, attributes: list[str], timing_name: str | None = None):
    cmd = [str(exe(role, "phase2_keygen")), "--gid", gid]
    for attribute in attributes:
        cmd.extend(["--attr", attribute])
    timing_path = None
    if timing_name is not None:
        timing_path = write_timing_path(role, timing_name)
        cmd.extend(["--timing-out", str(timing_path)])
    run(cmd, cwd=role_app_dir(role))
    return read_timing(timing_path) if timing_path is not None else None


def encrypt_bundle(role: str, owner_gid: str, label: str, plaintext: str, policy_type: str, threshold: int,
                   policy_attrs: list[str], kw_list: list[str]):
    cmd = [
        str(exe(role, "phase3_encrypt")),
        "--owner-gid", owner_gid,
        "--label", label,
        "--plaintext", plaintext,
        "--policy-type", policy_type,
        "--threshold", str(threshold),
    ]
    for keyword in kw_list:
        cmd.extend(["--keyword", keyword])
    for attribute in policy_attrs:
        cmd.extend(["--policy-attr", attribute])
    start = time.perf_counter()
    run(cmd, cwd=role_app_dir(role))
    return (time.perf_counter() - start) * 1000.0


def prepare_query(role: str, gid: str, label: str, kw_list: list[str], name: str) -> tuple[Path, Path]:
    out_dir = role_runtime_dir(role) / "service" / "requests" / name
    if out_dir.exists():
        shutil.rmtree(out_dir)
    timing_path = write_timing_path(role, f"{name}_trapdoor")
    cmd = [str(exe(role, "mdu_prepare_query")), "--gid", gid, "--label", label, "--out-dir", str(out_dir),
           "--trapdoor-timing-out", str(timing_path)]
    for keyword in kw_list:
        cmd.extend(["--query-keyword", keyword])
    run(cmd, cwd=role_app_dir(role))
    return out_dir, timing_path


def process_query(request_dir: Path, response_dir: Path, name: str) -> float:
    if response_dir.exists():
        shutil.rmtree(response_dir)
    response_dir.mkdir(parents=True, exist_ok=True)
    timing_path = write_timing_path("cs", f"{name}_candidate")
    cmd = [str(exe("cs", "cs_process_query")), "--request-dir", str(request_dir), "--response-dir", str(response_dir),
           "--candidate-timing-out", str(timing_path)]
    run(cmd, cwd=role_app_dir("cs"))
    return read_timing(timing_path)


def decrypt_response(request_dir: Path, response_dir: Path, gid: str, name: str) -> float:
    timing_path = write_timing_path("mdu", f"{name}_decrypt")
    cmd = [str(exe("mdu", "mdu_decrypt_response")), "--gid", gid, "--request-dir", str(request_dir),
           "--response-dir", str(response_dir), "--decrypt-timing-out", str(timing_path)]
    run(cmd, cwd=role_app_dir("mdu"))
    return read_timing(timing_path)


def copy_bundle_to_response(role_from: str, label: str, response_dir: Path):
    bundle_dir = response_dir / "bundles"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(role_runtime_dir(role_from) / "ciphertexts" / f"{label}_bundle.bin", bundle_dir / f"{label}_bundle.bin")
    shutil.copy2(role_runtime_dir(role_from) / "ciphertexts" / f"{label}_bundle.meta", bundle_dir / f"{label}_bundle.meta")


def last_phase5_update_token_ms() -> float:
    metrics_path = role_runtime_dir("ta") / "experiments" / "phase_metrics.csv"
    with metrics_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in reversed(rows):
        if row.get("phase") == "phase5_revoke":
            return float(row["update_token_write_ms"])
    raise RuntimeError("phase5_revoke row not found in phase_metrics.csv")


def run_keygen_experiment():
    csv_path = RESULTS_DIR / "keygen_results.csv"
    for attr_count in KEYGEN_ATTR_COUNTS:
        values = []
        for run_idx in range(RUNS_PER_POINT):
            reset_all_runtimes()
            setup_role("ta")
            value = register_user("ta", f"user_a{attr_count}_r{run_idx}", attrs(attr_count), f"keygen_{attr_count}_{run_idx}")
            values.append(value)
        print_average("keygen", "attribute_count", attr_count, values)
        append_csv(csv_path, {"experiment": "keygen", "attribute_count": attr_count, "runs": RUNS_PER_POINT,
                              "avg_ms": f"{sum(values) / len(values):.3f}"})


def run_encryption_experiment():
    csv_path = RESULTS_DIR / "full_encryption_results.csv"
    for keyword_count in KEYWORD_COUNTS:
        local_values = []
        for run_idx, policy in enumerate(FIXED_POLICIES):
            policy_type, threshold, policy_attrs = policy
            reset_all_runtimes()
            setup_role("mdo")
            register_user("mdo", "owner_local", policy_attrs, None)
            local_values.append(
                encrypt_bundle("mdo", "owner_local", f"local_bundle_{keyword_count}_{run_idx}", "payload",
                               policy_type, threshold, policy_attrs, keywords(keyword_count))
            )
        append_csv(csv_path, {
            "experiment": "full_encryption",
            "keyword_count": keyword_count,
            "runs": len(FIXED_POLICIES),
            "avg_mdo_full_ciphertext_bundle_ms": f"{sum(local_values) / len(local_values):.3f}",
        })
        print(f"full_encryption: keyword_count={keyword_count} runs={len(FIXED_POLICIES)} "
              f"avg_mdo_full_ciphertext_bundle_ms={sum(local_values) / len(local_values):.3f}")


def setup_search_stack(keyword_count: int):
    reset_all_runtimes()
    role = "cs"
    setup_role(role)
    register_user(role, "search_user", FIXED_POLICIES[0][2], None)
    register_user(role, "owner_search", FIXED_POLICIES[0][2], None)
    policy_type, threshold, policy_attrs = FIXED_POLICIES[0]
    kw_list = keywords(keyword_count)
    for index in range(SEARCH_FILE_COUNT):
        encrypt_bundle(role, "owner_search", f"bundle_{index:03d}", f"payload_{index}", policy_type, threshold, policy_attrs, kw_list)
    return kw_list


def run_search_speed_experiment():
    csv_path = RESULTS_DIR / "search_speed_results.csv"
    for keyword_count in KEYWORD_COUNTS:
        values = []
        for run_idx in range(RUNS_PER_POINT):
            kw_list = setup_search_stack(keyword_count)
            request_dir, _ = prepare_query("cs", "search_user", "bundle_000", kw_list, f"search_{keyword_count}_{run_idx}")
            response_dir = role_runtime_dir("cs") / "service" / "responses" / f"search_{keyword_count}_{run_idx}"
            values.append(process_query(request_dir, response_dir, f"search_{keyword_count}_{run_idx}"))
        print_average("search_speed", "keyword_count", keyword_count, values)
        append_csv(csv_path, {"experiment": "search_speed", "keyword_count": keyword_count, "file_count": SEARCH_FILE_COUNT,
                              "runs": RUNS_PER_POINT, "avg_candidate_generation_ms": f"{sum(values) / len(values):.3f}"})


def run_trapdoor_experiment():
    csv_path = RESULTS_DIR / "trapdoor_results.csv"
    for keyword_count in KEYWORD_COUNTS:
        values = []
        for run_idx in range(RUNS_PER_POINT):
            reset_all_runtimes()
            setup_role("mdu")
            register_user("mdu", "trap_user", FIXED_POLICIES[0][2], None)
            request_dir, timing_path = prepare_query("mdu", "trap_user", "preferred_bundle", keywords(keyword_count),
                                                     f"trapdoor_{keyword_count}_{run_idx}")
            values.append(read_timing(timing_path))
            shutil.rmtree(request_dir, ignore_errors=True)
        print_average("trapdoor_generation", "keyword_count", keyword_count, values)
        append_csv(csv_path, {"experiment": "trapdoor_generation", "keyword_count": keyword_count, "runs": RUNS_PER_POINT,
                              "avg_trapdoor_ms": f"{sum(values) / len(values):.3f}"})


def run_decryption_experiment():
    csv_path = RESULTS_DIR / "decryption_results.csv"
    policy_type, threshold, policy_attrs = FIXED_POLICIES[0]
    for keyword_count in KEYWORD_COUNTS:
        values = []
        for run_idx in range(RUNS_PER_POINT):
            reset_all_runtimes()
            setup_role("mdu")
            register_user("mdu", "decrypt_user", policy_attrs, None)
            register_user("mdu", "owner_decrypt", policy_attrs, None)
            kw_list = keywords(keyword_count)
            label = f"decrypt_bundle_{keyword_count}_{run_idx}"
            encrypt_bundle("mdu", "owner_decrypt", label, "payload", policy_type, threshold, policy_attrs, kw_list)
            request_dir, _ = prepare_query("mdu", "decrypt_user", label, kw_list, f"decrypt_{keyword_count}_{run_idx}")
            response_dir = role_runtime_dir("mdu") / "service" / "responses" / f"decrypt_{keyword_count}_{run_idx}"
            copy_bundle_to_response("mdu", label, response_dir)
            values.append(decrypt_response(request_dir, response_dir, "decrypt_user", f"decrypt_{keyword_count}_{run_idx}"))
        print_average("decryption", "keyword_count", keyword_count, values)
        append_csv(csv_path, {"experiment": "decryption", "keyword_count": keyword_count, "policy_size": 5,
                              "runs": RUNS_PER_POINT, "avg_decrypt_ms": f"{sum(values) / len(values):.3f}"})


def run_revocation_experiment():
    csv_path = RESULTS_DIR / "revocation_results.csv"
    for user_count in REVOCATION_USER_COUNTS:
        values = []
        for run_idx in range(RUNS_PER_POINT):
            reset_all_runtimes()
            setup_role("ta")
            for index in range(user_count):
                register_user("ta", f"rev_user_{index:03d}", FIXED_POLICIES[0][2], None)
            run([str(exe("ta", "phase5_revoke")), "--gid", "rev_user_000"], cwd=role_app_dir("ta"))
            values.append(last_phase5_update_token_ms())
        print_average("revocation", "active_user_count", user_count, values)
        append_csv(csv_path, {"experiment": "revocation", "active_user_count": user_count, "runs": RUNS_PER_POINT,
                              "avg_update_token_write_ms": f"{sum(values) / len(values):.3f}"})


def main():
    run_keygen_experiment()
    run_encryption_experiment()
    run_search_speed_experiment()
    run_trapdoor_experiment()
    run_decryption_experiment()
    run_revocation_experiment()
    print(f"Revised experiment outputs written under {RESULTS_DIR}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stdout or "")
        sys.stderr.write(exc.stderr or "")
        raise
