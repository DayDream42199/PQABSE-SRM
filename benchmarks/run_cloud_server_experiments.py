#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import string
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


KEYWORD_COUNTS = [10, 50, 300, 500]
ATTRIBUTE_COUNTS = [10, 20, 30, 40, 50]
USER_COUNTS = [10, 20, 30, 40, 50]
DEFAULT_REPEATS = 5

BASE_OWNER_ATTRS = ["alpha", "beta", "gamma"]
BASE_SEARCHER_ATTRS = ["alpha", "beta", "gamma"]
BASE_POLICY = "AND(alpha,beta)"


@dataclass
class EndpointConfig:
    ta_url: str
    edge_url: str
    cs_url: str


def http_post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {body}") from exc


def random_suffix(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def append_average_row(csv_path: Path, experiment: str, metric_name: str, parameter_name: str,
                       parameter_value: int, run_values: list[float], notes: str = "") -> None:
    ensure_parent(csv_path)
    fieldnames = [
        "recorded_at_utc",
        "experiment",
        "metric_name",
        "parameter_name",
        "parameter_value",
        "repeats",
        "run_1_ms",
        "run_2_ms",
        "run_3_ms",
        "run_4_ms",
        "run_5_ms",
        "average_ms",
        "notes",
    ]
    write_header = not csv_path.exists()
    with csv_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        row = {
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment": experiment,
            "metric_name": metric_name,
            "parameter_name": parameter_name,
            "parameter_value": parameter_value,
            "repeats": len(run_values),
            "average_ms": f"{average(run_values):.3f}",
            "notes": notes,
        }
        for index in range(5):
            row[f"run_{index + 1}_ms"] = f"{run_values[index]:.3f}" if index < len(run_values) else ""
        writer.writerow(row)


def append_run_row(csv_path: Path, experiment: str, metric_name: str, parameter_name: str,
                   parameter_value: int, run_index: int, duration_ms: float, notes: str = "") -> None:
    ensure_parent(csv_path)
    fieldnames = [
        "recorded_at_utc",
        "experiment",
        "metric_name",
        "parameter_name",
        "parameter_value",
        "run_index",
        "duration_ms",
        "notes",
    ]
    write_header = not csv_path.exists()
    with csv_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow({
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment": experiment,
            "metric_name": metric_name,
            "parameter_name": parameter_name,
            "parameter_value": parameter_value,
            "run_index": run_index,
            "duration_ms": f"{duration_ms:.3f}",
            "notes": notes,
        })


def average(values: list[float]) -> float:
    return sum(values) / float(len(values)) if values else 0.0


def require_timing(response: dict, key: str) -> float:
    timings = response.get("timings") or {}
    value = timings.get(key)
    if value in (None, ""):
        raise RuntimeError(f"Response did not include timing '{key}': {json.dumps(response)}")
    return float(value)


def register_user(config: EndpointConfig, gid: str, attributes: list[str]) -> dict:
    return http_post_json(
        f"{config.ta_url}/mobile/register",
        {"gid": gid, "attributes": attributes},
    )


def revoke_user(config: EndpointConfig, gid: str) -> dict:
    return http_post_json(
        f"{config.ta_url}/mobile/revoke",
        {"revoked_gid": gid},
    )


def prepare_query(config: EndpointConfig, gid: str, preferred_label: str, keywords: list[str]) -> dict:
    return http_post_json(
        f"{config.ta_url}/mobile/prepare-query",
        {"gid": gid, "preferred_label": preferred_label, "keywords": keywords},
    )


def encrypt_bundle(config: EndpointConfig, owner_gid: str, label: str, plaintext: str, keywords: list[str]) -> dict:
    return http_post_json(
        f"{config.edge_url}/mobile/encrypt",
        {
            "owner_gid": owner_gid,
            "label": label,
            "plaintext": plaintext,
            "keywords": keywords,
            "policy_expression": BASE_POLICY,
        },
    )


def import_bundle(config: EndpointConfig, bundle: dict) -> dict:
    return http_post_json(
        f"{config.cs_url}/mobile/import-bundle",
        {"bundle": bundle},
    )


def query_archive(config: EndpointConfig, request_archive_base64: str) -> dict:
    return http_post_json(
        f"{config.cs_url}/mobile/query-archive",
        {"request_archive_base64": request_archive_base64},
    )


def keyword_list(run_tag: str, count: int) -> list[str]:
    return [f"{run_tag}_kw_{index:04d}" for index in range(count)]


def attribute_list(count: int) -> list[str]:
    return [f"attr_{index:02d}" for index in range(count)]


def benchmark_keygen(config: EndpointConfig, attribute_count: int, run_index: int) -> float:
    gid = f"bench_keygen_{attribute_count}_{run_index}_{random_suffix()}"
    response = register_user(config, gid, attribute_list(attribute_count))
    return require_timing(response, "keygen_ms")


def benchmark_encrypt(config: EndpointConfig, keyword_count: int, run_index: int) -> float:
    tag = f"enc_{keyword_count}_{run_index}_{random_suffix()}"
    owner_gid = f"{tag}_owner"
    register_user(config, owner_gid, BASE_OWNER_ATTRS)
    response = encrypt_bundle(
        config,
        owner_gid=owner_gid,
        label=f"{tag}_bundle",
        plaintext=f"payload for {tag}",
        keywords=keyword_list(tag, keyword_count),
    )
    return require_timing(response, "encrypt_bundle_ms")


def benchmark_trapdoor(config: EndpointConfig, keyword_count: int, run_index: int) -> float:
    tag = f"trap_{keyword_count}_{run_index}_{random_suffix()}"
    searcher_gid = f"{tag}_searcher"
    register_user(config, searcher_gid, BASE_SEARCHER_ATTRS)
    response = prepare_query(
        config,
        gid=searcher_gid,
        preferred_label=f"{tag}_label",
        keywords=keyword_list(tag, keyword_count),
    )
    return require_timing(response, "trapdoor_gen_ms")


def benchmark_search(config: EndpointConfig, keyword_count: int, run_index: int) -> float:
    tag = f"search_{keyword_count}_{run_index}_{random_suffix()}"
    owner_gid = f"{tag}_owner"
    searcher_gid = f"{tag}_searcher"
    label = f"{tag}_bundle"
    keywords = keyword_list(tag, keyword_count)

    register_user(config, owner_gid, BASE_OWNER_ATTRS)
    register_user(config, searcher_gid, BASE_SEARCHER_ATTRS)

    encrypt_response = encrypt_bundle(
        config,
        owner_gid=owner_gid,
        label=label,
        plaintext=f"payload for {tag}",
        keywords=keywords,
    )
    import_bundle(config, encrypt_response["bundle"])

    prepare_response = prepare_query(
        config,
        gid=searcher_gid,
        preferred_label=label,
        keywords=keywords,
    )
    query_response = query_archive(config, prepare_response["request_archive_base64"])
    return require_timing(query_response, "candidate_generation_ms")


def benchmark_revoke(config: EndpointConfig, user_count: int, run_index: int) -> float:
    tag = f"revoke_{user_count}_{run_index}_{random_suffix()}"
    gids = [f"{tag}_user_{index:03d}" for index in range(user_count)]
    for gid in gids:
        register_user(config, gid, ["alpha", "beta"])
    response = revoke_user(config, gids[0])
    return require_timing(response, "update_token_write_ms")


def run_series(config: EndpointConfig, experiment: str, metric_name: str, parameter_name: str,
               parameter_values: list[int], repeats: int, averages_csv: Path, runs_csv: Path,
               runner) -> None:
    for parameter_value in parameter_values:
        values: list[float] = []
        for run_index in range(1, repeats + 1):
            print(f"[{experiment}] {parameter_name}={parameter_value} run {run_index}/{repeats}", flush=True)
            duration_ms = runner(config, parameter_value, run_index)
            values.append(duration_ms)
            append_run_row(
                runs_csv,
                experiment=experiment,
                metric_name=metric_name,
                parameter_name=parameter_name,
                parameter_value=parameter_value,
                run_index=run_index,
                duration_ms=duration_ms,
            )
            print(f"  -> {duration_ms:.3f} ms", flush=True)
            time.sleep(0.2)
        avg = average(values)
        append_average_row(
            averages_csv,
            experiment=experiment,
            metric_name=metric_name,
            parameter_name=parameter_name,
            parameter_value=parameter_value,
            run_values=values,
        )
        print(f"[{experiment}] {parameter_name}={parameter_value} average={avg:.3f} ms", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run cloud TA/Edge/CS server-side benchmark experiments and append CSV rows.")
    parser.add_argument("--ta-url", required=True, help="Base TA URL, for example http://1.2.3.4:8081")
    parser.add_argument("--edge-url", required=True, help="Base Edge URL, for example http://1.2.3.4:8082")
    parser.add_argument("--cs-url", required=True, help="Base CS URL, for example http://1.2.3.4:8083")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument(
        "--suite",
        choices=["all", "keyword", "keygen", "revoke"],
        default="all",
        help="keyword runs encrypt/search/trapdoor keyword-sweep; keygen runs attribute-sweep; revoke runs user-count sweep.",
    )
    parser.add_argument("--averages-csv", type=Path, default=Path("cloud_benchmark_results.csv"))
    parser.add_argument("--runs-csv", type=Path, default=Path("cloud_benchmark_runs.csv"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeats <= 0:
        raise SystemExit("--repeats must be positive")

    config = EndpointConfig(
        ta_url=args.ta_url.rstrip("/"),
        edge_url=args.edge_url.rstrip("/"),
        cs_url=args.cs_url.rstrip("/"),
    )

    if args.suite in {"all", "keyword"}:
        run_series(config, "cloud_encrypt", "encrypt_bundle_ms", "keyword_count", KEYWORD_COUNTS, args.repeats, args.averages_csv, args.runs_csv, benchmark_encrypt)
        run_series(config, "cloud_search", "candidate_generation_ms", "keyword_count", KEYWORD_COUNTS, args.repeats, args.averages_csv, args.runs_csv, benchmark_search)
        run_series(config, "cloud_trapdoor", "trapdoor_gen_ms", "keyword_count", KEYWORD_COUNTS, args.repeats, args.averages_csv, args.runs_csv, benchmark_trapdoor)

    if args.suite in {"all", "keygen"}:
        run_series(config, "cloud_keygen", "keygen_ms", "attribute_count", ATTRIBUTE_COUNTS, args.repeats, args.averages_csv, args.runs_csv, benchmark_keygen)

    if args.suite in {"all", "revoke"}:
        run_series(config, "cloud_revoke", "update_token_write_ms", "user_count", USER_COUNTS, args.repeats, args.averages_csv, args.runs_csv, benchmark_revoke)

    print(f"Averages appended to {args.averages_csv}")
    print(f"Per-run rows appended to {args.runs_csv}")
    print("Note: mobile decrypt timing is not included here; collect that from the emulator/app side.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
