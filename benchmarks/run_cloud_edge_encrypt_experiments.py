#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import string
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


KEYWORD_COUNTS = [10, 50, 300, 500]
DEFAULT_REPEATS = 5
BASE_OWNER_ATTRS = ["alpha", "beta", "gamma"]
BASE_POLICY = "AND(alpha,beta)"


@dataclass
class EndpointConfig:
    ta_url: str
    edge_url: str


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


def average(values: list[float]) -> float:
    return sum(values) / float(len(values)) if values else 0.0


def append_run_row(csv_path: Path, keyword_count: int, run_index: int, duration_ms: float) -> None:
    ensure_parent(csv_path)
    fieldnames = [
        "recorded_at_utc",
        "experiment",
        "metric_name",
        "parameter_name",
        "parameter_value",
        "run_index",
        "duration_ms",
    ]
    write_header = not csv_path.exists()
    with csv_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow(
            {
                "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                "experiment": "edge_node_encrypt",
                "metric_name": "encrypt_bundle_ms",
                "parameter_name": "keyword_count",
                "parameter_value": keyword_count,
                "run_index": run_index,
                "duration_ms": f"{duration_ms:.3f}",
            }
        )


def append_average_row(csv_path: Path, keyword_count: int, run_values: list[float]) -> None:
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
    ]
    write_header = not csv_path.exists()
    with csv_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        row = {
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment": "edge_node_encrypt",
            "metric_name": "encrypt_bundle_ms",
            "parameter_name": "keyword_count",
            "parameter_value": keyword_count,
            "repeats": len(run_values),
            "average_ms": f"{average(run_values):.3f}",
        }
        for index in range(5):
            row[f"run_{index + 1}_ms"] = f"{run_values[index]:.3f}" if index < len(run_values) else ""
        writer.writerow(row)


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


def keyword_list(run_tag: str, count: int) -> list[str]:
    return [f"{run_tag}_kw_{index:04d}" for index in range(count)]


def benchmark_encrypt(config: EndpointConfig, keyword_count: int, run_index: int) -> float:
    tag = f"enc_{keyword_count}_{run_index}_{random_suffix()}"
    owner_gid = f"{tag}_owner"
    register_user(config, owner_gid, BASE_OWNER_ATTRS)
    response = http_post_json(
        f"{config.edge_url}/mobile/encrypt",
        {
            "owner_gid": owner_gid,
            "label": f"{tag}_bundle",
            "plaintext": f"payload for {tag}",
            "keywords": keyword_list(tag, keyword_count),
            "policy_expression": BASE_POLICY,
        },
    )
    return require_timing(response, "encrypt_bundle_ms")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run only the Edge-node encrypt cloud benchmark and append CSV rows."
    )
    parser.add_argument("--ta-url", required=True, help="Base TA URL, for example http://1.2.3.4:8081")
    parser.add_argument("--edge-url", required=True, help="Base Edge URL, for example http://1.2.3.4:8082")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--averages-csv", type=Path, default=Path("cloud_edge_encrypt_results.csv"))
    parser.add_argument("--runs-csv", type=Path, default=Path("cloud_edge_encrypt_runs.csv"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeats <= 0:
        raise SystemExit("--repeats must be positive")

    config = EndpointConfig(
        ta_url=args.ta_url.rstrip("/"),
        edge_url=args.edge_url.rstrip("/"),
    )

    for keyword_count in KEYWORD_COUNTS:
        run_values: list[float] = []
        for run_index in range(1, args.repeats + 1):
            print(f"[edge_node_encrypt] keyword_count={keyword_count} run {run_index}/{args.repeats}", flush=True)
            duration_ms = benchmark_encrypt(config, keyword_count, run_index)
            run_values.append(duration_ms)
            append_run_row(args.runs_csv, keyword_count, run_index, duration_ms)
            print(f"  -> {duration_ms:.3f} ms", flush=True)
            time.sleep(0.2)
        avg = average(run_values)
        append_average_row(args.averages_csv, keyword_count, run_values)
        print(f"[edge_node_encrypt] keyword_count={keyword_count} average={avg:.3f} ms", flush=True)

    print(f"Averages appended to {args.averages_csv}")
    print(f"Per-run rows appended to {args.runs_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
