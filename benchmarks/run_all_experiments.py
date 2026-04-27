#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
RUNFULLSYS = ROOT / "RunFullSys"
TA_APP = RUNFULLSYS / "TA+IA+Blockchain" / "app"
EDGE_APP = RUNFULLSYS / "Edge node" / "app"
CS_APP = RUNFULLSYS / "CS" / "app"
MDU_APP = RUNFULLSYS / "MDU" / "app"

RESULTS_DIR = ROOT / "benchmarks" / "results"
WORK_DIR = ROOT / "benchmarks" / "work"

KEYWORD_COUNTS = [20, 300, 500, 1000]
ATTRIBUTE_COUNTS = [10, 20, 30, 40, 50]
USER_COUNTS = [10, 20, 30, 40, 50]

DEFAULT_REPEATS = 5
OWNER_GID = "9001"
SEARCHER_GID = "9002"
BASE_ATTRS = ["alpha", "beta", "gamma"]
BASE_POLICY = "AND(alpha,beta)"


@dataclass(frozen=True)
class RolePaths:
    name: str
    app_dir: Path

    @property
    def runtime_dir(self) -> Path:
        return self.app_dir / "runtime"

    @property
    def build_dir(self) -> Path:
        return self.app_dir / "build-wsl"


TA = RolePaths("ta", TA_APP)
EDGE = RolePaths("edge", EDGE_APP)
CS = RolePaths("cs", CS_APP)
MDU = RolePaths("mdu", MDU_APP)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def run_command(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    printable = " ".join(shlex_quote(part) for part in cmd)
    print(f"$ {printable}", flush=True)
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise RuntimeError(f"Command failed with exit code {completed.returncode}: {printable}")
    return completed


def shlex_quote(value: str) -> str:
    if not value:
        return "''"
    if all(ch.isalnum() or ch in "._/-:" for ch in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def require_binary(role: RolePaths, name: str) -> Path:
    binary = role.build_dir / name
    if not binary.exists():
        raise FileNotFoundError(f"Missing binary: {binary}")
    return binary


def reset_role_runtime(role: RolePaths) -> None:
    clean_dir(role.runtime_dir)


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    if src.exists():
        shutil.copytree(src, dst)


def rewrite_mdu_credentials(users_dir: Path) -> None:
    for cred_path in users_dir.glob("*.cred"):
        gid = cred_path.stem
        rewritten: list[str] = []
        replaced = False
        for raw_line in cred_path.read_text(encoding="utf-8").splitlines():
            if raw_line.startswith("user_key_path="):
                rewritten.append(f"user_key_path={users_dir / f'{gid}_userkey.bin'}")
                replaced = True
            else:
                rewritten.append(raw_line)
        if not replaced:
            rewritten.append(f"user_key_path={users_dir / f'{gid}_userkey.bin'}")
        cred_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def sync_ta_runtime_to_edge() -> None:
    ensure_dir(EDGE.runtime_dir)
    for name in ("abse", "state", "cloud"):
        copy_tree(TA.runtime_dir / name, EDGE.runtime_dir / name)


def sync_ta_runtime_to_cs() -> None:
    ensure_dir(CS.runtime_dir)
    for name in ("abse", "state", "cloud", "users"):
        copy_tree(TA.runtime_dir / name, CS.runtime_dir / name)


def sync_ta_runtime_to_mdu() -> None:
    ensure_dir(MDU.runtime_dir)
    for name in ("abse", "state", "cloud", "users"):
        copy_tree(TA.runtime_dir / name, MDU.runtime_dir / name)
    users_dir = MDU.runtime_dir / "users"
    if users_dir.exists():
        rewrite_mdu_credentials(users_dir)


def import_edge_bundles_to_cs() -> None:
    source_dir = EDGE.runtime_dir / "ciphertexts"
    dest_dir = CS.runtime_dir / "ciphertexts"
    ensure_dir(dest_dir)
    for bundle_file in source_dir.glob("*_bundle.bin"):
        shutil.copy2(bundle_file, dest_dir / bundle_file.name)
    for meta_file in source_dir.glob("*_bundle.meta"):
        target = dest_dir / meta_file.name
        shutil.copy2(meta_file, target)
        label = meta_file.name.removesuffix("_bundle.meta")
        rewrite_bundle_meta(target, dest_dir / f"{label}_bundle.bin")
    search_dir = CS.runtime_dir / "search"
    if search_dir.exists():
        for index_file in search_dir.glob("bitmap_index_epoch_*.bin"):
            index_file.unlink()


def rewrite_bundle_meta(meta_path: Path, bundle_path: Path) -> None:
    updated: list[str] = []
    replaced = False
    for raw_line in meta_path.read_text(encoding="utf-8").splitlines():
        if raw_line.startswith("bundle_path="):
            updated.append(f"bundle_path={bundle_path}")
            replaced = True
        else:
            updated.append(raw_line)
    if not replaced:
        updated.append(f"bundle_path={bundle_path}")
    meta_path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def fresh_multi_role_runtime() -> None:
    for role in (TA, EDGE, CS, MDU):
        reset_role_runtime(role)


def run_phase1_setup() -> None:
    binary = require_binary(TA, "phase1_setup")
    run_command([str(binary)], cwd=TA.app_dir)


def register_user(gid: str, attributes: Iterable[str], timing_out: Path | None = None) -> float:
    binary = require_binary(TA, "phase2_keygen")
    cmd = [str(binary), "--gid", gid]
    for attr in attributes:
        cmd.extend(["--attr", attr])
    if timing_out is not None:
        cmd.extend(["--timing-out", str(timing_out)])
    completed = run_command(cmd, cwd=TA.app_dir)
    if timing_out and timing_out.exists():
        return float(timing_out.read_text(encoding="utf-8").strip())
    return parse_stdout_metric(completed.stdout, "Keygen ms:")


def revoke_user(gid: str, metrics_out: Path) -> float:
    binary = require_binary(TA, "phase5_revoke")
    run_command([str(binary), "--gid", gid, "--metrics-out", str(metrics_out)], cwd=TA.app_dir)
    row = read_last_csv_row(metrics_out)
    return float(row["update_token_write_ms"])


def encrypt_bundle(owner_gid: str, label: str, plaintext: str, keywords: list[str], metrics_out: Path) -> float:
    binary = require_binary(EDGE, "phase3_encrypt")
    cmd = [
        str(binary),
        "--owner-gid", owner_gid,
        "--label", label,
        "--plaintext", plaintext,
        "--policy-expression", BASE_POLICY,
        "--threshold", "1",
        "--metrics-out", str(metrics_out),
    ]
    for keyword in keywords:
        cmd.extend(["--keyword", keyword])
    run_command(cmd, cwd=EDGE.app_dir)
    row = read_last_csv_row(metrics_out)
    return float(row["encrypt_bundle_ms"])


def prepare_query(gid: str, preferred_label: str, keywords: list[str], out_dir: Path, timing_out: Path | None = None) -> float:
    binary = require_binary(TA, "mdu_prepare_query")
    cmd = [str(binary), "--gid", gid, "--out-dir", str(out_dir), "--label", preferred_label]
    for keyword in keywords:
        cmd.extend(["--query-keyword", keyword])
    if timing_out is not None:
        cmd.extend(["--trapdoor-timing-out", str(timing_out)])
    start = time.perf_counter()
    completed = run_command(cmd, cwd=TA.app_dir)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    if timing_out and timing_out.exists():
        return float(timing_out.read_text(encoding="utf-8").strip())
    stdout = completed.stdout
    if "Trapdoor generation ms:" in stdout:
        return parse_stdout_metric(stdout, "Trapdoor generation ms:")
    return elapsed_ms


def run_cs_search(request_dir: Path, response_dir: Path, timing_out: Path) -> float:
    binary = require_binary(CS, "cs_process_query")
    cmd = [
        str(binary),
        "--request-dir", str(request_dir),
        "--response-dir", str(response_dir),
        "--candidate-timing-out", str(timing_out),
    ]
    run_command(cmd, cwd=CS.app_dir)
    return float(timing_out.read_text(encoding="utf-8").strip())


def run_mdu_decrypt(gid: str, request_dir: Path, response_dir: Path, timing_out: Path) -> float:
    binary = require_binary(MDU, "mdu_decrypt_response")
    cmd = [
        str(binary),
        "--gid", gid,
        "--request-dir", str(request_dir),
        "--response-dir", str(response_dir),
        "--decrypt-timing-out", str(timing_out),
    ]
    run_command(cmd, cwd=MDU.app_dir)
    return float(timing_out.read_text(encoding="utf-8").strip())


def parse_stdout_metric(stdout: str, prefix: str) -> float:
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line.startswith(prefix):
            return float(line.split(":", 1)[1].strip())
    raise ValueError(f"Could not find '{prefix}' in stdout")


def read_last_csv_row(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"No data rows in {path}")
    return rows[-1]


def keyword_list(count: int) -> list[str]:
    return [f"kw_{index:04d}" for index in range(count)]


def attribute_list(count: int) -> list[str]:
    return [f"attr_{index:02d}" for index in range(count)]


def make_average(values: list[float]) -> float:
    return sum(values) / float(len(values)) if values else 0.0


def append_average_row(csv_path: Path, experiment: str, metric_name: str, parameter_name: str,
                       parameter_value: int, run_values: list[float], notes: str = "") -> None:
    ensure_dir(csv_path.parent)
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
            "average_ms": f"{make_average(run_values):.3f}",
            "notes": notes,
        }
        for index in range(5):
            key = f"run_{index + 1}_ms"
            row[key] = f"{run_values[index]:.3f}" if index < len(run_values) else ""
        writer.writerow(row)


def append_run_row(csv_path: Path, experiment: str, metric_name: str, parameter_name: str,
                   parameter_value: int, run_index: int, duration_ms: float, notes: str = "") -> None:
    ensure_dir(csv_path.parent)
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


def setup_keyword_fixture(keyword_count: int, run_label: str) -> tuple[Path, Path]:
    fresh_multi_role_runtime()
    run_phase1_setup()
    register_user(OWNER_GID, BASE_ATTRS)
    register_user(SEARCHER_GID, BASE_ATTRS)
    sync_ta_runtime_to_edge()
    sync_ta_runtime_to_cs()
    sync_ta_runtime_to_mdu()

    keywords = keyword_list(keyword_count)
    metrics_path = WORK_DIR / run_label / "edge_metrics.csv"
    ensure_dir(metrics_path.parent)
    encrypt_bundle(OWNER_GID, f"bundle_{run_label}", f"payload for {run_label}", keywords, metrics_path)
    import_edge_bundles_to_cs()

    request_dir = WORK_DIR / run_label / "request"
    response_dir = WORK_DIR / run_label / "response"
    clean_dir(request_dir)
    clean_dir(response_dir)
    return request_dir, response_dir


def run_keyword_measurement(metric_name: str, keyword_count: int, run_index: int) -> float:
    run_label = f"{metric_name}_{keyword_count}_{run_index}"
    keywords = keyword_list(keyword_count)

    if metric_name == "encrypt_bundle_ms":
        fresh_multi_role_runtime()
        run_phase1_setup()
        register_user(OWNER_GID, BASE_ATTRS)
        sync_ta_runtime_to_edge()
        metrics_path = WORK_DIR / run_label / "edge_metrics.csv"
        ensure_dir(metrics_path.parent)
        return encrypt_bundle(OWNER_GID, f"bundle_{run_label}", f"payload for {run_label}", keywords, metrics_path)

    request_dir, response_dir = setup_keyword_fixture(keyword_count, run_label)

    trapdoor_timing = WORK_DIR / run_label / "trapdoor_ms.txt"
    trapdoor_ms = prepare_query(SEARCHER_GID, f"bundle_{run_label}", keywords, request_dir, trapdoor_timing)

    if metric_name == "trapdoor_gen_ms":
        return trapdoor_ms

    candidate_timing = WORK_DIR / run_label / "candidate_ms.txt"
    candidate_ms = run_cs_search(request_dir, response_dir, candidate_timing)
    if metric_name == "candidate_generation_ms":
        return candidate_ms

    if metric_name == "retrieve_decrypt_ms":
        sync_ta_runtime_to_mdu()
        decrypt_timing = WORK_DIR / run_label / "decrypt_ms.txt"
        return run_mdu_decrypt(SEARCHER_GID, request_dir, response_dir, decrypt_timing)

    raise ValueError(f"Unknown keyword metric {metric_name}")


def run_keygen_measurement(attribute_count: int, run_index: int) -> float:
    fresh_multi_role_runtime()
    run_phase1_setup()
    timing_path = WORK_DIR / f"keygen_{attribute_count}_{run_index}" / "keygen_ms.txt"
    ensure_dir(timing_path.parent)
    gid = f"kg_{attribute_count:02d}_{run_index:02d}"
    return register_user(gid, attribute_list(attribute_count), timing_path)


def run_revoke_measurement(user_count: int, run_index: int) -> float:
    fresh_multi_role_runtime()
    run_phase1_setup()
    fixed_attrs = ["alpha", "beta"]
    for index in range(user_count):
        gid = f"ru_{user_count:02d}_{run_index:02d}_{index:03d}"
        register_user(gid, fixed_attrs)
    metrics_path = WORK_DIR / f"revoke_{user_count}_{run_index}" / "revoke_metrics.csv"
    ensure_dir(metrics_path.parent)
    revoke_target = f"ru_{user_count:02d}_{run_index:02d}_{0:03d}"
    return revoke_user(revoke_target, metrics_path)


def benchmark_series(experiment: str, metric_name: str, parameter_name: str, parameter_values: list[int],
                     repeats: int, average_csv: Path, runs_csv: Path,
                     runner) -> None:
    for parameter_value in parameter_values:
        run_values: list[float] = []
        for run_index in range(1, repeats + 1):
            print(
                f"[{experiment}] {parameter_name}={parameter_value} run {run_index}/{repeats}",
                flush=True,
            )
            duration_ms = runner(parameter_value, run_index)
            run_values.append(duration_ms)
            append_run_row(
                runs_csv,
                experiment=experiment,
                metric_name=metric_name,
                parameter_name=parameter_name,
                parameter_value=parameter_value,
                run_index=run_index,
                duration_ms=duration_ms,
            )
            print(
                f"  -> {duration_ms:.3f} ms",
                flush=True,
            )
        average_ms = make_average(run_values)
        append_average_row(
            average_csv,
            experiment=experiment,
            metric_name=metric_name,
            parameter_name=parameter_name,
            parameter_value=parameter_value,
            run_values=run_values,
        )
        print(
            f"[{experiment}] {parameter_name}={parameter_value} average over {repeats} runs: {average_ms:.3f} ms",
            flush=True,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run PQABSE-SRM benchmark experiments and append averaged CSV results.")
    parser.add_argument(
        "--suite",
        choices=["all", "keyword", "keygen", "revoke"],
        default="all",
        help="Which experiment family to run.",
    )
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS, help="Runs per parameter value.")
    parser.add_argument(
        "--average-csv",
        type=Path,
        default=RESULTS_DIR / "benchmark_results.csv",
        help="CSV file that receives averaged rows.",
    )
    parser.add_argument(
        "--runs-csv",
        type=Path,
        default=RESULTS_DIR / "benchmark_runs.csv",
        help="CSV file that receives per-run rows.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeats <= 0:
        raise SystemExit("--repeats must be positive")
    ensure_dir(RESULTS_DIR)
    ensure_dir(WORK_DIR)

    if args.suite in {"all", "keyword"}:
        benchmark_series(
            experiment="keyword_suite_encrypt",
            metric_name="encrypt_bundle_ms",
            parameter_name="keyword_count",
            parameter_values=KEYWORD_COUNTS,
            repeats=args.repeats,
            average_csv=args.average_csv,
            runs_csv=args.runs_csv,
            runner=lambda value, run_idx: run_keyword_measurement("encrypt_bundle_ms", value, run_idx),
        )
        benchmark_series(
            experiment="keyword_suite_decrypt",
            metric_name="retrieve_decrypt_ms",
            parameter_name="keyword_count",
            parameter_values=KEYWORD_COUNTS,
            repeats=args.repeats,
            average_csv=args.average_csv,
            runs_csv=args.runs_csv,
            runner=lambda value, run_idx: run_keyword_measurement("retrieve_decrypt_ms", value, run_idx),
        )
        benchmark_series(
            experiment="keyword_suite_search",
            metric_name="candidate_generation_ms",
            parameter_name="keyword_count",
            parameter_values=KEYWORD_COUNTS,
            repeats=args.repeats,
            average_csv=args.average_csv,
            runs_csv=args.runs_csv,
            runner=lambda value, run_idx: run_keyword_measurement("candidate_generation_ms", value, run_idx),
        )
        benchmark_series(
            experiment="keyword_suite_trapdoor",
            metric_name="trapdoor_gen_ms",
            parameter_name="keyword_count",
            parameter_values=KEYWORD_COUNTS,
            repeats=args.repeats,
            average_csv=args.average_csv,
            runs_csv=args.runs_csv,
            runner=lambda value, run_idx: run_keyword_measurement("trapdoor_gen_ms", value, run_idx),
        )

    if args.suite in {"all", "keygen"}:
        benchmark_series(
            experiment="keygen_suite",
            metric_name="keygen_ms",
            parameter_name="attribute_count",
            parameter_values=ATTRIBUTE_COUNTS,
            repeats=args.repeats,
            average_csv=args.average_csv,
            runs_csv=args.runs_csv,
            runner=run_keygen_measurement,
        )

    if args.suite in {"all", "revoke"}:
        benchmark_series(
            experiment="revoke_suite",
            metric_name="update_token_write_ms",
            parameter_name="user_count",
            parameter_values=USER_COUNTS,
            repeats=args.repeats,
            average_csv=args.average_csv,
            runs_csv=args.runs_csv,
            runner=run_revoke_measurement,
        )

    print(f"Averages appended to {args.average_csv}")
    print(f"Per-run rows appended to {args.runs_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
