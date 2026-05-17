#!/usr/bin/env python3
"""Cloud/search-side reference benchmark models for PQABSE-SRM.

This runner is intentionally separate from the PQABSE-SRM runtime and from the
Android/mobile benchmark pack. It produces paper-ready reference curves for the
cloud-side evaluation axes used by the project:

* KeyGen(TA) attribute scaling: 10, 20, 30, 40, 50 attributes.
* Search(CS) keyword-pool scaling: 10, 300, 500, 1000 keywords.
* Search(CS) file-count scaling: 10, 100, 300, 500, 1000 files.
* Keyword scaling for encryption, decryption, and trapdoor generation:
  10, 50, 300, 500 keywords.

The models below are reference models/primitive surrogates, not full competing
system implementations. They use deterministic local operations that preserve
the intended scaling behavior of the cited scheme family when a complete
drop-in implementation is unavailable in this repository.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import random
import statistics
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "RunFullSys" / "experiment_results" / "cloud_reference_results.csv"

ATTRIBUTE_COUNTS = [10, 20, 30, 40, 50]
KEYWORD_COUNTS = [10, 50, 300, 500]
SEARCH_KEYWORD_POOL_COUNTS = [10, 300, 500, 1000]
SEARCH_FILE_COUNTS = [10, 100, 300, 500, 1000]

DEFAULT_RUNS = 5
DEFAULT_SEARCH_FILES = 1000
DEFAULT_SEARCH_POOL = 1000
DEFAULT_QUERY_KEYWORDS = 5
KEYWORDS_PER_FILE = 25
PRIME = (1 << 127) - 1


RAW_FIELDS = [
    "paper",
    "metric",
    "scale_type",
    "scale_value",
    "run",
    "ms",
    "status",
    "message",
    "model_type",
    "candidate_count",
    "exact_match_count",
]

AVERAGE_FIELDS = [
    "paper",
    "metric",
    "scale_type",
    "scale_value",
    "runs",
    "avg_ms",
    "ok_runs",
    "total_runs",
    "status",
    "message",
    "model_type",
    "avg_candidate_count",
    "avg_exact_match_count",
]


@dataclass(frozen=True)
class PaperModel:
    paper: str
    model_type: str
    description: str
    supported_metrics: tuple[str, ...]
    runner: Callable[[str, str, int, int, int], "BenchResult"]


@dataclass(frozen=True)
class BenchResult:
    ms: float
    status: str
    message: str
    candidate_count: int | None = None
    exact_match_count: int | None = None


@dataclass(frozen=True)
class SearchCorpus:
    keyword_pool_size: int
    file_count: int
    file_keywords: tuple[tuple[str, ...], ...]
    inverted_index: dict[str, frozenset[int]]


def keyword_name(index: int) -> str:
    return f"kw_{index:04d}"


def keyword_list(count: int) -> list[str]:
    return [keyword_name(index) for index in range(1, count + 1)]


def split_keyword_bands(keyword_pool_size: int) -> tuple[list[str], list[str], list[str], list[str]]:
    pool = keyword_list(keyword_pool_size)
    common_end = max(1, int(round(keyword_pool_size * 0.05)))
    medium_end = max(common_end + 1, common_end + int(round(keyword_pool_size * 0.20)))
    rare_end = max(medium_end + 1, medium_end + int(round(keyword_pool_size * 0.35)))
    common = pool[:common_end]
    medium = pool[common_end:medium_end]
    rare = pool[medium_end:rare_end]
    selective = pool[rare_end:] or pool[-1:]
    return common, medium, rare, selective


def deterministic_sample(rng: random.Random, values: list[str], count: int) -> list[str]:
    if count <= 0:
        return []
    if not values:
        return []
    if count <= len(values):
        return rng.sample(values, count)
    return [values[rng.randrange(len(values))] for _ in range(count)]


@lru_cache(maxsize=64)
def build_search_corpus(keyword_pool_size: int, file_count: int) -> SearchCorpus:
    """Build a deterministic OR-search corpus matching the project paper setup.

    Keyword bands are split as common 5%, medium 20%, rare 35%, and selective
    remainder. Each file uses a 16%/36%/28%/20% composition over those bands.
    Selective terms are sampled from cluster-local buckets over groups of
    eight files so file-count prefixes preserve the distribution.
    """
    common, medium, rare, selective = split_keyword_bands(keyword_pool_size)
    counts = {
        "common": max(1, round(KEYWORDS_PER_FILE * 0.16)),
        "medium": max(1, round(KEYWORDS_PER_FILE * 0.36)),
        "rare": max(1, round(KEYWORDS_PER_FILE * 0.28)),
    }
    counts["selective"] = max(1, KEYWORDS_PER_FILE - counts["common"] - counts["medium"] - counts["rare"])

    file_keywords: list[tuple[str, ...]] = []
    inverted: dict[str, set[int]] = {keyword: set() for keyword in keyword_list(keyword_pool_size)}

    for file_id in range(file_count):
        rng = random.Random((keyword_pool_size * 1_000_003) + file_id)
        group = file_id // 8
        bucket_size = min(len(selective), max(8, math.ceil(len(selective) / 16)))
        bucket_start = (group * bucket_size) % len(selective)
        selective_bucket = [selective[(bucket_start + offset) % len(selective)] for offset in range(bucket_size)]
        selected = set(deterministic_sample(rng, common, counts["common"]))
        selected.update(deterministic_sample(rng, medium, counts["medium"]))
        selected.update(deterministic_sample(rng, rare, counts["rare"]))
        selected.update(deterministic_sample(rng, selective_bucket, counts["selective"]))
        ordered = tuple(sorted(selected))
        file_keywords.append(ordered)
        for keyword in ordered:
            inverted.setdefault(keyword, set()).add(file_id)

    frozen_index = {keyword: frozenset(ids) for keyword, ids in inverted.items()}
    return SearchCorpus(keyword_pool_size, file_count, tuple(file_keywords), frozen_index)


def query_keywords(corpus: SearchCorpus, run: int, query_keyword_count: int) -> list[str]:
    target_file = ((run - 1) * 7 + corpus.keyword_pool_size + corpus.file_count) % corpus.file_count
    target_keywords = list(corpus.file_keywords[target_file])
    rng = random.Random(91_337 + run + corpus.keyword_pool_size * 17 + corpus.file_count * 31)
    count = min(query_keyword_count, len(target_keywords))
    return sorted(rng.sample(target_keywords, count))


def or_candidate_set(corpus: SearchCorpus, keywords: Iterable[str]) -> set[int]:
    candidates: set[int] = set()
    for keyword in keywords:
        candidates.update(corpus.inverted_index.get(keyword, frozenset()))
    return candidates


def timed(operation: Callable[[], tuple[int, int] | None]) -> tuple[float, int | None, int | None]:
    start_ns = time.perf_counter_ns()
    counts = operation()
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    if counts is None:
        return elapsed_ms, None, None
    return elapsed_ms, counts[0], counts[1]


def digest_rounds(label: str, count: int, digest_size: int = 32) -> int:
    acc = 0
    state = label.encode("utf-8")
    for index in range(count):
        state = hashlib.blake2b(state + index.to_bytes(4, "little"), digest_size=digest_size).digest()
        acc ^= int.from_bytes(state[:8], "little")
    return acc


def hmac_rounds(label: str, count: int) -> int:
    key = hashlib.sha256(f"key:{label}".encode("utf-8")).digest()
    acc = 0
    for index in range(count):
        token = hmac.new(key, f"{label}:{index}".encode("utf-8"), hashlib.sha256).digest()
        acc ^= token[0] << (index % 8)
    return acc


def modular_rounds(label: str, count: int, width: int = 64) -> int:
    seed = int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:8], "little")
    acc = seed or 1
    for index in range(count):
        acc = (acc * 65_537 + (index + 1) * 1_315_423_911) % PRIME
        acc ^= (acc >> 17)
        for lane in range(width // 16):
            acc = (acc + (lane + 1) * (index + 3)) % PRIME
    return acc


def pairing_like_rounds(label: str, count: int) -> int:
    base = int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:16], "little") % PRIME
    acc = 1
    for index in range(count):
        acc ^= pow(base + index + 3, 65_537 + index, PRIME)
    return acc


def lattice_vector_rounds(label: str, vectors: int, dimension: int = 64) -> int:
    rng = random.Random(int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:8], "little"))
    vector = [rng.randrange(12_289) for _ in range(dimension)]
    acc = 0
    for round_index in range(vectors):
        twiddle = 3 + (round_index % 251)
        for lane, value in enumerate(vector):
            mixed = (value * twiddle + lane * 17 + round_index) % 12_289
            vector[lane] = mixed
            acc ^= mixed << (lane % 8)
    return acc


def keep(value: int) -> None:
    if value == -1:
        raise RuntimeError("unreachable guard")


def keyword_work_count(metric: str, scale_type: str, scale_value: int) -> int:
    if scale_type != "keyword_count":
        raise ValueError(f"{metric} requires keyword_count scale, got {scale_type}")
    return scale_value


def attribute_work_count(metric: str, scale_type: str, scale_value: int) -> int:
    if scale_type != "attribute_count":
        raise ValueError(f"{metric} requires attribute_count scale, got {scale_type}")
    return scale_value


def corpus_for_scale(scale_type: str, scale_value: int) -> SearchCorpus:
    if scale_type == "keyword_pool_size":
        return build_search_corpus(scale_value, DEFAULT_SEARCH_FILES)
    if scale_type == "file_count":
        return build_search_corpus(DEFAULT_SEARCH_POOL, scale_value)
    raise ValueError(f"search requires keyword_pool_size or file_count scale, got {scale_type}")


def b20_runner(metric: str, scale_type: str, scale_value: int, run: int, query_keyword_count: int) -> BenchResult:
    message = "reference_model: BGN/CKKS-style batched HE surrogate; not a full b20 implementation"
    if metric == "search":
        corpus = corpus_for_scale(scale_type, scale_value)
        keywords = query_keywords(corpus, run, query_keyword_count)

        def op() -> tuple[int, int]:
            candidates = or_candidate_set(corpus, keywords)
            if scale_type == "keyword_pool_size":
                keep(modular_rounds(f"b20-search-pool-{scale_value}-{run}", 96, width=64))
            else:
                keep(modular_rounds(f"b20-search-files-{scale_value}-{run}", max(16, scale_value // 4), width=64))
            return len(candidates), len(candidates)

        ms, candidate_count, exact_count = timed(op)
        return BenchResult(ms, "ok", message, candidate_count, exact_count)

    keyword_count = keyword_work_count(metric, scale_type, scale_value)
    fixed_batch_rounds = 128

    def op() -> None:
        keep(modular_rounds(f"b20-{metric}-{keyword_count}-{run}", fixed_batch_rounds, width=64))
        return None

    ms, _, _ = timed(op)
    return BenchResult(ms, "ok", message)


def b30_runner(metric: str, scale_type: str, scale_value: int, run: int, query_keyword_count: int) -> BenchResult:
    del metric, query_keyword_count
    attr_count = attribute_work_count("keygen", scale_type, scale_value)
    message = "primitive_surrogate: lattice keygen comparison using deterministic module-vector arithmetic"

    def op() -> None:
        keep(lattice_vector_rounds(f"b30-keygen-{attr_count}-{run}", attr_count * 3, dimension=96))
        return None

    ms, _, _ = timed(op)
    return BenchResult(ms, "ok", message)


def b31_runner(metric: str, scale_type: str, scale_value: int, run: int, query_keyword_count: int) -> BenchResult:
    del query_keyword_count
    message = "primitive_surrogate: CP-ABE/pairing-style modular exponentiation surrogate"
    if metric == "keygen":
        attr_count = attribute_work_count(metric, scale_type, scale_value)
        rounds = attr_count * 6
    else:
        keyword_count = keyword_work_count(metric, scale_type, scale_value)
        multiplier = 3 if metric == "encryption" else 2
        rounds = keyword_count * multiplier

    def op() -> None:
        keep(pairing_like_rounds(f"b31-{metric}-{scale_value}-{run}", rounds))
        return None

    ms, _, _ = timed(op)
    return BenchResult(ms, "ok", message)


def b32_runner(metric: str, scale_type: str, scale_value: int, run: int, query_keyword_count: int) -> BenchResult:
    message = "primitive_surrogate: puncturable lattice search/trapdoor model with per-keyword token work"
    if metric == "trapdoor":
        keyword_count = keyword_work_count(metric, scale_type, scale_value)

        def op() -> None:
            keep(hmac_rounds(f"b32-trapdoor-{keyword_count}-{run}", keyword_count * 2))
            keep(lattice_vector_rounds(f"b32-puncture-{keyword_count}-{run}", max(1, keyword_count // 4), dimension=64))
            return None

        ms, _, _ = timed(op)
        return BenchResult(ms, "ok", message)

    corpus = corpus_for_scale(scale_type, scale_value)
    keywords = query_keywords(corpus, run, query_keyword_count)

    def op() -> tuple[int, int]:
        keep(hmac_rounds(f"b32-search-token-{scale_type}-{scale_value}-{run}", len(keywords) * 3))
        candidates = or_candidate_set(corpus, keywords)
        keep(digest_rounds(f"b32-search-candidates-{scale_value}-{run}", max(1, len(candidates) // 4)))
        return len(candidates), len(candidates)

    ms, candidate_count, exact_count = timed(op)
    return BenchResult(ms, "ok", message, candidate_count, exact_count)


def b33_runner(metric: str, scale_type: str, scale_value: int, run: int, query_keyword_count: int) -> BenchResult:
    message = "primitive_surrogate: time-epoch lattice/PEKS model using hash tokens and vector checks"
    if metric == "trapdoor":
        keyword_count = keyword_work_count(metric, scale_type, scale_value)

        def op() -> None:
            keep(digest_rounds(f"b33-trapdoor-token-{keyword_count}-{run}", keyword_count * 4))
            keep(lattice_vector_rounds(f"b33-trapdoor-lattice-{keyword_count}-{run}", max(1, keyword_count // 8), dimension=64))
            return None

        ms, _, _ = timed(op)
        return BenchResult(ms, "ok", message)

    if metric == "encryption":
        keyword_count = keyword_work_count(metric, scale_type, scale_value)

        def op() -> None:
            keep(digest_rounds(f"b33-peks-encrypt-{keyword_count}-{run}", keyword_count * 3))
            return None

        ms, _, _ = timed(op)
        return BenchResult(ms, "ok", message)

    corpus = corpus_for_scale(scale_type, scale_value)
    keywords = query_keywords(corpus, run, query_keyword_count)

    def op() -> tuple[int, int]:
        token_cost = len(keywords) * 2
        scan_cost = max(1, corpus.file_count * len(keywords) // 3)
        keep(digest_rounds(f"b33-search-token-{scale_type}-{scale_value}-{run}", token_cost))
        keep(lattice_vector_rounds(f"b33-search-scan-{scale_type}-{scale_value}-{run}", scan_cost, dimension=16))
        candidates = or_candidate_set(corpus, keywords)
        return len(candidates), len(candidates)

    ms, candidate_count, exact_count = timed(op)
    return BenchResult(ms, "ok", message, candidate_count, exact_count)


PAPER_MODELS: dict[str, PaperModel] = {
    "b20": PaperModel(
        paper="b20",
        model_type="reference_model",
        description=(
            "BGN/CKKS homomorphic top-k retrieval surrogate. Search is modeled as "
            "batched HE vector work and is intentionally near-constant for keyword-pool growth."
        ),
        supported_metrics=("search", "encryption", "decryption", "trapdoor"),
        runner=b20_runner,
    ),
    "b30": PaperModel(
        paper="b30",
        model_type="primitive_surrogate",
        description="Lattice searchable-encryption key-generation comparison for attribute scaling.",
        supported_metrics=("keygen",),
        runner=b30_runner,
    ),
    "b31": PaperModel(
        paper="b31",
        model_type="primitive_surrogate",
        description="CP-ABE/attribute-based encryption comparison using pairing-like modular operations.",
        supported_metrics=("keygen", "encryption", "decryption"),
        runner=b31_runner,
    ),
    "b32": PaperModel(
        paper="b32",
        model_type="primitive_surrogate",
        description="Puncturable encrypted search/trapdoor comparison using token and puncture work.",
        supported_metrics=("search", "trapdoor"),
        runner=b32_runner,
    ),
    "b33": PaperModel(
        paper="b33",
        model_type="primitive_surrogate",
        description="Time-epoch lattice/PEKS comparison using per-keyword token and scan work.",
        supported_metrics=("search", "trapdoor", "encryption"),
        runner=b33_runner,
    ),
}


def parse_csv_list(raw: str) -> list[str]:
    values = [part.strip().lower() for part in raw.split(",") if part.strip()]
    return values or ["all"]


def expand_metrics(raw: str) -> list[str]:
    metrics = parse_csv_list(raw)
    valid = ["keygen", "search", "encryption", "decryption", "trapdoor"]
    if "all" in metrics:
        return valid
    unknown = sorted(set(metrics) - set(valid))
    if unknown:
        raise SystemExit(f"Unknown metric(s): {', '.join(unknown)}")
    return metrics


def expand_papers(raw: str) -> list[str]:
    papers = parse_csv_list(raw)
    if "all" in papers:
        return list(PAPER_MODELS)
    unknown = sorted(set(papers) - set(PAPER_MODELS))
    if unknown:
        raise SystemExit(f"Unknown paper(s): {', '.join(unknown)}")
    return papers


def output_paths(out: Path) -> tuple[Path, Path]:
    if out.suffix.lower() != ".csv":
        return out / "cloud_reference_raw.csv", out / "cloud_reference_averages.csv"
    if out.name.endswith("_raw.csv"):
        return out, out.with_name(out.name.replace("_raw.csv", "_averages.csv"))
    return out.with_name("cloud_reference_raw.csv"), out.with_name("cloud_reference_averages.csv")


def scale_points_for_metric(metric: str) -> list[tuple[str, int]]:
    if metric == "keygen":
        return [("attribute_count", value) for value in ATTRIBUTE_COUNTS]
    if metric == "search":
        return (
            [("keyword_pool_size", value) for value in SEARCH_KEYWORD_POOL_COUNTS]
            + [("file_count", value) for value in SEARCH_FILE_COUNTS]
        )
    return [("keyword_count", value) for value in KEYWORD_COUNTS]


def append_rows(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)


def format_optional_float(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.3f}"


def raw_row(model: PaperModel, metric: str, scale_type: str, scale_value: int, run: int, result: BenchResult) -> dict[str, object]:
    return {
        "paper": model.paper,
        "metric": metric,
        "scale_type": scale_type,
        "scale_value": scale_value,
        "run": run,
        "ms": f"{result.ms:.3f}",
        "status": result.status,
        "message": result.message,
        "model_type": model.model_type,
        "candidate_count": "" if result.candidate_count is None else result.candidate_count,
        "exact_match_count": "" if result.exact_match_count is None else result.exact_match_count,
    }


def average_row(model: PaperModel, metric: str, scale_type: str, scale_value: int, results: list[BenchResult]) -> dict[str, object]:
    ok_results = [result for result in results if result.status == "ok"]
    timings = [result.ms for result in ok_results]
    candidate_counts = [result.candidate_count for result in ok_results if result.candidate_count is not None]
    exact_counts = [result.exact_match_count for result in ok_results if result.exact_match_count is not None]
    status = "ok" if len(ok_results) == len(results) else "partial"
    if not ok_results:
        status = "error"
    message = ok_results[0].message if ok_results else results[0].message
    return {
        "paper": model.paper,
        "metric": metric,
        "scale_type": scale_type,
        "scale_value": scale_value,
        "runs": len(ok_results),
        "avg_ms": f"{statistics.fmean(timings):.3f}" if timings else "",
        "ok_runs": len(ok_results),
        "total_runs": len(results),
        "status": status,
        "message": message,
        "model_type": model.model_type,
        "avg_candidate_count": format_optional_float(statistics.fmean(candidate_counts)) if candidate_counts else "",
        "avg_exact_match_count": format_optional_float(statistics.fmean(exact_counts)) if exact_counts else "",
    }


def run_benchmarks(args: argparse.Namespace) -> tuple[Path, Path]:
    raw_csv, averages_csv = output_paths(args.out)
    metrics = expand_metrics(args.metrics)
    papers = expand_papers(args.papers)
    raw_rows: list[dict[str, object]] = []
    average_rows: list[dict[str, object]] = []

    for paper in papers:
        model = PAPER_MODELS[paper]
        for metric in metrics:
            if metric not in model.supported_metrics:
                continue
            for scale_type, scale_value in scale_points_for_metric(metric):
                results: list[BenchResult] = []
                for run in range(1, args.runs + 1):
                    print(
                        f"[{paper}] {metric} {scale_type}={scale_value} run {run}/{args.runs}",
                        flush=True,
                    )
                    try:
                        result = model.runner(metric, scale_type, scale_value, run, args.search_query_keywords)
                    except Exception as exc:  # noqa: BLE001
                        result = BenchResult(0.0, "error", f"{type(exc).__name__}: {exc}")
                    results.append(result)
                    raw_rows.append(raw_row(model, metric, scale_type, scale_value, run, result))
                    if result.status == "ok":
                        print(f"  -> {result.ms:.3f} ms", flush=True)
                    else:
                        print(f"  -> {result.status}: {result.message}", flush=True)
                average_rows.append(average_row(model, metric, scale_type, scale_value, results))

    append_rows(raw_csv, RAW_FIELDS, raw_rows)
    append_rows(averages_csv, AVERAGE_FIELDS, average_rows)
    return raw_csv, averages_csv


def print_models() -> None:
    for model in PAPER_MODELS.values():
        print(f"{model.paper}: {model.model_type}")
        print(f"  metrics: {', '.join(model.supported_metrics)}")
        print(f"  {model.description}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run cloud/search-side reference benchmark models for competing papers."
    )
    parser.add_argument(
        "--metrics",
        default="all",
        help="Comma-separated metrics: keygen,search,encryption,decryption,trapdoor,all.",
    )
    parser.add_argument(
        "--papers",
        default="all",
        help="Comma-separated papers/models: b20,b30,b31,b32,b33,all.",
    )
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS, help="Runs per paper/metric/scale point.")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=(
            "Output CSV hint. If a directory is supplied, writes cloud_reference_raw.csv and "
            "cloud_reference_averages.csv there. If a CSV is supplied, writes those two files "
            "next to it."
        ),
    )
    parser.add_argument(
        "--search-query-keywords",
        type=int,
        default=DEFAULT_QUERY_KEYWORDS,
        help="Number of OR-query keywords sampled from a deterministic target bundle for search models.",
    )
    parser.add_argument("--list-models", action="store_true", help="Print model descriptions and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.list_models:
        print_models()
        return 0
    if args.runs <= 0:
        raise SystemExit("--runs must be positive")
    if args.search_query_keywords <= 0:
        raise SystemExit("--search-query-keywords must be positive")

    raw_csv, averages_csv = run_benchmarks(args)
    summary = {
        "raw_csv": str(raw_csv),
        "averages_csv": str(averages_csv),
        "runs": args.runs,
        "metrics": expand_metrics(args.metrics),
        "papers": expand_papers(args.papers),
    }
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
