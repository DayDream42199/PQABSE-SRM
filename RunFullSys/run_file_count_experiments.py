#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import run_revised_experiments as base


ROOT = Path(__file__).resolve().parent
CORPUS_ROOT = ROOT / "file_count_test_corpus" / "generated"
DEFAULT_FILE_STEPS = [10, 100, 300, 500, 1000]
DEFAULT_KEYWORD_STEPS = [10, 50, 100, 300, 500]
DEFAULT_QUERY_KEYWORDS = 5


def parse_int_list(raw: str) -> list[int]:
    values = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            values.append(int(item))
    return values


def resolve_step_pairs(keyword_steps: list[int], bundle_steps_raw: str) -> list[tuple[int, int]]:
    if not keyword_steps:
        return []
    if not bundle_steps_raw.strip():
        return [(step, step) for step in keyword_steps]
    bundle_steps = parse_int_list(bundle_steps_raw)
    if len(bundle_steps) != len(keyword_steps):
        raise ValueError("bundle-keyword-steps must have the same length as keyword-steps")
    return list(zip(keyword_steps, bundle_steps))


def corpus_name(keyword_pool_count: int, keywords_per_bundle: int, max_files: int, seed: int) -> str:
    return (
        f"pool_{keyword_pool_count:04d}"
        f"_per_bundle_{keywords_per_bundle:03d}"
        f"_files_{max_files:04d}"
        f"_seed_{seed}"
    )


def corpus_dir(keyword_pool_count: int, keywords_per_bundle: int, max_files: int, seed: int) -> Path:
    return CORPUS_ROOT / corpus_name(keyword_pool_count, keywords_per_bundle, max_files, seed)


def bundle_label(index: int) -> str:
    return f"bundle_{index:03d}"


def split_fixed_keyword_bands(keyword_pool: list[str]) -> tuple[list[str], list[str], list[str], list[str]]:
    return base.split_keyword_bands(keyword_pool)


def fixed_bundle_keyword_corpus(
    keyword_pool_count: int,
    keywords_per_bundle: int,
    file_count: int,
    query_keyword_count: int,
    seed: int,
) -> tuple[list[list[str]], list[str]]:
    keyword_pool = base.keywords(keyword_pool_count)
    common, medium, rare, selective = split_fixed_keyword_bands(keyword_pool)

    common_per_bundle = min(len(common), max(1, int(keywords_per_bundle * base.COMMON_PER_DOC_RATIO)))
    medium_per_bundle = min(len(medium), max(1, int(keywords_per_bundle * base.MEDIUM_PER_DOC_RATIO)))
    rare_per_bundle = min(len(rare), max(1, int(keywords_per_bundle * base.RARE_PER_DOC_RATIO)))
    selective_per_bundle = max(1, keywords_per_bundle - common_per_bundle - medium_per_bundle - rare_per_bundle)

    bundles: list[list[str]] = []
    master_rng = base.random.Random(seed)
    cluster_count = max(1, (file_count + base.SELECTIVE_CLUSTER_SPAN - 1) // base.SELECTIVE_CLUSTER_SPAN)
    selective_bucket_width = max(1, len(selective) // cluster_count) if selective else 1

    for doc_idx in range(file_count):
        doc_rng = base.random.Random(master_rng.randint(0, 1_000_000_000) ^ doc_idx)
        doc_keywords: set[str] = set()
        doc_keywords.update(base.sample_keywords_without_replacement(common, common_per_bundle, doc_rng))
        doc_keywords.update(base.sample_keywords_without_replacement(medium, medium_per_bundle, doc_rng))
        doc_keywords.update(base.sample_keywords_without_replacement(rare, rare_per_bundle, doc_rng))

        cluster_id = doc_idx // base.SELECTIVE_CLUSTER_SPAN
        selective_begin = min(cluster_id * selective_bucket_width, len(selective))
        selective_end = min(len(selective), selective_begin + selective_bucket_width)
        selective_bucket = selective[selective_begin:selective_end] or selective
        doc_keywords.update(
            base.sample_keywords_without_replacement(selective_bucket, selective_per_bundle, doc_rng)
        )

        if len(doc_keywords) < keywords_per_bundle:
            fallback_pool = medium + rare + selective + common
            for keyword in fallback_pool:
                if len(doc_keywords) >= keywords_per_bundle:
                    break
                doc_keywords.add(keyword)

        bundles.append(sorted(doc_keywords))

    query_rng = base.random.Random(seed ^ 0x13579BDF)
    query_keywords = sorted(
        base.sample_keywords_without_replacement(
            bundles[0],
            min(query_keyword_count, len(bundles[0])),
            query_rng,
        )
    )
    return bundles, query_keywords


def rewrite_meta_bundle_path(source_meta: Path, dest_meta: Path, bundle_path: Path):
    lines = source_meta.read_text(encoding="utf-8").splitlines()
    rewritten = []
    replaced = False
    for line in lines:
        if line.startswith("bundle_path="):
            rewritten.append(f"bundle_path={bundle_path}")
            replaced = True
        else:
            rewritten.append(line)
    if not replaced:
        rewritten.append(f"bundle_path={bundle_path}")
    dest_meta.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def manifest_path(target_dir: Path) -> Path:
    return target_dir / "manifest.json"


def load_manifest(target_dir: Path) -> dict:
    return json.loads(manifest_path(target_dir).read_text(encoding="utf-8"))


def save_manifest(target_dir: Path, manifest: dict):
    manifest_path(target_dir).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def ensure_persistent_corpus(
    keyword_pool_count: int,
    keywords_per_bundle: int,
    max_files: int,
    query_keyword_count: int,
    seed: int,
) -> Path:
    target_dir = corpus_dir(keyword_pool_count, keywords_per_bundle, max_files, seed)
    bundles_dir = target_dir / "bundles"
    metas_dir = target_dir / "metas"
    target_dir.mkdir(parents=True, exist_ok=True)
    bundles_dir.mkdir(parents=True, exist_ok=True)
    metas_dir.mkdir(parents=True, exist_ok=True)

    if manifest_path(target_dir).exists():
        manifest = load_manifest(target_dir)
        expected_labels = manifest.get("labels", [])
        if expected_labels and all(
            (bundles_dir / f"{label}_bundle.bin").exists() and (metas_dir / f"{label}_bundle.meta").exists()
            for label in expected_labels
        ):
            return target_dir

    bundle_keywords, query_keywords = fixed_bundle_keyword_corpus(
        keyword_pool_count,
        keywords_per_bundle,
        max_files,
        query_keyword_count,
        seed,
    )

    base.reset_role_runtime("cs")
    base.setup_role("cs")
    base.register_user("cs", "search_user", base.FIXED_POLICIES[0][2], None)
    base.register_user("cs", "owner_search", base.FIXED_POLICIES[0][2], None)
    policy_type, threshold, policy_attrs = base.FIXED_POLICIES[0]

    labels = []
    for index, keywords_for_bundle in enumerate(bundle_keywords):
        label = bundle_label(index)
        labels.append(label)
        base.encrypt_bundle(
            "cs",
            "owner_search",
            label,
            f"payload_{index}",
            policy_type,
            threshold,
            policy_attrs,
            keywords_for_bundle,
        )

        runtime_bundle = base.role_runtime_dir("cs") / "ciphertexts" / f"{label}_bundle.bin"
        runtime_meta = base.role_runtime_dir("cs") / "ciphertexts" / f"{label}_bundle.meta"
        persistent_bundle = bundles_dir / f"{label}_bundle.bin"
        persistent_meta = metas_dir / f"{label}_bundle.meta"
        shutil.copy2(runtime_bundle, persistent_bundle)
        rewrite_meta_bundle_path(runtime_meta, persistent_meta, persistent_bundle)

    manifest = {
        "keyword_pool_count": keyword_pool_count,
        "keywords_per_bundle": keywords_per_bundle,
        "max_files": max_files,
        "query_keyword_count": query_keyword_count,
        "seed": seed,
        "target_label": bundle_label(0),
        "query_keywords": query_keywords,
        "labels": labels,
    }
    save_manifest(target_dir, manifest)
    return target_dir


def activate_corpus_prefix(target_dir: Path, file_count: int):
    manifest = load_manifest(target_dir)
    labels = manifest["labels"]
    if file_count > len(labels):
        raise ValueError(f"Requested file_count={file_count} exceeds cached corpus size {len(labels)}")

    base.reset_role_runtime("cs")
    base.setup_role("cs")
    base.register_user("cs", "search_user", base.FIXED_POLICIES[0][2], None)
    base.register_user("cs", "owner_search", base.FIXED_POLICIES[0][2], None)

    ciphertext_dir = base.role_runtime_dir("cs") / "ciphertexts"
    ciphertext_dir.mkdir(parents=True, exist_ok=True)
    metas_dir = target_dir / "metas"
    for label in labels[:file_count]:
        shutil.copy2(metas_dir / f"{label}_bundle.meta", ciphertext_dir / f"{label}_bundle.meta")


def run_search_steps(
    keyword_pool_count: int,
    keywords_per_bundle: int,
    max_files: int,
    query_keyword_count: int,
    file_steps: list[int],
    seed: int,
):
    target_dir = ensure_persistent_corpus(
        keyword_pool_count,
        keywords_per_bundle,
        max_files,
        query_keyword_count,
        seed,
    )
    manifest = load_manifest(target_dir)
    query_keywords = manifest["query_keywords"]
    target_label = manifest["target_label"]

    for file_count in file_steps:
        activate_corpus_prefix(target_dir, file_count)
        request_name = f"file_count_{file_count}"
        request_dir, _ = base.prepare_query("cs", "search_user", target_label, query_keywords, request_name)
        response_dir = base.role_runtime_dir("cs") / "service" / "responses" / request_name
        candidate_ms = base.process_query(request_dir, response_dir, request_name)
        candidate_count = int((response_dir / "candidate_count.txt").read_text(encoding="utf-8").strip())
        exact_count = int((response_dir / "exact_match_count.txt").read_text(encoding="utf-8").strip())
        print(
            f"file_count={file_count} candidate_ms={candidate_ms:.3f} "
            f"candidate_count={candidate_count} exact_match_count={exact_count}"
        )


def prepare_keyword_step_corpora(
    step_pairs: list[tuple[int, int]],
    max_files: int,
    query_keyword_count: int,
    seed: int,
):
    for keyword_pool_count, keywords_per_bundle in step_pairs:
        target_dir = ensure_persistent_corpus(
            keyword_pool_count,
            keywords_per_bundle,
            max_files,
            query_keyword_count,
            seed,
        )
        print(
            f"keyword_pool={keyword_pool_count} keywords_per_bundle={keywords_per_bundle} "
            f"persistent_corpus={target_dir}"
        )


def run_keyword_search_steps(
    step_pairs: list[tuple[int, int]],
    max_files: int,
    query_keyword_count: int,
    file_count: int,
    seed: int,
):
    for keyword_pool_count, keywords_per_bundle in step_pairs:
        target_dir = ensure_persistent_corpus(
            keyword_pool_count,
            keywords_per_bundle,
            max_files,
            query_keyword_count,
            seed,
        )
        manifest = load_manifest(target_dir)
        query_keywords = manifest["query_keywords"]
        target_label = manifest["target_label"]

        activate_corpus_prefix(target_dir, file_count)
        request_name = f"keyword_step_{keyword_pool_count}_{keywords_per_bundle}_{file_count}"
        request_dir, _ = base.prepare_query("cs", "search_user", target_label, query_keywords, request_name)
        response_dir = base.role_runtime_dir("cs") / "service" / "responses" / request_name
        candidate_ms = base.process_query(request_dir, response_dir, request_name)
        candidate_count = int((response_dir / "candidate_count.txt").read_text(encoding="utf-8").strip())
        exact_count = int((response_dir / "exact_match_count.txt").read_text(encoding="utf-8").strip())
        print(
            f"keyword_pool={keyword_pool_count} keywords_per_bundle={keywords_per_bundle} "
            f"file_count={file_count} candidate_ms={candidate_ms:.3f} "
            f"candidate_count={candidate_count} exact_match_count={exact_count}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persistent file-count corpus helper for RunFullSys search experiments.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_args(subparser: argparse.ArgumentParser):
        subparser.add_argument("--keyword-pool", type=int, default=400)
        subparser.add_argument("--keywords-per-bundle", type=int, default=50)
        subparser.add_argument("--max-files", type=int, default=1000)
        subparser.add_argument("--query-keywords", type=int, default=DEFAULT_QUERY_KEYWORDS)
        subparser.add_argument("--seed", type=int, default=1337)

    prepare = subparsers.add_parser("prepare", help="Generate and cache the max-size corpus once.")
    add_common_args(prepare)

    run = subparsers.add_parser("run-search", help="Reuse the cached corpus and test prefix file counts.")
    add_common_args(run)
    run.add_argument("--file-steps", default="10,100,300,500,1000")

    prepare_keyword = subparsers.add_parser(
        "prepare-keyword-steps",
        help="Generate and cache persistent corpora for multiple keyword-scaling steps.",
    )
    add_common_args(prepare_keyword)
    prepare_keyword.add_argument("--keyword-steps", default="10,50,100,300,500")
    prepare_keyword.add_argument(
        "--bundle-keyword-steps",
        default="",
        help="Optional comma-separated keywords-per-bundle steps. Defaults to matching keyword-steps.",
    )

    run_keyword = subparsers.add_parser(
        "run-keyword-search",
        help="Reuse cached keyword-step corpora and run one search at a fixed file count.",
    )
    add_common_args(run_keyword)
    run_keyword.add_argument("--keyword-steps", default="10,50,100,300,500")
    run_keyword.add_argument(
        "--bundle-keyword-steps",
        default="",
        help="Optional comma-separated keywords-per-bundle steps. Defaults to matching keyword-steps.",
    )
    run_keyword.add_argument("--file-count", type=int, default=100)

    return parser


def main():
    args = build_parser().parse_args()
    if args.command == "prepare":
        target_dir = ensure_persistent_corpus(
            args.keyword_pool,
            args.keywords_per_bundle,
            args.max_files,
            args.query_keywords,
            args.seed,
        )
        print(f"Persistent corpus ready at {target_dir}")
        return

    if args.command == "prepare-keyword-steps":
        keyword_steps = parse_int_list(args.keyword_steps)
        if not keyword_steps:
            keyword_steps = DEFAULT_KEYWORD_STEPS
        prepare_keyword_step_corpora(
            resolve_step_pairs(keyword_steps, args.bundle_keyword_steps),
            args.max_files,
            args.query_keywords,
            args.seed,
        )
        return

    if args.command == "run-keyword-search":
        keyword_steps = parse_int_list(args.keyword_steps)
        if not keyword_steps:
            keyword_steps = DEFAULT_KEYWORD_STEPS
        run_keyword_search_steps(
            resolve_step_pairs(keyword_steps, args.bundle_keyword_steps),
            args.max_files,
            args.query_keywords,
            args.file_count,
            args.seed,
        )
        return

    file_steps = parse_int_list(args.file_steps)
    if not file_steps:
        file_steps = DEFAULT_FILE_STEPS
    run_search_steps(
        args.keyword_pool,
        args.keywords_per_bundle,
        args.max_files,
        args.query_keywords,
        file_steps,
        args.seed,
    )


if __name__ == "__main__":
    main()
