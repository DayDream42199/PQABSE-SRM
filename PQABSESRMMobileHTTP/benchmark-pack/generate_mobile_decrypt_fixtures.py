#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path


DEFAULT_COUNTS = [10, 50, 300, 500]
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "fixtures"
RUN_FULL_SYS = Path(__file__).resolve().parents[2] / "RunFullSys"


def parse_counts(raw: str) -> list[int]:
    values = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            values.append(int(item))
    return values or DEFAULT_COUNTS


def copy_tree_if_exists(src: Path, dst: Path):
    if dst.exists():
        shutil.rmtree(dst)
    if src.exists():
        shutil.copytree(src, dst)


def snapshot_runtime(runtime_dir: Path, snapshot_dir: Path):
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    for name in ("abse", "state", "users", "ciphertexts"):
        copy_tree_if_exists(runtime_dir / name, snapshot_dir / name)


def restore_runtime(runtime_dir: Path, snapshot_dir: Path):
    runtime_dir.mkdir(parents=True, exist_ok=True)
    for name in ("abse", "state", "users", "ciphertexts"):
        target = runtime_dir / name
        if target.exists():
            shutil.rmtree(target)
        source = snapshot_dir / name
        if source.exists():
            shutil.copytree(source, target)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Android mobile decrypt fixtures with bundles matching kw_0001..kw_N."
    )
    parser.add_argument("--counts", default=",".join(str(v) for v in DEFAULT_COUNTS))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--run-full-sys", type=Path, default=RUN_FULL_SYS)
    args = parser.parse_args()

    counts = parse_counts(args.counts)
    output_dir = args.output
    run_full_sys = args.run_full_sys
    sys.path.insert(0, str(run_full_sys))

    import run_revised_experiments as base

    runtime_dir = base.role_runtime_dir("cs")
    output_dir.mkdir(parents=True, exist_ok=True)
    bundles_dir = output_dir / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="pqabse-mobile-fixture-") as tmp:
        snapshot_dir = Path(tmp) / "runtime_snapshot"
        snapshot_runtime(runtime_dir, snapshot_dir)
        try:
            base.reset_role_runtime("cs")
            base.setup_role("cs")
            policy_type, threshold, policy_attrs = base.FIXED_POLICIES[0]
            base.register_user("cs", "search_user", policy_attrs, None)
            base.register_user("cs", "owner_search", policy_attrs, None)

            shutil.copy2(runtime_dir / "abse" / "phase1_params.txt", output_dir / "phase1_params.txt")
            shutil.copy2(runtime_dir / "users" / "search_user_userkey.bin", output_dir / "user_key.bin")

            manifest = {
                "keyword_counts": counts,
                "keyword_pattern": "kw_%04d",
                "bundles": [],
            }

            for count in counts:
                label = f"keywords_{count:04d}"
                keywords = [f"kw_{index:04d}" for index in range(1, count + 1)]
                base.encrypt_bundle(
                    "cs",
                    "owner_search",
                    label,
                    f"mobile decrypt fixture payload {count}",
                    policy_type,
                    threshold,
                    policy_attrs,
                    keywords,
                )
                source_bundle = runtime_dir / "ciphertexts" / f"{label}_bundle.bin"
                dest_bundle = bundles_dir / f"{label}_bundle.bin"
                shutil.copy2(source_bundle, dest_bundle)
                manifest["bundles"].append(
                    {
                        "keyword_count": count,
                        "label": label,
                        "bundle": str(dest_bundle),
                        "keywords_first": keywords[:5],
                        "keywords_last": keywords[-5:],
                    }
                )

            (output_dir / "mobile_decrypt_fixtures_manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
        finally:
            restore_runtime(runtime_dir, snapshot_dir)

    print(f"Mobile decrypt fixtures ready at {output_dir}")
    for count in counts:
        print(f"  {bundles_dir / f'keywords_{count:04d}_bundle.bin'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
