"""Synthetic benchmark runner for the three reference-paper baselines.

This script does not attempt full cryptographic reproduction of the cited
schemes. Instead, it re-implements the benchmark-relevant workloads in a
lightweight and deterministic way so we can compare the same families of
metrics inside this repository:

- ReferenceTestPaper1.txt: encryption, trapdoor generation, search, decryption
- ReferenceTestPaper4.txt: key generation
- ReferenceTestPaper5.txt: revocation

The operation shapes mirror the papers' experiments:
- Paper 1 keeps keyword-scaling work roughly constant once keywords fit in the
  same packed polynomial degree.
- Paper 4 key generation scales with the number of attributes.
- Paper 5 revocation measures update generation + key update + ciphertext
  update, and here we scale it by active user count to match the comparison
  style already used in this repo.
"""

from __future__ import annotations

import argparse
import csv
import heapq
import random
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "reference_experiment_results"

# Patched for the requested Paper 6 scaling.
KEYWORD_COUNTS = [20, 300, 500, 1000]
KEYGEN_ATTR_COUNTS = [10, 20, 30, 40, 50]
REVOCATION_USER_COUNTS = [10, 20, 30, 40, 50]
RUNS_PER_POINT = 5
SEARCH_FILE_COUNT = 100

MODULUS = 2_147_483_647
PAPER1_QUERY_KEYWORDS = 5
PAPER1_TOP_K = 10
PAPER4_RING_DIM = 128
PAPER5_RING_DIM = 128
PAPER5_REVOKED_ATTRS = 2
PAPER5_CIPHERTEXT_COMPONENTS = 20
PAPER6_VECTOR_DIM = 256
PAPER6_KEYGEN_ROUNDS = 24
PAPER6_ENCRYPTION_ROUNDS = 18
PAPER6_DECRYPTION_ROUNDS = 12


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run synthetic reference-paper benchmarks.")
    parser.add_argument(
        "--paper",
        choices=["all", "paper1", "paper4", "paper5", "paper6"],
        default="all",
        help="Run all reference-paper benchmarks or just one family.",
    )
    parser.add_argument("--runs", type=int, default=RUNS_PER_POINT, help="Runs per point.")
    parser.add_argument(
        "--search-file-count",
        type=int,
        default=SEARCH_FILE_COUNT,
        help="Synthetic corpus size used by the Paper 1 search benchmark.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RESULTS_DIR,
        help="Directory where CSV outputs are written.",
    )
    return parser


def print_phase(message: str):
    print(f"[phase] {message}", flush=True)


def print_progress(label: str, current: int, total: int, detail: str):
    print(f"[progress] {label} {current}/{total}: {detail}", flush=True)


def choose_poly_degree(keyword_count: int) -> int:
    degree = 2048
    while degree // 2 < keyword_count:
        degree *= 2
    return degree


def rotate(values: list[int], shift: int) -> list[int]:
    if not values:
        return []
    offset = shift % len(values)
    if offset == 0:
        return values[:]
    return values[offset:] + values[:offset]


def vec_add(left: list[int], right: list[int]) -> list[int]:
    return [(a + b) % MODULUS for a, b in zip(left, right)]


def vec_sub(left: list[int], right: list[int]) -> list[int]:
    return [(a - b) % MODULUS for a, b in zip(left, right)]


def vec_mul(left: list[int], right: list[int]) -> list[int]:
    return [(a * b) % MODULUS for a, b in zip(left, right)]


def scalar_mix(values: list[int], scalar: int) -> list[int]:
    return [(value * scalar) % MODULUS for value in values]


def make_sparse_vector(
    slot_count: int,
    active_count: int,
    rng: random.Random,
    min_value: int = 0,
    max_value: int = 1,
) -> list[int]:
    vector = [0] * slot_count
    count = min(slot_count, max(0, active_count))
    for index in rng.sample(range(slot_count), count):
        vector[index] = rng.randint(min_value, max_value)
    return vector


def dot_score(left: list[int], right: list[int]) -> int:
    return sum((a * b) % MODULUS for a, b in zip(left, right)) % MODULUS


def write_csv(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def average_ms(values: list[float]) -> float:
    return sum(values) / len(values)


def seed_for(*parts: int) -> int:
    seed = 49_363
    for part in parts:
        seed = (seed * 1_315_423_911 ^ part) & 0xFFFFFFFF
    return seed


def paper1_build_corpus(keyword_count: int, file_count: int, run_idx: int) -> tuple[int, list[dict[str, list[int]]]]:
    degree = choose_poly_degree(keyword_count)
    slots = degree // 2
    corpus: list[dict[str, list[int]]] = []
    rng = random.Random(seed_for(1, keyword_count, run_idx))
    doc_keyword_count = max(PAPER1_QUERY_KEYWORDS, min(slots, max(8, keyword_count // 20)))
    for doc_idx in range(file_count):
        doc_rng = random.Random(rng.randint(0, 1_000_000_000) ^ doc_idx)
        encoded = make_sparse_vector(slots, doc_keyword_count, doc_rng)
        noise_a = make_sparse_vector(slots, doc_keyword_count, doc_rng, 0, 17)
        noise_b = make_sparse_vector(slots, doc_keyword_count, doc_rng, 0, 17)
        secret = make_sparse_vector(slots, doc_keyword_count, doc_rng, 1, 31)
        c0 = vec_add(encoded, noise_a)
        c1 = vec_add(vec_mul(encoded, secret), noise_b)
        corpus.append({"c0": c0, "c1": c1, "secret": secret})
    return slots, corpus


def paper1_encrypt(keyword_count: int, run_idx: int) -> float:
    degree = choose_poly_degree(keyword_count)
    slots = degree // 2
    rng = random.Random(seed_for(101, keyword_count, run_idx))
    active_count = min(slots, max(PAPER1_QUERY_KEYWORDS, keyword_count))
    payload = make_sparse_vector(slots, active_count, rng)
    secret = make_sparse_vector(slots, active_count, rng, 1, 31)
    mask = make_sparse_vector(slots, active_count, rng, 1, 127)
    noise_a = make_sparse_vector(slots, active_count, rng, 0, 19)
    noise_b = make_sparse_vector(slots, active_count, rng, 0, 19)

    start = time.perf_counter()
    c0 = vec_add(payload, noise_a)
    c1 = vec_add(vec_mul(payload, secret), noise_b)
    _ = vec_add(c0, scalar_mix(mask, 7))
    _ = vec_add(c1, scalar_mix(mask, 11))
    return (time.perf_counter() - start) * 1000.0


def paper1_trapdoor(keyword_count: int, run_idx: int) -> tuple[float, dict[str, list[int]]]:
    degree = choose_poly_degree(keyword_count)
    slots = degree // 2
    rng = random.Random(seed_for(102, keyword_count, run_idx))
    query = make_sparse_vector(slots, min(PAPER1_QUERY_KEYWORDS, keyword_count), rng)
    secret = make_sparse_vector(slots, min(PAPER1_QUERY_KEYWORDS, keyword_count), rng, 1, 31)
    rekey = make_sparse_vector(slots, min(PAPER1_QUERY_KEYWORDS, keyword_count), rng, 1, 17)
    noise = make_sparse_vector(slots, min(PAPER1_QUERY_KEYWORDS, keyword_count), rng, 0, 11)

    start = time.perf_counter()
    beta0 = vec_add(query, noise)
    beta1 = vec_add(vec_mul(query, secret), scalar_mix(rekey, 3))
    beta2 = vec_add(beta0, scalar_mix(rekey, 5))
    beta3 = vec_add(beta1, rotate(beta0, 3))
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, {"beta0": beta0, "beta1": beta1, "beta2": beta2, "beta3": beta3}


def paper1_search(keyword_count: int, file_count: int, run_idx: int) -> tuple[float, list[dict[str, object]]]:
    _, trapdoor = paper1_trapdoor(keyword_count, run_idx)
    slots, corpus = paper1_build_corpus(keyword_count, file_count, run_idx)
    _ = slots

    start = time.perf_counter()
    ranked: list[tuple[int, int, list[int]]] = []
    for doc_idx, doc in enumerate(corpus):
        left = vec_mul(doc["c0"], trapdoor["beta0"])
        right = vec_mul(doc["c1"], trapdoor["beta1"])
        merged = vec_add(left, right)
        score = dot_score(merged, trapdoor["beta2"])
        ranked.append((score, doc_idx, merged))
    top_results = heapq.nlargest(PAPER1_TOP_K, ranked, key=lambda item: item[0])
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, [
        {"score": score, "doc_idx": doc_idx, "merged": merged}
        for score, doc_idx, merged in top_results
    ]


def paper1_decrypt(keyword_count: int, file_count: int, run_idx: int) -> float:
    _, trapdoor = paper1_trapdoor(keyword_count, run_idx)
    _, top_results = paper1_search(keyword_count, file_count, run_idx)
    proxy_key = rotate(trapdoor["beta3"], 5)

    start = time.perf_counter()
    outputs = []
    for result in top_results:
        phase1 = vec_sub(result["merged"], trapdoor["beta2"])
        phase2 = vec_add(phase1, proxy_key)
        outputs.append(dot_score(phase2, trapdoor["beta0"]))
    _ = sum(outputs) % MODULUS
    return (time.perf_counter() - start) * 1000.0


def simulate_paper4_keygen(attribute_count: int, run_idx: int) -> float:
    rng = random.Random(seed_for(201, attribute_count, run_idx))
    start = time.perf_counter()
    for attr_idx in range(attribute_count):
        attr_rng = random.Random(rng.randint(0, 1_000_000_000) ^ attr_idx)
        base = make_sparse_vector(PAPER4_RING_DIM, PAPER4_RING_DIM // 3, attr_rng, 1, 101)
        trap = make_sparse_vector(PAPER4_RING_DIM, PAPER4_RING_DIM // 3, attr_rng, 1, 31)
        noise = make_sparse_vector(PAPER4_RING_DIM, PAPER4_RING_DIM // 4, attr_rng, 0, 13)
        secret_one = vec_add(base, noise)
        secret_two = vec_mul(base, trap)
        _ = vec_add(secret_one, rotate(secret_two, attr_idx + 1))
    return (time.perf_counter() - start) * 1000.0


def simulate_paper5_revocation(active_user_count: int, run_idx: int) -> float:
    rng = random.Random(seed_for(301, active_user_count, run_idx))
    users = []
    for user_idx in range(active_user_count):
        user_rng = random.Random(rng.randint(0, 1_000_000_000) ^ user_idx)
        attrs = []
        for _attr_idx in range(PAPER5_REVOKED_ATTRS):
            attrs.append(
                {
                    "sk1": make_sparse_vector(PAPER5_RING_DIM, PAPER5_RING_DIM // 4, user_rng, 1, 97),
                    "sk2": make_sparse_vector(PAPER5_RING_DIM, PAPER5_RING_DIM // 4, user_rng, 1, 97),
                }
            )
        users.append(attrs)

    ciphertexts = []
    for ct_idx in range(PAPER5_CIPHERTEXT_COMPONENTS):
        ct_rng = random.Random(rng.randint(0, 1_000_000_000) ^ ct_idx)
        ciphertexts.append(make_sparse_vector(PAPER5_RING_DIM, PAPER5_RING_DIM // 4, ct_rng, 1, 97))

    start = time.perf_counter()
    update_material = []
    for attr_idx in range(PAPER5_REVOKED_ATTRS):
        update_rng = random.Random(rng.randint(0, 1_000_000_000) ^ (attr_idx + 17))
        old_g = make_sparse_vector(PAPER5_RING_DIM, PAPER5_RING_DIM // 5, update_rng, 1, 53)
        new_g = make_sparse_vector(PAPER5_RING_DIM, PAPER5_RING_DIM // 5, update_rng, 1, 53)
        f_old = make_sparse_vector(PAPER5_RING_DIM, PAPER5_RING_DIM // 5, update_rng, 1, 53)
        f_new = make_sparse_vector(PAPER5_RING_DIM, PAPER5_RING_DIM // 5, update_rng, 1, 53)
        kuk1 = vec_sub(new_g, old_g)
        kuk2 = vec_sub(vec_mul(new_g, f_new), vec_mul(old_g, f_old))
        cuk = vec_sub(f_new, f_old)
        update_material.append((kuk1, kuk2, cuk))

    for user_attrs in users[1:]:
        for attr_idx, (kuk1, kuk2, _cuk) in enumerate(update_material):
            user_attrs[attr_idx]["sk1"] = vec_add(user_attrs[attr_idx]["sk1"], kuk1)
            user_attrs[attr_idx]["sk2"] = vec_add(user_attrs[attr_idx]["sk2"], kuk2)

    for _kuk1, _kuk2, cuk in update_material:
        for index, component in enumerate(ciphertexts):
            ciphertexts[index] = vec_add(component, cuk)

    return (time.perf_counter() - start) * 1000.0


def paper6_vector_pair(rng: random.Random, active_count: int, value_hi: int) -> tuple[list[int], list[int]]:
    left = make_sparse_vector(PAPER6_VECTOR_DIM, active_count, rng, 1, value_hi)
    right = make_sparse_vector(PAPER6_VECTOR_DIM, active_count, rng, 1, value_hi)
    return left, right


def paper6_keygen(attribute_count: int, run_idx: int) -> float:
    rng = random.Random(seed_for(401, attribute_count, run_idx))
    per_attr_active = max(16, min(PAPER6_VECTOR_DIM // 3, 12 + attribute_count // 2))

    start = time.perf_counter()
    for attr_idx in range(attribute_count):
        attr_rng = random.Random(rng.randint(0, 1_000_000_000) ^ (attr_idx * 31 + 7))
        base, tweak = paper6_vector_pair(attr_rng, per_attr_active, 131)
        accum = vec_add(base, rotate(tweak, (attr_idx % 11) + 1))
        for round_idx in range(PAPER6_KEYGEN_ROUNDS):
            noise = make_sparse_vector(PAPER6_VECTOR_DIM, per_attr_active // 2, attr_rng, 0, 23)
            mix = scalar_mix(tweak, (round_idx % 7) + 2)
            accum = vec_add(accum, noise)
            accum = vec_add(accum, rotate(mix, (round_idx + attr_idx) % 17))
            tweak = vec_mul(vec_add(base, noise), rotate(tweak, (round_idx % 5) + 1))
        _ = dot_score(accum, tweak)
    return (time.perf_counter() - start) * 1000.0


def paper6_encrypt(keyword_count: int, run_idx: int) -> float:
    rng = random.Random(seed_for(402, keyword_count, run_idx))
    active_count = max(24, min(PAPER6_VECTOR_DIM // 2, keyword_count // 3 + 16))
    segments = max(1, keyword_count // 20)

    start = time.perf_counter()
    for segment_idx in range(segments):
        seg_rng = random.Random(rng.randint(0, 1_000_000_000) ^ (segment_idx * 13 + 3))
        payload, mask = paper6_vector_pair(seg_rng, active_count, 191)
        secret = make_sparse_vector(PAPER6_VECTOR_DIM, active_count, seg_rng, 1, 73)
        aux = make_sparse_vector(PAPER6_VECTOR_DIM, max(12, active_count // 2), seg_rng, 0, 29)
        c0 = payload
        c1 = mask
        for round_idx in range(PAPER6_ENCRYPTION_ROUNDS):
            round_noise = make_sparse_vector(PAPER6_VECTOR_DIM, max(8, active_count // 3), seg_rng, 0, 17)
            c0 = vec_add(vec_add(c0, round_noise), scalar_mix(secret, (round_idx % 9) + 2))
            c1 = vec_add(vec_mul(c1, rotate(secret, (round_idx % 7) + 1)), aux)
            aux = vec_add(rotate(aux, (round_idx % 19) + 1), scalar_mix(mask, (round_idx % 5) + 3))
        _ = dot_score(c0, c1)
    return (time.perf_counter() - start) * 1000.0


def paper6_decrypt(keyword_count: int, run_idx: int) -> float:
    rng = random.Random(seed_for(403, keyword_count, run_idx))
    active_count = max(20, min(PAPER6_VECTOR_DIM // 2, keyword_count // 4 + 12))
    segments = max(1, keyword_count // 20)

    start = time.perf_counter()
    for segment_idx in range(segments):
        seg_rng = random.Random(rng.randint(0, 1_000_000_000) ^ (segment_idx * 29 + 5))
        transformed, witness = paper6_vector_pair(seg_rng, active_count, 149)
        token = make_sparse_vector(PAPER6_VECTOR_DIM, active_count, seg_rng, 1, 61)
        refresh = make_sparse_vector(PAPER6_VECTOR_DIM, max(10, active_count // 2), seg_rng, 0, 19)
        for round_idx in range(PAPER6_DECRYPTION_ROUNDS):
            phase1 = vec_sub(transformed, scalar_mix(refresh, (round_idx % 7) + 2))
            phase2 = vec_add(phase1, rotate(token, (round_idx % 13) + 1))
            witness = vec_add(witness, vec_mul(phase2, rotate(token, (round_idx % 5) + 1)))
            transformed = vec_add(phase2, rotate(refresh, (round_idx % 11) + 1))
            refresh = vec_add(refresh, scalar_mix(token, (round_idx % 3) + 2))
        _ = dot_score(transformed, witness)
    return (time.perf_counter() - start) * 1000.0


def run_paper1(runs: int, search_file_count: int, output_dir: Path):
    print_phase("Starting Reference Paper 1 benchmark")
    encryption_rows = []
    trapdoor_rows = []
    search_rows = []
    decrypt_rows = []

    for keyword_count in KEYWORD_COUNTS:
        encryption_values = []
        trapdoor_values = []
        search_values = []
        decrypt_values = []
        for run_idx in range(runs):
            print_progress("paper1", run_idx + 1, runs, f"keyword_count={keyword_count}")
            encryption_values.append(paper1_encrypt(keyword_count, run_idx))
            trapdoor_ms, _ = paper1_trapdoor(keyword_count, run_idx)
            trapdoor_values.append(trapdoor_ms)
            search_values.append(paper1_search(keyword_count, search_file_count, run_idx)[0])
            decrypt_values.append(paper1_decrypt(keyword_count, search_file_count, run_idx))

        encryption_avg = average_ms(encryption_values)
        trapdoor_avg = average_ms(trapdoor_values)
        search_avg = average_ms(search_values)
        decrypt_avg = average_ms(decrypt_values)

        print(f"paper1_encryption: keyword_count={keyword_count} runs={runs} avg_ms={encryption_avg:.3f}")
        print(f"paper1_trapdoor: keyword_count={keyword_count} runs={runs} avg_ms={trapdoor_avg:.3f}")
        print(f"paper1_search: keyword_count={keyword_count} runs={runs} avg_ms={search_avg:.3f}")
        print(f"paper1_decryption: keyword_count={keyword_count} runs={runs} avg_ms={decrypt_avg:.3f}")

        encryption_rows.append(
            {"experiment": "paper1_encryption", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{encryption_avg:.3f}"}
        )
        trapdoor_rows.append(
            {"experiment": "paper1_trapdoor", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{trapdoor_avg:.3f}"}
        )
        search_rows.append(
            {
                "experiment": "paper1_search",
                "keyword_count": keyword_count,
                "file_count": search_file_count,
                "runs": runs,
                "avg_ms": f"{search_avg:.3f}",
            }
        )
        decrypt_rows.append(
            {
                "experiment": "paper1_decryption",
                "keyword_count": keyword_count,
                "top_k": PAPER1_TOP_K,
                "runs": runs,
                "avg_ms": f"{decrypt_avg:.3f}",
            }
        )

    write_csv(output_dir / "paper1_encryption_results.csv", encryption_rows)
    write_csv(output_dir / "paper1_trapdoor_results.csv", trapdoor_rows)
    write_csv(output_dir / "paper1_search_results.csv", search_rows)
    write_csv(output_dir / "paper1_decryption_results.csv", decrypt_rows)


def run_paper4(runs: int, output_dir: Path):
    print_phase("Starting Reference Paper 4 benchmark")
    rows = []
    for attr_count in KEYGEN_ATTR_COUNTS:
        values = []
        for run_idx in range(runs):
            print_progress("paper4_keygen", run_idx + 1, runs, f"attribute_count={attr_count}")
            values.append(simulate_paper4_keygen(attr_count, run_idx))
        avg = average_ms(values)
        print(f"paper4_keygen: attribute_count={attr_count} runs={runs} avg_ms={avg:.3f}")
        rows.append(
            {"experiment": "paper4_keygen", "attribute_count": attr_count, "runs": runs, "avg_ms": f"{avg:.3f}"}
        )
    write_csv(output_dir / "paper4_keygen_results.csv", rows)


def run_paper5(runs: int, output_dir: Path):
    print_phase("Starting Reference Paper 5 benchmark")
    rows = []
    for user_count in REVOCATION_USER_COUNTS:
        values = []
        for run_idx in range(runs):
            print_progress("paper5_revocation", run_idx + 1, runs, f"active_user_count={user_count}")
            values.append(simulate_paper5_revocation(user_count, run_idx))
        avg = average_ms(values)
        print(f"paper5_revocation: active_user_count={user_count} runs={runs} avg_ms={avg:.3f}")
        rows.append(
            {"experiment": "paper5_revocation", "active_user_count": user_count, "runs": runs, "avg_ms": f"{avg:.3f}"}
        )
    write_csv(output_dir / "paper5_revocation_results.csv", rows)


def run_paper6(runs: int, search_file_count: int, output_dir: Path):
    print_phase("Starting Reference Paper 6 benchmark")
    _ = search_file_count

    keygen_rows = []
    encryption_rows = []
    decrypt_rows = []

    for attr_count in KEYGEN_ATTR_COUNTS:
        values = []
        for run_idx in range(runs):
            print_progress("paper6_keygen", run_idx + 1, runs, f"attribute_count={attr_count}")
            values.append(paper6_keygen(attr_count, run_idx))
        avg = average_ms(values)
        print(f"paper6_keygen: attribute_count={attr_count} runs={runs} avg_ms={avg:.3f}")
        keygen_rows.append(
            {"experiment": "paper6_keygen", "attribute_count": attr_count, "runs": runs, "avg_ms": f"{avg:.3f}"}
        )

    for keyword_count in KEYWORD_COUNTS:
        encryption_values = []
        decrypt_values = []
        for run_idx in range(runs):
            print_progress("paper6_encryption", run_idx + 1, runs, f"keyword_count={keyword_count}")
            encryption_values.append(paper6_encrypt(keyword_count, run_idx))
            print_progress("paper6_decryption", run_idx + 1, runs, f"keyword_count={keyword_count}")
            decrypt_values.append(paper6_decrypt(keyword_count, run_idx))

        encryption_avg = average_ms(encryption_values)
        decrypt_avg = average_ms(decrypt_values)
        print(f"paper6_encryption: keyword_count={keyword_count} runs={runs} avg_ms={encryption_avg:.3f}")
        print(f"paper6_decryption: keyword_count={keyword_count} runs={runs} avg_ms={decrypt_avg:.3f}")
        encryption_rows.append(
            {"experiment": "paper6_encryption", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{encryption_avg:.3f}"}
        )
        decrypt_rows.append(
            {
                "experiment": "paper6_decryption",
                "keyword_count": keyword_count,
                "top_k": PAPER1_TOP_K,
                "runs": runs,
                "avg_ms": f"{decrypt_avg:.3f}",
            }
        )

    write_csv(output_dir / "paper6_keygen_results.csv", keygen_rows)
    write_csv(output_dir / "paper6_encryption_results.csv", encryption_rows)
    write_csv(output_dir / "paper6_decryption_results.csv", decrypt_rows)


def main():
    args = build_parser().parse_args()
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.paper in {"all", "paper1"}:
        run_paper1(args.runs, args.search_file_count, output_dir)
    if args.paper in {"all", "paper4"}:
        run_paper4(args.runs, output_dir)
    if args.paper in {"all", "paper5"}:
        run_paper5(args.runs, output_dir)
    if args.paper == "paper6":
        run_paper6(args.runs, args.search_file_count, output_dir)

    print(f"Reference paper benchmark outputs written under {output_dir}")


if __name__ == "__main__":
    main()
