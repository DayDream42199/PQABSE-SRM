"""Synthetic benchmark runner for the reference-paper baselines.

This script does not attempt full cryptographic reproduction of the cited
schemes. Instead, it re-implements the benchmark-relevant workloads in a
lightweight and deterministic way so we can compare the same families of
metrics inside this repository:

- ReferenceTestPaper1.txt: encryption, trapdoor generation, search, decryption
- ReferenceTestPaper4.txt: key generation
- ReferenceTestPaper5.txt: revocation
- ReferenceTestPaper8.txt: encryption, trapdoor generation, search, revocation
- ReferenceTestPaper9.txt: encryption, trapdoor generation, search/test

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
import pickle
import random
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "reference_experiment_results"
CORPUS_CACHE_ROOT = ROOT / "reference_test_corpus" / "generated"

# Patched for the requested Paper 6 scaling.
KEYWORD_COUNTS = [10, 50, 100, 300, 500]
KEYGEN_ATTR_COUNTS = [10, 20, 30, 40, 50]
REVOCATION_USER_COUNTS = [10, 20, 30, 40, 50]
RUNS_PER_POINT = 5
SEARCH_FILE_COUNT = 100
FILE_COUNTS = [10, 100, 300, 500, 1000]

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
PAPER8_MATRIX_DIM = 192
PAPER8_TAG_WIDTH = 12
PAPER8_CANDIDATE_FACTOR = 4
PAPER8_PUNCTURE_ROUNDS = 10
PAPER9_VECTOR_DIM = 224
PAPER9_TEST_STRING_LEN = 10
PAPER9_CANDIDATE_FACTOR = 4

COMMON_BAND_RATIO = 0.05
MEDIUM_BAND_RATIO = 0.20
RARE_BAND_RATIO = 0.35
COMMON_PER_DOC_RATIO = 0.16
MEDIUM_PER_DOC_RATIO = 0.36
RARE_PER_DOC_RATIO = 0.28
SELECTIVE_CLUSTER_SPAN = 8


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run synthetic reference-paper benchmarks.")
    parser.add_argument(
        "--paper",
        choices=["all", "paper1", "paper4", "paper5", "paper6", "paper8", "paper9"],
        default="all",
        help="Run all reference-paper benchmarks or just one family.",
    )
    parser.add_argument("--runs", type=int, default=RUNS_PER_POINT, help="Runs per point.")
    parser.add_argument(
        "--search-file-count",
        type=int,
        default=SEARCH_FILE_COUNT,
        help="Synthetic corpus size used by the Paper 1 keyword-scaling benchmark.",
    )
    parser.add_argument(
        "--paper1-file-counts",
        default="10,100,300,500,1000",
        help="Default file-count steps for the Paper 1 file-scaling benchmark.",
    )
    parser.add_argument(
        "--paper1-keyword-counts",
        default="10,50,100,300,500",
        help="Default keyword-count steps for the Paper 1 keyword-scaling benchmark.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RESULTS_DIR,
        help="Directory where CSV outputs are written.",
    )
    parser.add_argument(
        "--corpus-cache-dir",
        type=Path,
        default=CORPUS_CACHE_ROOT,
        help="Directory where reusable Paper 1 synthetic corpora are cached.",
    )
    return parser


def parse_int_list(raw: str) -> list[int]:
    values = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            values.append(int(item))
    return values


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


def split_band_counts(keyword_count: int) -> tuple[int, int, int, int]:
    common = max(1, int(keyword_count * COMMON_BAND_RATIO))
    medium = max(1, int(keyword_count * MEDIUM_BAND_RATIO))
    rare = max(1, int(keyword_count * RARE_BAND_RATIO))
    selective = keyword_count - common - medium - rare
    if selective <= 0:
        selective = 1
        rare = max(1, rare - 1)
    return common, medium, rare, selective


def banded_keyword_indices(keyword_count: int, file_count: int, run_idx: int) -> list[list[int]]:
    common_count, medium_count, rare_count, selective_count = split_band_counts(keyword_count)
    common_range = list(range(common_count))
    medium_range = list(range(common_count, common_count + medium_count))
    rare_range = list(range(common_count + medium_count, common_count + medium_count + rare_count))
    selective_range = list(range(common_count + medium_count + rare_count, keyword_count))

    keywords_per_doc = max(PAPER1_QUERY_KEYWORDS, min(keyword_count, max(8, keyword_count // 20)))
    common_per_doc = min(len(common_range), max(1, int(keywords_per_doc * COMMON_PER_DOC_RATIO)))
    medium_per_doc = min(len(medium_range), max(1, int(keywords_per_doc * MEDIUM_PER_DOC_RATIO)))
    rare_per_doc = min(len(rare_range), max(1, int(keywords_per_doc * RARE_PER_DOC_RATIO)))
    selective_per_doc = max(1, keywords_per_doc - common_per_doc - medium_per_doc - rare_per_doc)

    rng = random.Random(seed_for(1, keyword_count, run_idx))
    cluster_count = max(1, (file_count + SELECTIVE_CLUSTER_SPAN - 1) // SELECTIVE_CLUSTER_SPAN)
    selective_bucket_width = max(1, max(1, selective_count) // cluster_count)
    corpus_indices: list[list[int]] = []
    for doc_idx in range(file_count):
        doc_rng = random.Random(rng.randint(0, 1_000_000_000) ^ doc_idx)
        indices: set[int] = set()
        indices.update(doc_rng.sample(common_range, common_per_doc))
        indices.update(doc_rng.sample(medium_range, medium_per_doc))
        indices.update(doc_rng.sample(rare_range, rare_per_doc))
        cluster_id = doc_idx // SELECTIVE_CLUSTER_SPAN
        selective_begin = common_count + medium_count + rare_count + cluster_id * selective_bucket_width
        selective_end = min(keyword_count, selective_begin + selective_bucket_width)
        selective_bucket = list(range(selective_begin, selective_end)) or selective_range
        if selective_bucket:
            indices.update(doc_rng.sample(selective_bucket, min(selective_per_doc, len(selective_bucket))))
        fallback = medium_range + rare_range + selective_range + common_range
        for index in fallback:
            if len(indices) >= keywords_per_doc:
                break
            indices.add(index)
        corpus_indices.append(sorted(indices))
    return corpus_indices


def vector_from_indices(slot_count: int, indices: list[int], rng: random.Random, min_value: int, max_value: int) -> list[int]:
    vector = [0] * slot_count
    for index in indices:
        vector[index] = rng.randint(min_value, max_value)
    return vector


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def paper1_cache_prefix(keyword_count: int, run_idx: int) -> str:
    return f"paper1_kw_{keyword_count:04d}_run_{run_idx:02d}_files_"


def paper1_cache_path(cache_dir: Path, keyword_count: int, run_idx: int, max_file_count: int) -> Path:
    return cache_dir / f"{paper1_cache_prefix(keyword_count, run_idx)}{max_file_count:05d}.pkl"


def find_cached_paper1_corpus(cache_dir: Path, keyword_count: int, run_idx: int, min_file_count: int) -> Path | None:
    if not cache_dir.exists():
        return None
    prefix = paper1_cache_prefix(keyword_count, run_idx)
    candidates: list[tuple[int, Path]] = []
    for path in cache_dir.glob(f"{prefix}*.pkl"):
        suffix = path.stem.removeprefix(prefix)
        try:
            file_count = int(suffix)
        except ValueError:
            continue
        if file_count >= min_file_count:
            candidates.append((file_count, path))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


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


def paper1_build_corpus(keyword_count: int, file_count: int, run_idx: int) -> tuple[int, list[dict[str, list[int]]], list[list[int]]]:
    degree = choose_poly_degree(keyword_count)
    slots = degree // 2
    corpus: list[dict[str, list[int]]] = []
    rng = random.Random(seed_for(1, keyword_count, run_idx))
    corpus_indices = banded_keyword_indices(min(keyword_count, slots), file_count, run_idx)
    for doc_idx in range(file_count):
        doc_rng = random.Random(rng.randint(0, 1_000_000_000) ^ doc_idx)
        doc_indices = corpus_indices[doc_idx]
        encoded = vector_from_indices(slots, doc_indices, doc_rng, 1, 1)
        noise_a = vector_from_indices(slots, doc_indices, doc_rng, 0, 17)
        noise_b = vector_from_indices(slots, doc_indices, doc_rng, 0, 17)
        secret = vector_from_indices(slots, doc_indices, doc_rng, 1, 31)
        c0 = vec_add(encoded, noise_a)
        c1 = vec_add(vec_mul(encoded, secret), noise_b)
        corpus.append({"c0": c0, "c1": c1, "secret": secret})
    return slots, corpus, corpus_indices


def load_or_generate_paper1_corpus(
    keyword_count: int,
    file_count: int,
    run_idx: int,
    cache_dir: Path,
) -> dict[str, object]:
    ensure_dir(cache_dir)
    cached_path = find_cached_paper1_corpus(cache_dir, keyword_count, run_idx, file_count)
    if cached_path is not None:
        with cached_path.open("rb") as handle:
            cached = pickle.load(handle)
        return {
            "slots": cached["slots"],
            "corpus": cached["corpus"][:file_count],
            "corpus_indices": cached["corpus_indices"][:file_count],
            "query_indices": cached["query_indices"],
            "cached_from": cached_path,
        }

    slots, corpus, corpus_indices = paper1_build_corpus(keyword_count, file_count, run_idx)
    query_rng = random.Random(seed_for(103, keyword_count, run_idx))
    query_indices = sorted(query_rng.sample(corpus_indices[0], min(PAPER1_QUERY_KEYWORDS, len(corpus_indices[0]))))
    payload = {
        "keyword_count": keyword_count,
        "run_idx": run_idx,
        "max_file_count": file_count,
        "slots": slots,
        "corpus": corpus,
        "corpus_indices": corpus_indices,
        "query_indices": query_indices,
    }
    output_path = paper1_cache_path(cache_dir, keyword_count, run_idx, file_count)
    with output_path.open("wb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return {
        "slots": slots,
        "corpus": corpus,
        "corpus_indices": corpus_indices,
        "query_indices": query_indices,
        "cached_from": output_path,
    }


def explicit_indices(keyword_count: int, slots: int) -> list[int]:
    return list(range(min(keyword_count, slots)))


def paper1_build_single_doc(keyword_count: int, run_idx: int) -> tuple[int, dict[str, list[int]], list[int]]:
    degree = choose_poly_degree(keyword_count)
    slots = degree // 2
    rng = random.Random(seed_for(111, keyword_count, run_idx))
    doc_indices = explicit_indices(keyword_count, slots)
    encoded = vector_from_indices(slots, doc_indices, rng, 1, 1)
    noise_a = vector_from_indices(slots, doc_indices, rng, 0, 17)
    noise_b = vector_from_indices(slots, doc_indices, rng, 0, 17)
    secret = vector_from_indices(slots, doc_indices, rng, 1, 31)
    c0 = vec_add(encoded, noise_a)
    c1 = vec_add(vec_mul(encoded, secret), noise_b)
    return slots, {"c0": c0, "c1": c1, "secret": secret}, doc_indices


def paper1_encrypt(keyword_count: int, run_idx: int) -> float:
    degree = choose_poly_degree(keyword_count)
    slots = degree // 2
    rng = random.Random(seed_for(101, keyword_count, run_idx))
    active_count = max(1, min(slots, keyword_count))
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


def paper1_trapdoor(keyword_count: int, run_idx: int, query_indices: list[int] | None = None) -> tuple[float, dict[str, list[int]]]:
    degree = choose_poly_degree(keyword_count)
    slots = degree // 2
    rng = random.Random(seed_for(102, keyword_count, run_idx))
    if query_indices is None:
        query_indices = explicit_indices(keyword_count, slots)
    query = vector_from_indices(slots, query_indices, rng, 1, 1)
    secret = vector_from_indices(slots, query_indices, rng, 1, 31)
    rekey = vector_from_indices(slots, query_indices, rng, 1, 17)
    noise = vector_from_indices(slots, query_indices, rng, 0, 11)

    start = time.perf_counter()
    beta0 = vec_add(query, noise)
    beta1 = vec_add(vec_mul(query, secret), scalar_mix(rekey, 3))
    beta2 = vec_add(beta0, scalar_mix(rekey, 5))
    beta3 = vec_add(beta1, rotate(beta0, 3))
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, {"beta0": beta0, "beta1": beta1, "beta2": beta2, "beta3": beta3}


def paper1_search_candidate_from_corpus(
    keyword_count: int,
    run_idx: int,
    slots: int,
    corpus: list[dict[str, list[int]]],
    query_indices: list[int],
) -> tuple[float, dict[str, list[int]], list[dict[str, object]]]:
    _, trapdoor = paper1_trapdoor(keyword_count, run_idx, query_indices)
    _ = slots

    start = time.perf_counter()
    ranked: list[tuple[int, int]] = []
    for doc_idx, doc in enumerate(corpus):
        score = dot_score(doc["c0"], trapdoor["beta0"])
        ranked.append((score, doc_idx))
    candidate_limit = min(len(ranked), max(PAPER1_TOP_K, PAPER1_TOP_K * 4))
    candidate_rows = heapq.nlargest(candidate_limit, ranked, key=lambda item: item[0])
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, trapdoor, [
        {"candidate_score": score, "doc_idx": doc_idx}
        for score, doc_idx in candidate_rows
    ]


def paper1_exact_match_from_candidates(
    corpus: list[dict[str, list[int]]],
    trapdoor: dict[str, list[int]],
    candidate_results: list[dict[str, object]],
) -> tuple[float, list[dict[str, object]]]:
    start = time.perf_counter()
    ranked: list[tuple[int, int, list[int]]] = []
    for candidate in candidate_results:
        doc_idx = int(candidate["doc_idx"])
        doc = corpus[doc_idx]
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


def paper1_search(
    keyword_count: int,
    file_count: int,
    run_idx: int,
    cache_dir: Path,
) -> tuple[float, float, list[dict[str, object]]]:
    cached = load_or_generate_paper1_corpus(keyword_count, file_count, run_idx, cache_dir)
    candidate_ms, trapdoor, candidate_results = paper1_search_candidate_from_corpus(
        keyword_count,
        run_idx,
        int(cached["slots"]),
        cached["corpus"],
        cached["query_indices"],
    )
    exact_ms, top_results = paper1_exact_match_from_candidates(cached["corpus"], trapdoor, candidate_results)
    return candidate_ms, exact_ms, top_results


def paper1_decrypt_from_corpus(
    keyword_count: int,
    run_idx: int,
    query_indices: list[int],
    top_results: list[dict[str, object]],
) -> float:
    _, trapdoor = paper1_trapdoor(keyword_count, run_idx, query_indices)
    proxy_key = rotate(trapdoor["beta3"], 5)

    start = time.perf_counter()
    outputs = []
    for result in top_results:
        phase1 = vec_sub(result["merged"], trapdoor["beta2"])
        phase2 = vec_add(phase1, proxy_key)
        outputs.append(dot_score(phase2, trapdoor["beta0"]))
    _ = sum(outputs) % MODULUS
    return (time.perf_counter() - start) * 1000.0


def paper1_decrypt(
    keyword_count: int,
    file_count: int,
    run_idx: int,
    cache_dir: Path,
) -> float:
    _ = file_count
    _ = cache_dir
    slots, doc, doc_indices = paper1_build_single_doc(keyword_count, run_idx)
    query_indices = doc_indices[: min(PAPER1_QUERY_KEYWORDS, len(doc_indices))]
    _, trapdoor, candidate_results = paper1_search_candidate_from_corpus(
        keyword_count,
        run_idx,
        slots,
        [doc],
        query_indices,
    )
    _, top_results = paper1_exact_match_from_candidates([doc], trapdoor, candidate_results)
    return paper1_decrypt_from_corpus(keyword_count, run_idx, query_indices, top_results)


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


def paper8_explicit_indices(keyword_count: int) -> list[int]:
    return list(range(max(1, keyword_count)))


def paper8_encrypt(keyword_count: int, run_idx: int) -> float:
    slot_count = max(PAPER8_MATRIX_DIM, keyword_count + PAPER8_TAG_WIDTH)
    rng = random.Random(seed_for(801, keyword_count, run_idx))
    keyword_indices = [index % slot_count for index in paper8_explicit_indices(keyword_count)]
    tag_indices = [((keyword_count * 7) + offset) % slot_count for offset in range(PAPER8_TAG_WIDTH)]
    keyword_vec = vector_from_indices(slot_count, keyword_indices, rng, 1, 3)
    tag_vec = vector_from_indices(slot_count, tag_indices, rng, 1, 5)
    public_base = make_sparse_vector(slot_count, min(slot_count, keyword_count + PAPER8_TAG_WIDTH), rng, 1, 31)
    noise = make_sparse_vector(slot_count, min(slot_count, keyword_count + PAPER8_TAG_WIDTH), rng, 0, 11)

    start = time.perf_counter()
    c0 = vec_add(vec_mul(keyword_vec, public_base), noise)
    c1 = vec_add(vec_mul(tag_vec, rotate(public_base, 3)), scalar_mix(keyword_vec, 5))
    mix = vec_add(c0, rotate(c1, 7))
    for round_idx in range(4):
        mix = vec_add(mix, scalar_mix(rotate(tag_vec, round_idx + 1), round_idx + 2))
    _ = dot_score(mix, public_base)
    return (time.perf_counter() - start) * 1000.0


def paper8_trapdoor(keyword_count: int, run_idx: int, query_indices: list[int] | None = None) -> tuple[float, dict[str, list[int]]]:
    slot_count = max(PAPER8_MATRIX_DIM, keyword_count + PAPER8_TAG_WIDTH)
    rng = random.Random(seed_for(802, keyword_count, run_idx))
    if query_indices is None:
        query_indices = [index % slot_count for index in paper8_explicit_indices(keyword_count)]
    puncture_indices = [((keyword_count * 11) + offset) % slot_count for offset in range(PAPER8_TAG_WIDTH)]
    query_vec = vector_from_indices(slot_count, query_indices, rng, 1, 3)
    puncture_vec = vector_from_indices(slot_count, puncture_indices, rng, 1, 7)
    lattice_basis = make_sparse_vector(slot_count, min(slot_count, keyword_count + PAPER8_TAG_WIDTH), rng, 1, 29)

    start = time.perf_counter()
    beta0 = vec_add(query_vec, scalar_mix(puncture_vec, 3))
    beta1 = vec_add(vec_mul(beta0, lattice_basis), rotate(puncture_vec, 5))
    beta2 = vec_add(beta1, scalar_mix(query_vec, 7))
    permit = vec_add(beta2, rotate(beta0, 9))
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, {"beta0": beta0, "beta1": beta1, "beta2": beta2, "permit": permit}


def paper8_build_corpus(keyword_count: int, file_count: int, run_idx: int) -> tuple[int, list[dict[str, object]], list[list[int]]]:
    slot_count = max(PAPER8_MATRIX_DIM, keyword_count + PAPER8_TAG_WIDTH)
    rng = random.Random(seed_for(803, keyword_count, run_idx))
    corpus_indices = banded_keyword_indices(keyword_count, file_count, run_idx)
    corpus: list[dict[str, object]] = []
    for doc_idx in range(file_count):
        doc_rng = random.Random(rng.randint(0, 1_000_000_000) ^ (doc_idx * 19 + 5))
        keyword_indices = [index % slot_count for index in corpus_indices[doc_idx]]
        tag_indices = [((doc_idx * 13) + offset) % slot_count for offset in range(PAPER8_TAG_WIDTH)]
        keyword_vec = vector_from_indices(slot_count, keyword_indices, doc_rng, 1, 3)
        tag_vec = vector_from_indices(slot_count, tag_indices, doc_rng, 1, 5)
        base = make_sparse_vector(slot_count, min(slot_count, len(keyword_indices) + PAPER8_TAG_WIDTH), doc_rng, 1, 31)
        c0 = vec_add(vec_mul(keyword_vec, base), tag_vec)
        c1 = vec_add(vec_mul(tag_vec, rotate(base, 3)), scalar_mix(keyword_vec, 5))
        corpus.append({"c0": c0, "c1": c1, "tags": tag_indices, "keywords": keyword_indices})
    return slot_count, corpus, corpus_indices


def paper8_search_candidate_from_corpus(
    keyword_count: int,
    file_count: int,
    run_idx: int,
) -> tuple[float, dict[str, list[int]], list[dict[str, int]], list[dict[str, object]], list[int]]:
    slot_count, corpus, corpus_indices = paper8_build_corpus(keyword_count, file_count, run_idx)
    query_indices = corpus_indices[0][: min(PAPER1_QUERY_KEYWORDS, len(corpus_indices[0]))]
    _, trapdoor = paper8_trapdoor(keyword_count, run_idx, [index % slot_count for index in query_indices])

    start = time.perf_counter()
    ranked: list[tuple[int, int]] = []
    for doc_idx, doc in enumerate(corpus):
        score = dot_score(doc["c0"], trapdoor["beta0"])
        ranked.append((score, doc_idx))
    candidate_limit = min(len(ranked), max(PAPER1_TOP_K, PAPER1_TOP_K * PAPER8_CANDIDATE_FACTOR))
    candidate_rows = heapq.nlargest(candidate_limit, ranked, key=lambda item: item[0])
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, trapdoor, [{"candidate_score": score, "doc_idx": doc_idx} for score, doc_idx in candidate_rows], corpus, query_indices


def paper8_exact_match_from_candidates(
    trapdoor: dict[str, list[int]],
    candidates: list[dict[str, int]],
    corpus: list[dict[str, object]],
) -> tuple[float, list[dict[str, object]]]:
    start = time.perf_counter()
    ranked: list[tuple[int, int, list[int]]] = []
    punctured_tag_set = {index for index, value in enumerate(trapdoor["permit"]) if value % 3 == 0}
    for candidate in candidates:
        doc_idx = int(candidate["doc_idx"])
        doc = corpus[doc_idx]
        if punctured_tag_set.intersection(set(doc["tags"])):
            continue
        merged = vec_add(vec_mul(doc["c0"], trapdoor["beta1"]), vec_mul(doc["c1"], trapdoor["beta2"]))
        score = dot_score(merged, trapdoor["permit"])
        ranked.append((score, doc_idx, merged))
    top_results = heapq.nlargest(PAPER1_TOP_K, ranked, key=lambda item: item[0])
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, [{"score": score, "doc_idx": doc_idx, "merged": merged} for score, doc_idx, merged in top_results]


def paper8_puncture(active_user_count: int, run_idx: int) -> float:
    rng = random.Random(seed_for(804, active_user_count, run_idx))
    basis_pool = [
        make_sparse_vector(PAPER8_MATRIX_DIM, PAPER8_MATRIX_DIM // 4, random.Random(rng.randint(0, 1_000_000_000) ^ user_idx), 1, 41)
        for user_idx in range(active_user_count)
    ]
    update_tag = make_sparse_vector(PAPER8_MATRIX_DIM, PAPER8_TAG_WIDTH, rng, 1, 17)

    start = time.perf_counter()
    accumulator = update_tag
    for round_idx in range(PAPER8_PUNCTURE_ROUNDS):
        basis = basis_pool[round_idx % max(1, len(basis_pool))]
        accumulator = vec_add(accumulator, vec_mul(basis, rotate(update_tag, (round_idx % 7) + 1)))
        accumulator = vec_add(accumulator, scalar_mix(rotate(basis, (round_idx % 11) + 1), round_idx + 2))
    _ = dot_score(accumulator, update_tag)
    return (time.perf_counter() - start) * 1000.0


def paper9_encrypt(keyword_count: int, run_idx: int) -> float:
    slot_count = max(PAPER9_VECTOR_DIM, keyword_count + PAPER9_TEST_STRING_LEN)
    rng = random.Random(seed_for(901, keyword_count, run_idx))
    keyword_indices = [index % slot_count for index in paper8_explicit_indices(keyword_count)]
    payload = vector_from_indices(slot_count, keyword_indices, rng, 1, 3)
    fixed_bits = [1] * PAPER9_TEST_STRING_LEN
    masks = [make_sparse_vector(slot_count, min(slot_count, keyword_count), random.Random(rng.randint(0, 1_000_000_000) ^ bit_idx), 1, 23)
             for bit_idx in range(PAPER9_TEST_STRING_LEN)]

    start = time.perf_counter()
    accum = payload
    for bit_idx, mask in enumerate(masks):
        bit_scalar = 2 if fixed_bits[bit_idx] else 1
        accum = vec_add(vec_mul(accum, rotate(mask, (bit_idx % 7) + 1)), scalar_mix(mask, bit_scalar))
    _ = dot_score(accum, payload)
    return (time.perf_counter() - start) * 1000.0


def paper9_trapdoor(keyword_count: int, run_idx: int, query_indices: list[int] | None = None) -> tuple[float, dict[str, list[int]]]:
    slot_count = max(PAPER9_VECTOR_DIM, keyword_count + PAPER9_TEST_STRING_LEN)
    rng = random.Random(seed_for(902, keyword_count, run_idx))
    if query_indices is None:
        query_indices = [index % slot_count for index in paper8_explicit_indices(keyword_count)]
    query = vector_from_indices(slot_count, query_indices, rng, 1, 3)
    basis = make_sparse_vector(slot_count, min(slot_count, keyword_count), rng, 1, 29)
    deltas = [make_sparse_vector(slot_count, max(8, min(slot_count, keyword_count // 4 + 1)), random.Random(rng.randint(0, 1_000_000_000) ^ idx), 0, 13)
              for idx in range(PAPER9_TEST_STRING_LEN)]

    start = time.perf_counter()
    beta0 = vec_add(query, basis)
    beta1 = vec_mul(beta0, rotate(basis, 3))
    for idx, delta in enumerate(deltas):
        beta1 = vec_add(beta1, rotate(delta, (idx % 5) + 1))
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, {"beta0": beta0, "beta1": beta1}


def paper9_build_corpus(keyword_count: int, file_count: int, run_idx: int) -> tuple[int, list[dict[str, object]], list[list[int]]]:
    slot_count = max(PAPER9_VECTOR_DIM, keyword_count + PAPER9_TEST_STRING_LEN)
    rng = random.Random(seed_for(903, keyword_count, run_idx))
    corpus_indices = banded_keyword_indices(keyword_count, file_count, run_idx)
    corpus: list[dict[str, object]] = []
    for doc_idx in range(file_count):
        doc_rng = random.Random(rng.randint(0, 1_000_000_000) ^ (doc_idx * 23 + 9))
        keyword_indices = [index % slot_count for index in corpus_indices[doc_idx]]
        payload = vector_from_indices(slot_count, keyword_indices, doc_rng, 1, 3)
        masks = [make_sparse_vector(slot_count, min(slot_count, len(keyword_indices) + 1), random.Random(doc_rng.randint(0, 1_000_000_000) ^ idx), 1, 19)
                 for idx in range(PAPER9_TEST_STRING_LEN)]
        corpus.append({"payload": payload, "masks": masks})
    return slot_count, corpus, corpus_indices


def paper9_search_candidate_from_corpus(
    keyword_count: int,
    file_count: int,
    run_idx: int,
) -> tuple[float, dict[str, list[int]], list[dict[str, int]], list[dict[str, object]], list[int]]:
    slot_count, corpus, corpus_indices = paper9_build_corpus(keyword_count, file_count, run_idx)
    query_indices = corpus_indices[0][: min(PAPER1_QUERY_KEYWORDS, len(corpus_indices[0]))]
    _, trapdoor = paper9_trapdoor(keyword_count, run_idx, [index % slot_count for index in query_indices])

    start = time.perf_counter()
    ranked: list[tuple[int, int]] = []
    for doc_idx, doc in enumerate(corpus):
        score = dot_score(doc["payload"], trapdoor["beta0"])
        ranked.append((score, doc_idx))
    candidate_limit = min(len(ranked), max(PAPER1_TOP_K, PAPER1_TOP_K * PAPER9_CANDIDATE_FACTOR))
    candidate_rows = heapq.nlargest(candidate_limit, ranked, key=lambda item: item[0])
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, trapdoor, [{"candidate_score": score, "doc_idx": doc_idx} for score, doc_idx in candidate_rows], corpus, query_indices


def paper9_exact_match_from_candidates(
    trapdoor: dict[str, list[int]],
    candidates: list[dict[str, int]],
    corpus: list[dict[str, object]],
) -> tuple[float, list[dict[str, object]]]:
    start = time.perf_counter()
    ranked: list[tuple[int, int, list[int]]] = []
    for candidate in candidates:
        doc_idx = int(candidate["doc_idx"])
        doc = corpus[doc_idx]
        accum = doc["payload"]
        recovered_bits = 0
        for bit_idx, mask in enumerate(doc["masks"]):
            probe = dot_score(vec_mul(accum, mask), trapdoor["beta1"])
            if probe % 5 == 0:
                break
            recovered_bits += 1
            accum = vec_add(accum, rotate(mask, (bit_idx % 7) + 1))
        score = recovered_bits * 1000 + dot_score(accum, trapdoor["beta0"])
        ranked.append((score, doc_idx, accum))
    top_results = heapq.nlargest(PAPER1_TOP_K, ranked, key=lambda item: item[0])
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, [{"score": score, "doc_idx": doc_idx, "merged": merged} for score, doc_idx, merged in top_results]


def run_paper1_keyword_scaling(
    runs: int,
    keyword_counts: list[int],
    search_file_count: int,
    output_dir: Path,
    cache_dir: Path,
):
    print_phase("Starting Reference Paper 1 benchmark")
    encryption_rows = []
    trapdoor_rows = []
    search_candidate_rows = []
    search_exact_rows = []
    decrypt_rows = []

    for keyword_count in keyword_counts:
        encryption_values = []
        trapdoor_values = []
        search_candidate_values = []
        search_exact_values = []
        decrypt_values = []
        for run_idx in range(runs):
            print_progress("paper1", run_idx + 1, runs, f"keyword_count={keyword_count}")
            encryption_values.append(paper1_encrypt(keyword_count, run_idx))
            cached = load_or_generate_paper1_corpus(keyword_count, search_file_count, run_idx, cache_dir)
            trapdoor_ms, _ = paper1_trapdoor(keyword_count, run_idx, cached["query_indices"])
            trapdoor_values.append(trapdoor_ms)
            candidate_ms, exact_ms, top_results = paper1_search(
                keyword_count,
                search_file_count,
                run_idx,
                cache_dir,
            )
            search_candidate_values.append(candidate_ms)
            search_exact_values.append(exact_ms)
            decrypt_values.append(
                paper1_decrypt_from_corpus(keyword_count, run_idx, cached["query_indices"], top_results)
            )

        encryption_avg = average_ms(encryption_values)
        trapdoor_avg = average_ms(trapdoor_values)
        search_candidate_avg = average_ms(search_candidate_values)
        search_exact_avg = average_ms(search_exact_values)
        decrypt_avg = average_ms(decrypt_values)

        print(f"paper1_encryption: keyword_count={keyword_count} runs={runs} avg_ms={encryption_avg:.3f}")
        print(f"paper1_trapdoor: keyword_count={keyword_count} runs={runs} avg_ms={trapdoor_avg:.3f}")
        print(f"paper1_search_candidate: keyword_count={keyword_count} runs={runs} avg_ms={search_candidate_avg:.3f}")
        print(f"paper1_exact_match: keyword_count={keyword_count} runs={runs} avg_ms={search_exact_avg:.3f}")
        print(f"paper1_decryption: keyword_count={keyword_count} runs={runs} avg_ms={decrypt_avg:.3f}")

        encryption_rows.append(
            {"experiment": "paper1_encryption", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{encryption_avg:.3f}"}
        )
        trapdoor_rows.append(
            {"experiment": "paper1_trapdoor", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{trapdoor_avg:.3f}"}
        )
        search_candidate_rows.append(
            {
                "experiment": "paper1_search_candidate",
                "keyword_count": keyword_count,
                "file_count": search_file_count,
                "runs": runs,
                "avg_ms": f"{search_candidate_avg:.3f}",
            }
        )
        search_exact_rows.append(
            {
                "experiment": "paper1_exact_match",
                "keyword_count": keyword_count,
                "file_count": search_file_count,
                "runs": runs,
                "avg_ms": f"{search_exact_avg:.3f}",
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
    write_csv(output_dir / "paper1_search_candidate_results.csv", search_candidate_rows)
    write_csv(output_dir / "paper1_exact_match_results.csv", search_exact_rows)
    write_csv(output_dir / "paper1_decryption_results.csv", decrypt_rows)


def run_paper1_file_scaling(
    runs: int,
    file_counts: list[int],
    keyword_count: int,
    output_dir: Path,
    cache_dir: Path,
):
    print_phase("Starting Reference Paper 1 file-scaling benchmark")
    search_candidate_rows = []
    search_exact_rows = []
    decrypt_rows = []

    for file_count in file_counts:
        search_candidate_values = []
        search_exact_values = []
        decrypt_values = []
        for run_idx in range(runs):
            print_progress("paper1_file_scaling", run_idx + 1, runs, f"keyword_count={keyword_count}, file_count={file_count}")
            cached = load_or_generate_paper1_corpus(keyword_count, file_count, run_idx, cache_dir)
            candidate_ms, trapdoor, candidate_results = paper1_search_candidate_from_corpus(
                keyword_count,
                run_idx,
                int(cached["slots"]),
                cached["corpus"],
                cached["query_indices"],
            )
            exact_ms, top_results = paper1_exact_match_from_candidates(cached["corpus"], trapdoor, candidate_results)
            search_candidate_values.append(candidate_ms)
            search_exact_values.append(exact_ms)
            decrypt_values.append(
                paper1_decrypt_from_corpus(keyword_count, run_idx, cached["query_indices"], top_results)
            )

        search_candidate_avg = average_ms(search_candidate_values)
        search_exact_avg = average_ms(search_exact_values)
        decrypt_avg = average_ms(decrypt_values)
        print(f"paper1_file_scaling_search_candidate: keyword_count={keyword_count} file_count={file_count} runs={runs} avg_ms={search_candidate_avg:.3f}")
        print(f"paper1_file_scaling_exact_match: keyword_count={keyword_count} file_count={file_count} runs={runs} avg_ms={search_exact_avg:.3f}")
        print(f"paper1_file_scaling_decryption: keyword_count={keyword_count} file_count={file_count} runs={runs} avg_ms={decrypt_avg:.3f}")

        search_candidate_rows.append(
            {
                "experiment": "paper1_file_scaling_search_candidate",
                "keyword_count": keyword_count,
                "file_count": file_count,
                "runs": runs,
                "avg_ms": f"{search_candidate_avg:.3f}",
            }
        )
        search_exact_rows.append(
            {
                "experiment": "paper1_file_scaling_exact_match",
                "keyword_count": keyword_count,
                "file_count": file_count,
                "runs": runs,
                "avg_ms": f"{search_exact_avg:.3f}",
            }
        )
        decrypt_rows.append(
            {
                "experiment": "paper1_file_scaling_decryption",
                "keyword_count": keyword_count,
                "file_count": file_count,
                "runs": runs,
                "avg_ms": f"{decrypt_avg:.3f}",
            }
        )

    write_csv(output_dir / "paper1_file_scaling_search_candidate_results.csv", search_candidate_rows)
    write_csv(output_dir / "paper1_file_scaling_exact_match_results.csv", search_exact_rows)
    write_csv(output_dir / "paper1_file_scaling_decryption_results.csv", decrypt_rows)


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


def run_paper8(runs: int, search_file_count: int, output_dir: Path):
    print_phase("Starting Reference Paper 8 benchmark")
    encryption_rows = []
    trapdoor_rows = []
    search_candidate_rows = []
    exact_match_rows = []
    revocation_rows = []

    for keyword_count in KEYWORD_COUNTS:
        encryption_values = []
        trapdoor_values = []
        search_candidate_values = []
        exact_match_values = []
        for run_idx in range(runs):
            print_progress("paper8_encryption", run_idx + 1, runs, f"keyword_count={keyword_count}")
            encryption_values.append(paper8_encrypt(keyword_count, run_idx))
            print_progress("paper8_trapdoor", run_idx + 1, runs, f"keyword_count={keyword_count}")
            trapdoor_ms, _ = paper8_trapdoor(keyword_count, run_idx)
            trapdoor_values.append(trapdoor_ms)
            print_progress("paper8_search", run_idx + 1, runs, f"keyword_count={keyword_count}")
            candidate_ms, trapdoor, candidates, corpus, _query_indices = paper8_search_candidate_from_corpus(
                keyword_count,
                search_file_count,
                run_idx,
            )
            exact_ms, _results = paper8_exact_match_from_candidates(trapdoor, candidates, corpus)
            search_candidate_values.append(candidate_ms)
            exact_match_values.append(exact_ms)

        encryption_avg = average_ms(encryption_values)
        trapdoor_avg = average_ms(trapdoor_values)
        search_candidate_avg = average_ms(search_candidate_values)
        exact_match_avg = average_ms(exact_match_values)
        print(f"paper8_encryption: keyword_count={keyword_count} runs={runs} avg_ms={encryption_avg:.3f}")
        print(f"paper8_trapdoor: keyword_count={keyword_count} runs={runs} avg_ms={trapdoor_avg:.3f}")
        print(f"paper8_search_candidate: keyword_count={keyword_count} runs={runs} avg_ms={search_candidate_avg:.3f}")
        print(f"paper8_exact_match: keyword_count={keyword_count} runs={runs} avg_ms={exact_match_avg:.3f}")

        encryption_rows.append({"experiment": "paper8_encryption", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{encryption_avg:.3f}"})
        trapdoor_rows.append({"experiment": "paper8_trapdoor", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{trapdoor_avg:.3f}"})
        search_candidate_rows.append(
            {
                "experiment": "paper8_search_candidate",
                "keyword_count": keyword_count,
                "file_count": search_file_count,
                "runs": runs,
                "avg_ms": f"{search_candidate_avg:.3f}",
            }
        )
        exact_match_rows.append(
            {
                "experiment": "paper8_exact_match",
                "keyword_count": keyword_count,
                "file_count": search_file_count,
                "runs": runs,
                "avg_ms": f"{exact_match_avg:.3f}",
            }
        )

    for user_count in REVOCATION_USER_COUNTS:
        values = []
        for run_idx in range(runs):
            print_progress("paper8_revocation", run_idx + 1, runs, f"active_user_count={user_count}")
            values.append(paper8_puncture(user_count, run_idx))
        avg = average_ms(values)
        print(f"paper8_revocation: active_user_count={user_count} runs={runs} avg_ms={avg:.3f}")
        revocation_rows.append(
            {"experiment": "paper8_revocation", "active_user_count": user_count, "runs": runs, "avg_ms": f"{avg:.3f}"}
        )

    write_csv(output_dir / "paper8_encryption_results.csv", encryption_rows)
    write_csv(output_dir / "paper8_trapdoor_results.csv", trapdoor_rows)
    write_csv(output_dir / "paper8_search_candidate_results.csv", search_candidate_rows)
    write_csv(output_dir / "paper8_exact_match_results.csv", exact_match_rows)
    write_csv(output_dir / "paper8_revocation_results.csv", revocation_rows)


def run_paper8_file_scaling(runs: int, file_counts: list[int], keyword_count: int, output_dir: Path):
    print_phase("Starting Reference Paper 8 file-scaling benchmark")
    search_candidate_rows = []
    exact_match_rows = []

    for file_count in file_counts:
        search_candidate_values = []
        exact_match_values = []
        for run_idx in range(runs):
            print_progress("paper8_file_scaling", run_idx + 1, runs, f"keyword_count={keyword_count}, file_count={file_count}")
            candidate_ms, trapdoor, candidates, corpus, _query_indices = paper8_search_candidate_from_corpus(
                keyword_count,
                file_count,
                run_idx,
            )
            exact_ms, _results = paper8_exact_match_from_candidates(trapdoor, candidates, corpus)
            search_candidate_values.append(candidate_ms)
            exact_match_values.append(exact_ms)

        search_candidate_avg = average_ms(search_candidate_values)
        exact_match_avg = average_ms(exact_match_values)
        print(f"paper8_file_scaling_search_candidate: keyword_count={keyword_count} file_count={file_count} runs={runs} avg_ms={search_candidate_avg:.3f}")
        print(f"paper8_file_scaling_exact_match: keyword_count={keyword_count} file_count={file_count} runs={runs} avg_ms={exact_match_avg:.3f}")
        search_candidate_rows.append(
            {
                "experiment": "paper8_file_scaling_search_candidate",
                "keyword_count": keyword_count,
                "file_count": file_count,
                "runs": runs,
                "avg_ms": f"{search_candidate_avg:.3f}",
            }
        )
        exact_match_rows.append(
            {
                "experiment": "paper8_file_scaling_exact_match",
                "keyword_count": keyword_count,
                "file_count": file_count,
                "runs": runs,
                "avg_ms": f"{exact_match_avg:.3f}",
            }
        )

    write_csv(output_dir / "paper8_file_scaling_search_candidate_results.csv", search_candidate_rows)
    write_csv(output_dir / "paper8_file_scaling_exact_match_results.csv", exact_match_rows)


def run_paper9(runs: int, search_file_count: int, output_dir: Path):
    print_phase("Starting Reference Paper 9 benchmark")
    encryption_rows = []
    trapdoor_rows = []
    search_candidate_rows = []
    exact_match_rows = []

    for keyword_count in KEYWORD_COUNTS:
        encryption_values = []
        trapdoor_values = []
        search_candidate_values = []
        exact_match_values = []
        for run_idx in range(runs):
            print_progress("paper9_encryption", run_idx + 1, runs, f"keyword_count={keyword_count}")
            encryption_values.append(paper9_encrypt(keyword_count, run_idx))
            print_progress("paper9_trapdoor", run_idx + 1, runs, f"keyword_count={keyword_count}")
            trapdoor_ms, _ = paper9_trapdoor(keyword_count, run_idx)
            trapdoor_values.append(trapdoor_ms)
            print_progress("paper9_search", run_idx + 1, runs, f"keyword_count={keyword_count}")
            candidate_ms, trapdoor, candidates, corpus, _query_indices = paper9_search_candidate_from_corpus(
                keyword_count,
                search_file_count,
                run_idx,
            )
            exact_ms, _results = paper9_exact_match_from_candidates(trapdoor, candidates, corpus)
            search_candidate_values.append(candidate_ms)
            exact_match_values.append(exact_ms)

        encryption_avg = average_ms(encryption_values)
        trapdoor_avg = average_ms(trapdoor_values)
        search_candidate_avg = average_ms(search_candidate_values)
        exact_match_avg = average_ms(exact_match_values)
        print(f"paper9_encryption: keyword_count={keyword_count} runs={runs} avg_ms={encryption_avg:.3f}")
        print(f"paper9_trapdoor: keyword_count={keyword_count} runs={runs} avg_ms={trapdoor_avg:.3f}")
        print(f"paper9_search_candidate: keyword_count={keyword_count} runs={runs} avg_ms={search_candidate_avg:.3f}")
        print(f"paper9_exact_match: keyword_count={keyword_count} runs={runs} avg_ms={exact_match_avg:.3f}")

        encryption_rows.append({"experiment": "paper9_encryption", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{encryption_avg:.3f}"})
        trapdoor_rows.append({"experiment": "paper9_trapdoor", "keyword_count": keyword_count, "runs": runs, "avg_ms": f"{trapdoor_avg:.3f}"})
        search_candidate_rows.append(
            {
                "experiment": "paper9_search_candidate",
                "keyword_count": keyword_count,
                "file_count": search_file_count,
                "runs": runs,
                "avg_ms": f"{search_candidate_avg:.3f}",
            }
        )
        exact_match_rows.append(
            {
                "experiment": "paper9_exact_match",
                "keyword_count": keyword_count,
                "file_count": search_file_count,
                "runs": runs,
                "avg_ms": f"{exact_match_avg:.3f}",
            }
        )

    write_csv(output_dir / "paper9_encryption_results.csv", encryption_rows)
    write_csv(output_dir / "paper9_trapdoor_results.csv", trapdoor_rows)
    write_csv(output_dir / "paper9_search_candidate_results.csv", search_candidate_rows)
    write_csv(output_dir / "paper9_exact_match_results.csv", exact_match_rows)


def run_paper9_file_scaling(runs: int, file_counts: list[int], keyword_count: int, output_dir: Path):
    print_phase("Starting Reference Paper 9 file-scaling benchmark")
    search_candidate_rows = []
    exact_match_rows = []

    for file_count in file_counts:
        search_candidate_values = []
        exact_match_values = []
        for run_idx in range(runs):
            print_progress("paper9_file_scaling", run_idx + 1, runs, f"keyword_count={keyword_count}, file_count={file_count}")
            candidate_ms, trapdoor, candidates, corpus, _query_indices = paper9_search_candidate_from_corpus(
                keyword_count,
                file_count,
                run_idx,
            )
            exact_ms, _results = paper9_exact_match_from_candidates(trapdoor, candidates, corpus)
            search_candidate_values.append(candidate_ms)
            exact_match_values.append(exact_ms)

        search_candidate_avg = average_ms(search_candidate_values)
        exact_match_avg = average_ms(exact_match_values)
        print(f"paper9_file_scaling_search_candidate: keyword_count={keyword_count} file_count={file_count} runs={runs} avg_ms={search_candidate_avg:.3f}")
        print(f"paper9_file_scaling_exact_match: keyword_count={keyword_count} file_count={file_count} runs={runs} avg_ms={exact_match_avg:.3f}")
        search_candidate_rows.append(
            {
                "experiment": "paper9_file_scaling_search_candidate",
                "keyword_count": keyword_count,
                "file_count": file_count,
                "runs": runs,
                "avg_ms": f"{search_candidate_avg:.3f}",
            }
        )
        exact_match_rows.append(
            {
                "experiment": "paper9_file_scaling_exact_match",
                "keyword_count": keyword_count,
                "file_count": file_count,
                "runs": runs,
                "avg_ms": f"{exact_match_avg:.3f}",
            }
        )

    write_csv(output_dir / "paper9_file_scaling_search_candidate_results.csv", search_candidate_rows)
    write_csv(output_dir / "paper9_file_scaling_exact_match_results.csv", exact_match_rows)


def main():
    args = build_parser().parse_args()
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    ensure_dir(args.corpus_cache_dir)
    paper1_keyword_counts = parse_int_list(args.paper1_keyword_counts) or KEYWORD_COUNTS
    paper1_file_counts = parse_int_list(args.paper1_file_counts) or FILE_COUNTS

    if args.paper in {"all", "paper1"}:
        run_paper1_keyword_scaling(
            args.runs,
            paper1_keyword_counts,
            args.search_file_count,
            output_dir,
            args.corpus_cache_dir,
        )
        run_paper1_file_scaling(
            args.runs,
            paper1_file_counts,
            paper1_keyword_counts[-1],
            output_dir,
            args.corpus_cache_dir,
        )
    if args.paper in {"all", "paper4"}:
        run_paper4(args.runs, output_dir)
    if args.paper in {"all", "paper5"}:
        run_paper5(args.runs, output_dir)
    if args.paper in {"all", "paper6"}:
        run_paper6(args.runs, args.search_file_count, output_dir)
    if args.paper in {"all", "paper8"}:
        run_paper8(args.runs, args.search_file_count, output_dir)
        run_paper8_file_scaling(args.runs, paper1_file_counts, paper1_keyword_counts[-1], output_dir)
    if args.paper in {"all", "paper9"}:
        run_paper9(args.runs, args.search_file_count, output_dir)
        run_paper9_file_scaling(args.runs, paper1_file_counts, paper1_keyword_counts[-1], output_dir)

    print(f"Reference paper benchmark outputs written under {output_dir}")


if __name__ == "__main__":
    main()
