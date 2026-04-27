# Benchmark Runner

This folder contains the experiment harness for the six benchmark families:

1. ciphertext bundle creation time on Edge
2. mobile data user decrypt time
3. TA key generation time
4. CS search time
5. trapdoor generation time
6. update-token generation/write time after revocation

The runner appends results into the same CSV files every time you execute it.

## Files

- [run_all_experiments.py](/home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py)
- [benchmark_results.csv](/home/daydream/PQABSE-SRM-httpnitro/benchmarks/results/benchmark_results.csv)
- [benchmark_runs.csv](/home/daydream/PQABSE-SRM-httpnitro/benchmarks/results/benchmark_runs.csv)

## Rebuild First

Rebuild the role binaries before running the experiments, especially TA because trapdoor timing support was added there.

### TA

```bash
cd /home/daydream/PQABSE-SRM-httpnitro/RunFullSys/TA+IA+Blockchain/app/build-wsl
cmake ..
cmake --build . -j2
```

### Edge

```bash
cd "/home/daydream/PQABSE-SRM-httpnitro/RunFullSys/Edge node/app/build-wsl"
cmake ..
cmake --build . -j2
```

### CS

```bash
cd /home/daydream/PQABSE-SRM-httpnitro/RunFullSys/CS/app/build-wsl
cmake ..
cmake --build . -j2
```

### MDU

```bash
cd /home/daydream/PQABSE-SRM-httpnitro/RunFullSys/MDU/app/build-wsl
cmake ..
cmake --build . -j2
```

## What The Runner Measures

### Keyword-scaled benchmarks

These run at keyword counts:

- `20`
- `300`
- `500`
- `1000`

Measured metrics:

- `encrypt_bundle_ms`
- `retrieve_decrypt_ms`
- `candidate_generation_ms`
- `trapdoor_gen_ms`

### Attribute-scaled benchmark

These run at attribute counts:

- `10`
- `20`
- `30`
- `40`
- `50`

Measured metric:

- `keygen_ms`

### User-count-scaled benchmark

These run at active user counts:

- `10`
- `20`
- `30`
- `40`
- `50`

Measured metric:

- `update_token_write_ms`

## Run Everything

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py
```

## Run Only One Family

### Keyword benchmarks

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py --suite keyword
```

### Key generation benchmark

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py --suite keygen
```

### Revocation benchmark

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py --suite revoke
```

## Change Repeat Count

Default is `5` runs per parameter value.

Example with `3` repeats:

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py --repeats 3
```

## Output Format

### Averaged CSV

[benchmark_results.csv](/home/daydream/PQABSE-SRM-httpnitro/benchmarks/results/benchmark_results.csv)

Each row contains:

- experiment name
- metric name
- parameter name
- parameter value
- `run_1_ms` to `run_5_ms`
- `average_ms`

### Per-run CSV

[benchmark_runs.csv](/home/daydream/PQABSE-SRM-httpnitro/benchmarks/results/benchmark_runs.csv)

Each row contains:

- experiment name
- metric name
- parameter name
- parameter value
- run index
- duration in ms

## Notes

- The runner resets TA, Edge, CS, and MDU runtimes between runs for cleaner measurements.
- Results are appended, not overwritten.
- If you want a fresh CSV, delete the old CSV files first.
- The script uses local binaries directly; it does not require the HTTP servers to be running.
