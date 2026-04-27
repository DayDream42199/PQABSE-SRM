# Benchmark Runner

This folder contains the experiment harness for the six benchmark families:

1. ciphertext bundle creation time on the Edge node
2. mobile-side query-response decrypt time
3. TA-side key generation time
4. CS-side search candidate generation time
5. TA-side trapdoor generation time
6. TA-side update-token generation/write time after revocation

The runner appends results into the same CSV files every time you execute it.

## Cloud Runner

If your `TA`, `Edge`, and `CS` are deployed on cloud instances and the mobile side runs in the emulator, use:

- [run_cloud_server_experiments.py](/home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_cloud_server_experiments.py)

This script measures server-side timings from the real cloud HTTP responses:

- `encrypt_bundle_ms` from the `Edge` node
- `keygen_ms` from `TA`
- `candidate_generation_ms` from `CS`
- `trapdoor_gen_ms` from `TA`
- `update_token_write_ms` from `TA`

It does **not** measure mobile decrypt time. That still has to be collected from the emulator/app side.

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

- `10`
- `50`
- `300`
- `500`

Measured metrics:

- `encrypt_bundle_ms` on the Edge node
- `retrieve_decrypt_ms` on the mobile-side local decrypt path
- `candidate_generation_ms` on CS
- `trapdoor_gen_ms` on TA

### Attribute-scaled benchmark

These run at attribute counts:

- `10`
- `20`
- `30`
- `40`
- `50`

Measured metric:

- `keygen_ms` on TA

### User-count-scaled benchmark

These run at active user counts:

- `10`
- `20`
- `30`
- `40`
- `50`

Measured metric:

- `update_token_write_ms` on TA

## Run Everything

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py
```

## Run Only One Family

### Keyword benchmarks

These include three cloud/local role-specific families depending on which runner you use:

- `edge_node_encrypt`
- `cs_search`
- `ta_trapdoor_generation`

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py --suite keyword
```

### Key generation benchmark

CSV experiment label:

- `ta_key_generation`

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_all_experiments.py --suite keygen
```

### Revocation benchmark

CSV experiment label:

- `ta_update_token_write`

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

- The local runner resets TA, Edge, CS, and MDU runtimes between runs for cleaner measurements.
- Results are appended, not overwritten.
- If you want a fresh CSV, delete the old CSV files first.
- The local runner uses local binaries directly; it does not require the HTTP servers to be running.

## Run Against Cloud TA, Edge, and CS

Before using the cloud runner, rebuild and restart the cloud services so they include the new timing fields in the HTTP responses.

### TA

Rebuild:

```bash
cd ~/PQABSE-SRM/RunFullSys/TA+IA+Blockchain/app/build-wsl
cmake ..
cmake --build . -j2
```

Restart:

```bash
pkill -f "ta_ia_blockchain.sh serve-http"
cd ~/PQABSE-SRM/RunFullSys/TA+IA+Blockchain
nohup bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081 > ta_http.log 2>&1 &
```

### Edge

Rebuild:

```bash
cd ~/PQABSE-SRM/"RunFullSys/Edge node"/app/build-wsl
cmake ..
cmake --build . -j2
```

Restart:

```bash
pkill -f "edge_node.sh serve-http"
cd ~/PQABSE-SRM/"RunFullSys/Edge node"
nohup env PQ_ABSE_TA_URL="http://<TA_IP>:8081" bash ./edge_node.sh serve-http 0.0.0.0 8082 > edge_http.log 2>&1 &
```

### CS

Rebuild:

```bash
cd ~/PQABSE-SRM/RunFullSys/CS/app/build-wsl
cmake ..
cmake --build . -j2
```

Restart:

```bash
pkill -f "cs.sh serve-http"
cd ~/PQABSE-SRM/RunFullSys/CS
nohup env PQ_ABSE_TA_URL="http://<TA_IP>:8081" bash ./cs.sh serve-http 0.0.0.0 8083 > cs_http.log 2>&1 &
```

### Cloud benchmark command

Run this from a machine that can reach the three public URLs:

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083
```

Optional suites:

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083 \
  --suite keyword
```

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083 \
  --suite keygen
```

```bash
python3 /home/daydream/PQABSE-SRM-httpnitro/benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083 \
  --suite revoke
```
