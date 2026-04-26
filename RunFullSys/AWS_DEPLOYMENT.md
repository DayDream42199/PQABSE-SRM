# AWS Deployment Manual

## Goal

Run the system across:

- one EC2 instance for `TA+IA+Blockchain`
- one EC2 instance for `Edge node`
- one EC2 instance for `CS`
- one MDO client host
- one MDU client host

The intended sensitive roles are:

- `TA+IA+Blockchain` on Nitro-capable EC2
- `Edge node` on Nitro-capable EC2

`CS` can run on a normal EC2 instance.

## Current status

The repo already implements the HTTP role split required for EC2:

- `MDO/mobile owner -> Edge`
- `Edge -> returns ciphertext bundle`
- `MDO/mobile owner -> CS import`
- `MDU/mobile user -> CS query`
- `MDU/mobile user -> local decrypt`

The repo also already contains a Nitro-backed TEE path for:

- `TA+IA+Blockchain` trusted key generation
- `Edge node` trusted ciphertext-bundle creation

See [AWS_NITRO_TEE.md](./AWS_NITRO_TEE.md) for the parent/enclave flags and binaries.

## Transport model

`RunFullSys` now uses HTTP between roles.

The main service edges are:

- `MDO -> Edge node`
- `Edge node -> TA+IA+Blockchain`
- `Edge node -> CS`
- `MDU -> TA+IA+Blockchain`
- `MDU -> CS`
- `CS -> TA+IA+Blockchain`

The old shared-folder `service_bus` and `shared_exports` flow is no longer required.

## What to copy where

### TA+IA+Blockchain EC2

Copy:

- `RunFullSys/TA+IA+Blockchain`

### Edge node EC2

Copy:

- `RunFullSys/Edge node`

### CS EC2

Copy:

- `RunFullSys/CS`

### MDO client host

Copy:

- `RunFullSys/MDO`

### MDU client host

Copy:

- `RunFullSys/MDU`

If the real phones cannot run this shell-based client directly, use a relay laptop or mini-PC beside each phone and treat that machine as the executable MDO or MDU endpoint.

## Build dependencies

Each role with an `app/` directory needs:

- `cmake`
- `g++`
- `make`
- `python3`
- `node`

Each role app also needs the ZKP Node packages installed:

```bash
cd /srv/pq_abse/<ROLE>/app
npm ci
```

Then build:

```bash
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

## Network variables

Use these URLs on the relevant machines:

- `PQ_ABSE_TA_URL=http://TA_HOST:8081`
- `PQ_ABSE_EDGE_URL=http://EDGE_HOST:8082`
- `PQ_ABSE_CS_URL=http://CS_HOST:8083`

Open the ports in your EC2 security groups only as needed.

Suggested exposure:

- `TA+IA+Blockchain`: allow from `Edge node`, `MDU`, and your admin host
- `Edge node`: allow from `MDO`
- `CS`: allow from `Edge node` and `MDU`

## TA+IA+Blockchain EC2

Copy:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/TA+IA+Blockchain ubuntu@TA_HOST:/srv/pq_abse/
```

Build:

```bash
cd /srv/pq_abse/TA+IA+Blockchain/app
npm ci
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Run the HTTP service:

```bash
cd /srv/pq_abse/TA+IA+Blockchain
bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081
```

Administrative commands on the TA machine:

```bash
bash ./ta_ia_blockchain.sh setup
bash ./ta_ia_blockchain.sh register Alice
bash ./ta_ia_blockchain.sh register Bob
bash ./ta_ia_blockchain.sh revoke revoke_alice
bash ./ta_ia_blockchain.sh refresh Bob
```

## Edge node EC2

Copy:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/Edge\ node ubuntu@EDGE_HOST:/srv/pq_abse/
```

Build:

```bash
cd /srv/pq_abse/Edge\ node/app
npm ci
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Run:

```bash
export PQ_ABSE_TA_URL=http://TA_HOST:8081
export PQ_ABSE_CS_URL=http://CS_HOST:8083
cd /srv/pq_abse/Edge\ node
bash ./edge_node.sh serve-http 0.0.0.0 8082
```

## CS EC2

Copy:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/CS ubuntu@CS_HOST:/srv/pq_abse/
```

Build:

```bash
cd /srv/pq_abse/CS/app
npm ci
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Run:

```bash
export PQ_ABSE_TA_URL=http://TA_HOST:8081
cd /srv/pq_abse/CS
bash ./cs.sh serve-http 0.0.0.0 8083
```

## MDO host

Copy:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/MDO user@MDO_HOST:/srv/pq_abse/
```

Run upload:

```bash
export PQ_ABSE_EDGE_URL=http://EDGE_HOST:8082
cd /srv/pq_abse/MDO
bash ./mdo.sh encrypt-upload demo1 demo_encrypt_1
```

## MDU host

Copy:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/MDU user@MDU_HOST:/srv/pq_abse/
```

Build:

```bash
cd /srv/pq_abse/MDU/app
npm ci
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Run:

```bash
export PQ_ABSE_TA_URL=http://TA_HOST:8081
export PQ_ABSE_CS_URL=http://CS_HOST:8083
cd /srv/pq_abse/MDU
bash ./mdu.sh search bob_before_revoke demo_search_before
```

Refresh after revocation:

```bash
bash ./mdu.sh refresh Bob
bash ./mdu.sh search bob_after_revoke demo_search_after
```

## Startup order

Start services first:

1. `TA+IA+Blockchain`
2. `CS`
3. `Edge node`

Then initialize the authority:

1. `bash ./ta_ia_blockchain.sh setup`
2. `bash ./ta_ia_blockchain.sh register Alice`
3. `bash ./ta_ia_blockchain.sh register Bob`

Then run the demo flow:

1. MDO uploads with `bash ./mdo.sh encrypt-upload demo1 demo_encrypt_1`
2. MDU searches with `bash ./mdu.sh search bob_before_revoke demo_search_before`

## Benchmarking the EC2/mobile flow

The repo now includes:

- `RunFullSys/benchmark_ec2_mobile_flow.py`

This script measures the live HTTP flow against deployed services:

- owner/mobile-to-Edge encrypt roundtrip
- local MDU trapdoor generation
- CS query roundtrip
- local MDU decrypt time

The benchmark writes:

- per-run CSV: `RunFullSys/experiment_results/ec2_mobile_flow_runs.csv`
- averages CSV: `RunFullSys/experiment_results/ec2_mobile_flow_avg.csv`

Default benchmark points:

- `20`
- `300`
- `500`
- `1000`

Default repetitions:

- `5`

Run it from a client host that has the `RunFullSys/MDU` folder built locally:

```bash
cd /srv/pq_abse/RunFullSys
python3 ./benchmark_ec2_mobile_flow.py \
  --ta-url http://TA_HOST:8081 \
  --edge-url http://EDGE_HOST:8082 \
  --cs-url http://CS_HOST:8083
```

Notes:

- The script registers a fresh owner and user per run.
- It sends the owner plaintext/keywords to `Edge /mobile/encrypt`.
- It imports the returned bundle into `CS`.
- It prepares the query locally with the MDU binaries.
- It submits the request archive to `CS /query/<id>`.
- It decrypts locally and records the decrypt timing.

If you want different keyword points or repetition counts:

```bash
python3 ./benchmark_ec2_mobile_flow.py \
  --ta-url http://TA_HOST:8081 \
  --edge-url http://EDGE_HOST:8082 \
  --cs-url http://CS_HOST:8083 \
  --keyword-counts 20 300 500 1000 \
  --runs 5
```
3. TA revokes Alice with `bash ./ta_ia_blockchain.sh revoke revoke_alice`
4. MDU refreshes Bob with `bash ./mdu.sh refresh Bob`
5. MDU searches again with `bash ./mdu.sh search bob_after_revoke demo_search_after`

Expected behavior:

- Bob decrypts `hello_pq_world` before revocation
- Bob decrypts `hello_pq_world` after refresh
- Alice fails after revocation until refreshed

## Nitro note

The transport is now HTTP, but the active runtime path still calls the current C++ binaries. The repository already contains Nitro-related code for TA and Edge enclaves, but wiring those enclave binaries into the live HTTP service path is still a separate hardening step.
