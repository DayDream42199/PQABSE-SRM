# ABSE_ZKP

## Current State

`ABSE_ZKP` is the current merged local testbed for the paper flow.

Implemented now:
- ABSE core flow from the original `ABSE` project
- ZKP-based authentication flow from `pqpeak`
- registration and revocation state using Merkle-tree-backed roots
- local blockchain-style state synchronization, with optional Anvil-backed mode
- separate runnable phases:
  - `phase1_setup`
  - `phase1_verify`
  - `phase2_keygen`
  - `phase3_encrypt`
  - `phase4_search`
  - `phase5_revoke`
- revocation epoch update flow
- re-encryption key generation
- update token generation and enforcement
- local software TEE boundary abstraction
- shared scenario file support for demo/test inputs
- nested policy expressions with `AND(...)`, `OR(...)`, and `THRESHOLD(k, ...)`

Current scope notes:
- runs locally on one laptop first
- bitmap search optimization is intentionally skipped
- TEE is software-only for now, but the boundary is kept explicit for later replacement

## What To Do Next

Main next steps:
- test and refine the TEE boundary more seriously
- split the code more cleanly for later deployment across mobile, edge, and cloud devices
- add more integration tests for different users, attributes, keywords, and revocation scenarios
- decide whether to keep local-file state or standardize Anvil-backed demos
- polish CLI/config handling for teammate handoff

## Important Commands

Build:
```bash
cd /home/chees/Work/ABSE_ZKP
cmake -S . -B build-wsl
cmake --build build-wsl -j"$(nproc)"
```

Run the demo script:
```bash
cd /home/chees/Work/ABSE_ZKP
./test_demo_1.sh
```

Run the demo script from a completely fresh state:
```bash
cd /home/chees/Work/ABSE_ZKP
./test_demo_1.sh --fresh
```

Run the ZKP test suite:
```bash
cd /home/chees/Work/ABSE_ZKP
npm run zk:test
```

## Scenario File

The shared demo/test inputs now live in:
- [`/home/chees/Work/ABSE_ZKP/config/test_demo_1.conf`](/home/chees/Work/ABSE_ZKP/config/test_demo_1.conf)

This file controls:
- which users are registered and which attributes they receive
- which data owner publishes a bundle
- plaintext and keyword sets
- the access policy expression
- which queries run before and after revocation
- which user is revoked

## How To Run Test Demo

The demo script runs the full happy path using the scenario file:
- setup
- register Alice
- register Bob
- encrypt `demo1`
- let Bob search before revocation
- revoke Alice
- let Bob search again after the epoch update
- confirm Alice is blocked after revocation

Command:
```bash
cd /home/chees/Work/ABSE_ZKP
./test_demo_1.sh
```

If you already ran the system before and want a clean rerun, use:
```bash
cd /home/chees/Work/ABSE_ZKP
./test_demo_1.sh --fresh
```

## Manual Phase Commands

The phase binaries can now pull their inputs from the shared scenario file instead of long terminal flag lists:
```bash
cd /home/chees/Work/ABSE_ZKP/build-wsl
./phase1_setup
./phase2_keygen --scenario /home/chees/Work/ABSE_ZKP/config/test_demo_1.conf --user Alice
./phase2_keygen --scenario /home/chees/Work/ABSE_ZKP/config/test_demo_1.conf --user Bob
./phase3_encrypt --scenario /home/chees/Work/ABSE_ZKP/config/test_demo_1.conf --bundle demo1
./phase4_search --scenario /home/chees/Work/ABSE_ZKP/config/test_demo_1.conf --query bob_before_revoke
./phase5_revoke --scenario /home/chees/Work/ABSE_ZKP/config/test_demo_1.conf --revocation revoke_alice
./phase4_search --scenario /home/chees/Work/ABSE_ZKP/config/test_demo_1.conf --query bob_after_revoke
./phase4_search --scenario /home/chees/Work/ABSE_ZKP/config/test_demo_1.conf --query alice_after_revoke
```

## Upload Status Note

Current upload checkpoint:
- main encrypt -> authenticate -> search -> revoke -> refresh -> lazy re-encrypt -> decrypt flow is working
- refreshed valid user access is enforced after revocation
- revoked user access is blocked after revocation
- lazy re-encryption is triggered on access to a stale bundle instead of requiring eager bundle rewrite
- current implementation is a working prototype aligned with the paper workflow, not a claim of exact formal cryptographic reproduction

Recommended for teammate handoff:
- treat this branch as the current prototype baseline
- use `./test_demo_1.sh --fresh` for the main end-to-end demo
- use `./test_lazy_refresh_flow.sh` to verify the paper-style stale-bundle then on-access refresh path
- generate broader experiment/test cases after the remaining teammate components are merged

Additional regression command:
```bash
cd /home/daydream/ABSE_ZKP
./test_lazy_refresh_flow.sh
```

## Synthetic Experiment Workflow

The repo now includes a synthetic benchmark pipeline for three reference-aligned experiment tracks:
- search benchmark sweep
- encryption benchmark sweep
- revocation benchmark sweep

These experiments are benchmark-compatible with the reference papers, not exact line-by-line reproductions of those papers' implementations.

Recommended reference mapping:
- `ReferenceTestPaper1.txt` -> search / keyword-scaling benchmark
- `ReferenceTestPaper4.txt` -> encryption / attribute-scaling benchmark
- `ReferenceTestPaper5.txt` -> revocation benchmark

### Build Benchmark Tools

From the project root:
```bash
cd /home/user/PQABSE/ABSE_ZKP
cmake -S . -B build-wsl
cmake --build build-wsl -j"$(nproc)"
```

Useful benchmark executables in `build-wsl`:
- `generate_synthetic_scenario`
- `materialize_scenario`
- `search_benchmark`
- `search_benchmark_sweep`
- `encryption_benchmark_sweep`
- `revocation_benchmark_sweep`
- `benchmark_orchestrator`

### One-Command Full Run

The easiest way to run everything is the orchestrator:
```bash
cd /home/user/PQABSE/ABSE_ZKP
./build-wsl/benchmark_orchestrator \
  --run-label paper_eval_1 \
  --users 50 \
  --bundles 200 \
  --keyword-pool 2000 \
  --keywords-per-bundle 500 \
  --attribute-pool 500 \
  --attrs-per-user 80 \
  --attrs-per-policy 20 \
  --query-sizes 10,50,100,200 \
  --queries-per-size 5 \
  --revocations 10 \
  --search-limit-per-size 5 \
  --revocation-limit 10
```

This runs:
1. synthetic scenario generation
2. scenario materialization into runtime users/bundles/indexes
3. search benchmark sweep
4. encryption benchmark sweep
5. revocation benchmark sweep

Outputs are written under:
- `/home/user/PQABSE/ABSE_ZKP/runtime/experiments/<run-label>/`

### Manual Step-By-Step Run

#### 1. Generate a Synthetic Scenario

```bash
cd /home/user/PQABSE/ABSE_ZKP
./build-wsl/generate_synthetic_scenario \
  --output /home/user/PQABSE/ABSE_ZKP/config/synthetic_benchmark.conf \
  --users 50 \
  --bundles 200 \
  --keyword-pool 2000 \
  --keywords-per-bundle 500 \
  --attribute-pool 500 \
  --attrs-per-user 80 \
  --attrs-per-policy 20 \
  --query-sizes 10,50,100,200 \
  --queries-per-size 5 \
  --revocations 10
```

This produces a standard scenario file that can be reused by the rest of the tools.

#### 2. Materialize Runtime Artifacts

```bash
cd /home/user/PQABSE/ABSE_ZKP
./build-wsl/materialize_scenario \
  --scenario /home/user/PQABSE/ABSE_ZKP/config/synthetic_benchmark.conf \
  --init-phase1-if-missing
```

This step:
- registers scenario users in IA if needed
- generates user secret keys and credentials
- encrypts all synthetic bundles
- rebuilds the bitmap search index

#### 3. Run Search Sweep

```bash
cd /home/user/PQABSE/ABSE_ZKP
./build-wsl/search_benchmark_sweep \
  --scenario /home/user/PQABSE/ABSE_ZKP/config/synthetic_benchmark.conf \
  --query-sizes 10,50,100,200 \
  --limit-per-size 5 \
  --provision-users
```

Outputs:
- `runtime/experiments/search_benchmark_sweep.csv`
- `runtime/experiments/search_benchmark_sweep_aggregate.csv`

#### 4. Run Encryption Sweep

```bash
cd /home/user/PQABSE/ABSE_ZKP
./build-wsl/encryption_benchmark_sweep \
  --scenario /home/user/PQABSE/ABSE_ZKP/config/synthetic_benchmark.conf \
  --rebuild-index
```

Outputs:
- `runtime/experiments/encryption_benchmark_sweep.csv`
- `runtime/experiments/encryption_user_aggregate.csv`
- `runtime/experiments/encryption_bundle_aggregate.csv`

#### 5. Run Revocation Sweep

```bash
cd /home/user/PQABSE/ABSE_ZKP
./build-wsl/revocation_benchmark_sweep \
  --scenario /home/user/PQABSE/ABSE_ZKP/config/synthetic_benchmark.conf
```

Outputs:
- `runtime/experiments/revocation_benchmark_sweep.csv`
- `runtime/experiments/revocation_benchmark_sweep_aggregate.csv`

### Important Parameters You Can Change

Synthetic scenario generation parameters:
- `--users`
  Number of synthetic users.
- `--bundles`
  Number of encrypted bundles/documents.
- `--keyword-pool`
  Total keyword dictionary size.
- `--keywords-per-bundle`
  Number of keywords sampled into each bundle.
- `--attribute-pool`
  Total attribute dictionary size.
- `--attrs-per-user`
  Number of attributes assigned to each user.
- `--attrs-per-policy`
  Number of attributes used in each bundle policy.
- `--policy-type`
  One of `attribute`, `and`, `or`, `threshold`.
- `--threshold`
  Required only for `threshold` policies.
- `--query-sizes`
  Comma-separated keyword counts to generate query buckets such as `10,50,100,200,500,1000`.
- `--queries-per-size`
  Number of generated queries for each query-size bucket.
- `--revocations`
  Number of revocation entries generated in the scenario.
- `--seed`
  Fixed random seed for reproducible datasets.

Sweep runner parameters:
- `search_benchmark_sweep --query-sizes`
  Which query-size buckets to actually execute.
- `search_benchmark_sweep --limit-per-size`
  Cap the number of executed queries per bucket.
- `search_benchmark_sweep --respect-policy`
  Require access policy satisfaction in the search benchmark.
- `search_benchmark_sweep --decrypt`
  Also measure decrypt-after-match time.
- `search_benchmark_sweep --rebuild-index-each`
  Force search index rebuild for each query run.
- `encryption_benchmark_sweep --rebuild-index`
  Rebuild the bitmap index after encryption runs.
- `revocation_benchmark_sweep --limit`
  Limit how many scenario revocation events are executed.

Orchestrator parameters:
- `--run-label`
  Output folder label under `runtime/experiments`.
- `--results-dir`
  Override the output directory directly.
- `--scenario-out`
  Override where the generated scenario file is written.
- `--search-limit-per-size`
  Per-bucket cap for the search sweep inside the orchestration run.
- `--revocation-limit`
  Limit revocation events inside the orchestration run.

### Practical Notes

- For the current exact-match search benchmark, `max(query size)` must be less than or equal to `keywords-per-bundle`.
- Large values like `2000+` keywords or attributes are supported by the CLI as long as the local machine and current crypto/runtime settings can handle them.
- Revocation state is persistent. If a user was already revoked in a previous run, the revocation sweep skips that event instead of crashing.
- For cleanest revocation comparisons, use fresh synthetic user IDs or reset runtime state between runs.
- The benchmark outputs are suitable for subsystem comparison and scaling plots. They should be described as reference-aligned benchmarking rather than exact reproductions of the cited papers.
