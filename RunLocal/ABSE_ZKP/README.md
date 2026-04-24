# ABSE_ZKP

`RunLocal/ABSE_ZKP` is the local baseline prototype.

Use this directory for:

- local end-to-end validation
- local revocation and refresh checks
- local experiment and benchmark runs

This is the place for local testing. `RunFullSys` is now reserved for AWS deployment work.

## Build

```bash
cd /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP
cmake -S . -B build-wsl
cmake --build build-wsl -j"$(nproc)"
```

## Main local runs

Fresh end-to-end demo:

```bash
cd /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP
./test_demo_1.sh --fresh
```

Lazy refresh regression:

```bash
cd /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP
./test_lazy_refresh_flow.sh
```

Core benchmark for keygen, encryption, decryption, key size, and ciphertext size:

```bash
cd /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP
rm -rf runtime
./build-wsl/core_crypto_benchmark \
  --scenario config/test_demo_1.conf \
  --user Bob \
  --bundle demo1 \
  --query bob_before_revoke \
  --init-phase1-if-missing
```

Benchmark output is written to:

- [core_crypto_benchmark.csv](/home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/runtime/experiments/core_crypto_benchmark.csv)

## Scenario file

The local demo scenario is:

- [test_demo_1.conf](/home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf)

It defines:

- Alice and Bob
- the `demo1` ciphertext bundle
- pre-revocation and post-revocation queries
- Alice revocation

## Manual phase flow

```bash
cd /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/build-wsl
./phase1_setup
./phase2_keygen --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --user Alice
./phase2_keygen --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --user Bob
./phase3_encrypt --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --bundle demo1
./phase4_search --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --query bob_before_revoke
./phase5_revoke --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --revocation revoke_alice
./phase2_keygen --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --user Bob --refresh-existing
./phase4_search --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --query bob_after_revoke
./phase4_search --scenario /home/chees/FinalProjAllBuild/RunLocal/ABSE_ZKP/config/test_demo_1.conf --query alice_after_revoke
```

## Scope note

I did not change the intended ABSE/revocation logic in this cleanup. This pass is to keep `RunLocal` usable and current as the local reference directory.
