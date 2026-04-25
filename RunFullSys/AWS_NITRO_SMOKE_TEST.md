# AWS Nitro Smoke Test

This guide is for a first, simple AWS validation of the HTTP Nitro branch.

The goal is not to run the full experiment yet. The goal is only to prove that:

1. the parent service runs on EC2
2. the enclave server runs in Nitro Enclaves
3. one TA or Edge trusted request crosses the `vsock` boundary successfully

That is what "smoke test" means here.

## Recommended order

Start with TA first.

Why:

- TA `phase2_keygen` is the smaller trusted operation
- it is easier to debug than the full Edge encryption path
- once TA works, the same parent/enclave pattern can be reused for Edge

## TA smoke test target

Success means:

- TA HTTP service is running on the EC2 parent
- `nitro_keygen_enclave_server` is running inside the enclave
- TA is started with `PQ_ABSE_TEE_MODE=nitro`
- one registration request succeeds through the HTTP API

## Edge smoke test target

Success means:

- Edge HTTP service is running on the EC2 parent
- `nitro_encrypt_enclave_server` is running inside the enclave
- Edge is started with `PQ_ABSE_TEE_MODE=nitro`
- one encryption request succeeds through the HTTP API

## Environment variables used by the HTTP branch

TA and Edge both use:

```bash
export PQ_ABSE_TEE_MODE=nitro
export PQ_ABSE_NITRO_CID=16
export PQ_ABSE_NITRO_PORT=5005
export PQ_ABSE_NITRO_TIMEOUT_MS=30000
```

Use `software` instead of `nitro` if you want to fall back to the old path.

## What to check during the smoke test

- Did the HTTP service start?
- Did the enclave server start?
- Did the parent connect to the configured CID and port?
- Did the enclave return a result?
- Did the request finish without crashing?

## What this does not prove yet

A successful smoke test does not yet prove:

- production-ready enclave hardening
- AWS KMS attestation-based secret unsealing
- performance targets
- full multi-role experiment correctness

It only proves that the basic parent-to-enclave path is alive.
