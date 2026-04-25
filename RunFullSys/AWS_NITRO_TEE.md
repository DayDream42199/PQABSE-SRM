# AWS Nitro TEE Setup

This repo now supports a parent/enclave split for:

- `TA+IA+Blockchain/app/apps/phase2_keygen_main.cpp`
- `Edge node/app/apps/phase3_encrypt_main.cpp`

The existing software path still works. The Nitro path is enabled with:

- `--tee-mode nitro`
- `--nitro-cid <cid>`
- `--nitro-port <port>`
- `--nitro-timeout-ms <ms>`

## Parent-side executables

- TA parent: `phase2_keygen`
- Edge parent: `phase3_encrypt`

## Enclave-side executables

- TA enclave service: `nitro_keygen_enclave_server`
- Edge enclave service: `nitro_encrypt_enclave_server`

## Suggested port mapping

- TA keygen enclave port: `5005`
- Edge encryption enclave port: `5005`

These are typically on different parent instances, so reusing the same port is fine.

## HTTP role integration

In the HTTP deployment, the TA and Edge role scripts can now forward Nitro settings into the live parent binaries.

Set these environment variables before starting the HTTP role service:

```bash
export PQ_ABSE_TEE_MODE=nitro
export PQ_ABSE_NITRO_CID=16
export PQ_ABSE_NITRO_PORT=5005
export PQ_ABSE_NITRO_TIMEOUT_MS=30000
```

The TA service will then invoke `phase2_keygen` in Nitro mode, and the Edge service will invoke `phase3_encrypt` in Nitro mode.

If you do not set `PQ_ABSE_TEE_MODE=nitro`, the services stay on the existing software TEE path.

## Build

Build in each role folder:

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

## How the Nitro path works

1. The parent app loads the existing phase-1 artifacts.
2. The parent app opens a vsock connection to the enclave.
3. The parent sends files as a framed packet:
   - phase-1 params/public key/trapdoor files
   - request metadata files
4. The enclave service reconstructs a temp working directory.
5. The enclave runs the existing `SoftwareTee` logic internally.
6. The enclave returns the generated artifact file:
   - `user_key.bin` for TA keygen
   - `ciphertext_bundle.bin` for Edge encryption
7. The parent decodes the returned file and continues the normal workflow.

## TA parent run example

```bash
./build/phase2_keygen \
  --gid Alice \
  --attr doctor \
  --tee-mode nitro \
  --nitro-cid 16 \
  --nitro-port 5005
```

## Edge parent run example

```bash
./build/phase3_encrypt \
  --owner-gid owner1 \
  --label demo1 \
  --plaintext "hello" \
  --keyword alpha \
  --keyword beta \
  --policy-type and \
  --policy-attr doctor \
  --tee-mode nitro \
  --nitro-cid 16 \
  --nitro-port 5005
```

## Enclave process run example

Inside the enclave image, run one of:

```bash
./nitro_keygen_enclave_server --port 5005
./nitro_encrypt_enclave_server --port 5005
```

For smoke tests, you can add `--once` so the enclave handles one request and exits.

## Smoke test meaning

A smoke test is a very small end-to-end check that tells us whether the basic system is alive.

For this repo, a smoke test means:

1. The parent binary starts.
2. The enclave server starts.
3. The parent connects to the enclave over `vsock`.
4. One trusted request succeeds.
5. A result comes back without crashing.

It is not a full experiment or performance test. It is just the fastest way to answer:

- "Does the Nitro path basically work?"
- "Can these two processes actually talk to each other?"
- "Do we get one successful TA or Edge trusted operation back?"

## AWS instance setup notes

- Launch an enclave-enabled EC2 parent instance.
- Install Nitro CLI on the parent.
- Configure `/etc/nitro_enclaves/allocator.yaml`.
- Build an enclave image file (`.eif`) containing the enclave server binary and its runtime dependencies.
- Run the enclave with `nitro-cli run-enclave`.
- Use the returned enclave CID in the parent app flags.

Official docs:

- https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html
- https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
- https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html

## Important limitation

This patch provides the Nitro process boundary and vsock transport, but it does not yet move `MSK` unsealing to AWS KMS attestation. The parent still loads the phase-1 artifact files and forwards them into the enclave. That is enough to run on AWS Nitro Enclaves for development and integration, but for production-hardening you should next replace parent-side `MSK` loading with enclave-side attested KMS decrypt.
