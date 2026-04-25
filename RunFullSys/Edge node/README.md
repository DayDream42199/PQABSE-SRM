# Edge node

Build:

```bash
cd app
npm ci
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Run:

```bash
export PQ_ABSE_TA_URL=http://TA_HOST:8081
export PQ_ABSE_CS_URL=http://CS_HOST:8083
export PQ_ABSE_TEE_MODE=software
cd ..
bash ./edge_node.sh serve-http 0.0.0.0 8082
```

Run with Nitro enabled:

```bash
export PQ_ABSE_TA_URL=http://TA_HOST:8081
export PQ_ABSE_CS_URL=http://CS_HOST:8083
export PQ_ABSE_TEE_MODE=nitro
export PQ_ABSE_NITRO_CID=16
export PQ_ABSE_NITRO_PORT=5005
export PQ_ABSE_NITRO_TIMEOUT_MS=30000
cd ..
bash ./edge_node.sh serve-http 0.0.0.0 8082
```

In Nitro mode, the HTTP service behavior is the same from the outside, but the trusted bundle-creation step is forwarded to the enclave-backed `phase3_encrypt` path.
