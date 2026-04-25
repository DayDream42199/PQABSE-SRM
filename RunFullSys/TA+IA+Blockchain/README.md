# TA+IA+Blockchain

Build:

```bash
cd app
npm ci
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Run the HTTP service:

```bash
export PQ_ABSE_TEE_MODE=software
cd ..
bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081
```

Run the HTTP service with Nitro enabled:

```bash
export PQ_ABSE_TEE_MODE=nitro
export PQ_ABSE_NITRO_CID=16
export PQ_ABSE_NITRO_PORT=5005
export PQ_ABSE_NITRO_TIMEOUT_MS=30000
cd ..
bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081
```

In Nitro mode, the TA service still exposes the same HTTP API, but the trusted key-generation step is forwarded to the enclave-backed `phase2_keygen` path.

Manual admin commands:

```bash
bash ./ta_ia_blockchain.sh setup
bash ./ta_ia_blockchain.sh register Alice
bash ./ta_ia_blockchain.sh register Bob
bash ./ta_ia_blockchain.sh revoke revoke_alice
bash ./ta_ia_blockchain.sh refresh Bob
```
