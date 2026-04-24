# TA+IA+Blockchain

Deploy this folder to the TA EC2 instance.

Main commands:

```bash
./ta_ia_blockchain.sh setup
./ta_ia_blockchain.sh register Alice
./ta_ia_blockchain.sh register Bob
./ta_ia_blockchain.sh serve
./ta_ia_blockchain.sh submit-revoke revoke_alice live_revoke_1
```

Environment:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
export PQ_ABSE_TA_EXPORT_DIR=/mnt/pq_abse_exports
```

This is the parent control plane for:

- setup
- keygen
- revocation
- blockchain state
- export of shared state and refresh material

Planned real TEE upgrade:

- replace the software TEE-backed keygen path with a Nitro Enclave service
