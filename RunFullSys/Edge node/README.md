# Edge node

Deploy this folder to the Edge EC2 instance.

Main commands:

```bash
./edge_node.sh serve
./edge_node.sh encrypt demo1
```

Environment:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
export PQ_ABSE_TA_EXPORT_DIR=/mnt/pq_abse_exports
```

This role handles:

- encryption requests
- secure index creation
- forwarding ciphertext bundles toward CS

Planned real TEE upgrade:

- replace the current software TEE-backed encryption path with Nitro Enclave execution
