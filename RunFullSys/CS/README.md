# CS

Deploy this folder to the CS EC2 instance.

Main commands:

```bash
./cs.sh serve
```

Environment:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
export PQ_ABSE_TA_EXPORT_DIR=/mnt/pq_abse_exports
```

This role handles:

- import of uploaded ciphertext bundles
- query processing
- exact match search
- lazy re-encryption during search after revocation
