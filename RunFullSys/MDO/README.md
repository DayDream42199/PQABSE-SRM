# MDO

Deploy this folder to the MDO client host or relay host.

Main commands:

```bash
./mdo.sh encrypt-upload demo1 demo_encrypt_1
./mdo.sh wait-edge demo_encrypt_1 60
```

Environment:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
```

Use this on:

- a laptop beside the phone
- a relay host
- any client machine that can submit requests into your chosen AWS transport
