# MDU

Deploy this folder to the MDU client host or relay host.

Main commands:

```bash
./mdu.sh refresh Bob live_refresh_1
./mdu.sh submit-search bob_before_revoke search_before_1
./mdu.sh wait-response search_before_1 60
./mdu.sh collect-response Bob search_before_1
```

Environment:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
export PQ_ABSE_TA_EXPORT_DIR=/mnt/pq_abse_exports
```

Use this on:

- a laptop beside the phone
- a relay host
- any client machine that can import refresh material and submit queries
