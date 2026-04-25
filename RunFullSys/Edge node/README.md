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
cd ..
bash ./edge_node.sh serve-http 0.0.0.0 8082
```
