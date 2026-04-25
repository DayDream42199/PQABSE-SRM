# CS

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
cd ..
bash ./cs.sh serve-http 0.0.0.0 8083
```
