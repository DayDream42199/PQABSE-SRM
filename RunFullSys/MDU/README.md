# MDU

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
bash ./mdu.sh search bob_before_revoke demo_search_before
```

Refresh after revocation:

```bash
bash ./mdu.sh refresh Bob
bash ./mdu.sh search bob_after_revoke demo_search_after
```
