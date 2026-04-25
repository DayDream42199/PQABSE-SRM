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
cd ..
bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081
```

Manual admin commands:

```bash
bash ./ta_ia_blockchain.sh setup
bash ./ta_ia_blockchain.sh register Alice
bash ./ta_ia_blockchain.sh register Bob
bash ./ta_ia_blockchain.sh revoke revoke_alice
bash ./ta_ia_blockchain.sh refresh Bob
```
