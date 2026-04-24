# AWS Deployment Manual

## Goal

Run the full system across:

- one EC2 instance for `TA+IA+Blockchain`
- one EC2 instance for `Edge node`
- one EC2 instance for `CS`
- one MDO client device
- one MDU client device

The two TEE-backed roles are:

- `TA+IA+Blockchain`
- `Edge node`

For production-style deployment, these two should use AWS Nitro Enclaves for the sensitive operations instead of the current software TEE implementation inside the code.

## Important note

`RunFullSys` no longer contains a local orchestration flow. If you want local testing, use `RunLocal`.

## 1. What to copy where

### AWS EC2 instance 1

Copy:

- `RunFullSys/TA+IA+Blockchain`

Run there:

- `ta_ia_blockchain.sh`

### AWS EC2 instance 2

Copy:

- `RunFullSys/Edge node`

Run there:

- `edge_node.sh`

### AWS EC2 instance 3

Copy:

- `RunFullSys/CS`

Run there:

- `cs.sh`

### MDO device or relay host

Copy:

- `RunFullSys/MDO`

Run there:

- `mdo.sh`

### MDU device or relay host

Copy:

- `RunFullSys/MDU`

Run there:

- `mdu.sh`

If your real phones cannot directly run the shell/client code, use a laptop or small relay host beside each phone and treat that relay as the executable MDO or MDU endpoint.

## 2. Three EC2 instances

Use Nitro-based instance families for all three machines. The two enclave roles must be on instance types that support Nitro Enclaves.

Recommended shape:

- `TA+IA+Blockchain`: Nitro-capable EC2 with enclave support enabled
- `Edge node`: Nitro-capable EC2 with enclave support enabled
- `CS`: standard EC2 is acceptable, but Nitro-based is fine too

Before deployment:

1. Create the three EC2 instances.
2. Enable Nitro Enclaves on `TA+IA+Blockchain` and `Edge node`.
3. Install build dependencies on each machine.
4. Copy the corresponding role folder onto each machine with `scp` or `rsync`.

AWS references:

- [Nitro Enclaves overview](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Getting started](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html)
- [Attestation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
- [EC2 SCP transfer](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/linux-file-transfer-scp.html)

## 3. Shared paths and transport

The current role scripts coordinate through two path variables:

- `PQ_ABSE_BUS_DIR`
- `PQ_ABSE_TA_EXPORT_DIR`

On AWS, you should back these with a real transport.

Practical options:

- easiest prototype: shared EFS mounted on all three EC2 instances
- simpler copy-based option: TA pushes snapshots to S3, Edge and CS pull them, clients submit requests through API or SCP
- stronger system design: replace the file-bus with HTTP or gRPC APIs per role

For your current code, the fastest path is:

- EFS mount shared by `TA+IA+Blockchain`, `Edge node`, and `CS`
- MDO and MDU upload request files through SCP, S3 sync, or a lightweight API relay

## 4. Manual deployment steps

### 4.1 TA+IA+Blockchain EC2

Copy the role directory:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/TA+IA+Blockchain ubuntu@TA_HOST:/srv/pq_abse/
```

On the instance:

```bash
cd /srv/pq_abse/TA+IA+Blockchain/app
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Set paths:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
export PQ_ABSE_TA_EXPORT_DIR=/mnt/pq_abse_exports
```

Start service:

```bash
cd /srv/pq_abse/TA+IA+Blockchain
./ta_ia_blockchain.sh serve
```

### 4.2 Edge node EC2

Copy:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/Edge\ node ubuntu@EDGE_HOST:/srv/pq_abse/
```

Build:

```bash
cd /srv/pq_abse/Edge\ node/app
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Set paths:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
export PQ_ABSE_TA_EXPORT_DIR=/mnt/pq_abse_exports
```

Start service:

```bash
cd /srv/pq_abse/Edge\ node
./edge_node.sh serve
```

### 4.3 CS EC2

Copy:

```bash
scp -i /path/to/key.pem -r /home/chees/FinalProjAllBuild/RunFullSys/CS ubuntu@CS_HOST:/srv/pq_abse/
```

Build:

```bash
cd /srv/pq_abse/CS/app
cmake -S . -B build-wsl
cmake --build build-wsl -j
```

Set paths:

```bash
export PQ_ABSE_BUS_DIR=/mnt/pq_abse_bus
export PQ_ABSE_TA_EXPORT_DIR=/mnt/pq_abse_exports
```

Start service:

```bash
cd /srv/pq_abse/CS
./cs.sh serve
```

## 5. Dumping code to MDO and MDU

For MDO, copy:

- `RunFullSys/MDO`

For MDU, copy:

- `RunFullSys/MDU`

Those can live on:

- a laptop attached to the phone
- a relay mini-PC
- a Termux-style Android environment if you adapt the build/runtime setup yourself

MDO and MDU do not need Nitro Enclaves. They need network reachability to your chosen request transport.

## 6. Expected execution order

### Initial setup

1. Start `TA+IA+Blockchain`
2. Start `Edge node`
3. Start `CS`
4. Run TA setup
5. Register users

Example TA commands:

```bash
./ta_ia_blockchain.sh setup
./ta_ia_blockchain.sh register Alice
./ta_ia_blockchain.sh register Bob
```

### Upload flow

From MDO:

```bash
./mdo.sh encrypt-upload demo1 demo_encrypt_1
./mdo.sh wait-edge demo_encrypt_1 60
```

### Query flow

From MDU:

```bash
./mdu.sh submit-search bob_before_revoke search_before_1
./mdu.sh wait-response search_before_1 60
./mdu.sh collect-response Bob search_before_1
```

### Revocation flow

From TA:

```bash
./ta_ia_blockchain.sh submit-revoke revoke_alice live_revoke_1
```

From MDU:

```bash
./mdu.sh refresh Bob live_refresh_1
./mdu.sh submit-search bob_after_revoke search_after_1
./mdu.sh wait-response search_after_1 60
./mdu.sh collect-response Bob search_after_1
```

## 7. Real TEE requirement

Right now, the role split is ready for AWS deployment, but the enclave-sensitive code still uses the current in-project software TEE behavior.

To satisfy the real TEE requirement, the next implementation step is:

- move TA keygen operations into a Nitro Enclave worker
- move Edge encryption and secure-index generation into a Nitro Enclave worker
- have the parent EC2 instance communicate with the enclave over vsock
- optionally add Nitro attestation checks before the clients trust the outputs

That is the next phase, not the local cleanup phase.
