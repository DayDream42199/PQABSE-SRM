# ReadMe!!!
## Introduction
This repository contains a demo of post-quantum attribute-based searchable encryption. It includes backend services for the Trusted Authority, Edge Node, and Cloud Server, plus an Android mobile client for testing encryption, query generation, search, decryption, and revocation workflows.

The backend is intended to run on AWS EC2 instances, while the Android client is built locally with Android Studio on Windows using files prepared through WSL Ubuntu.

## Overall system
<p align="center">
  <img src="MainStructure.png" width="700">
</p>

---

## Running the System

The repository contains two distinct deployment modes for testing the framework's capabilities: `RunFullSys` and `RunLocal/ABSE_ZKP`.

1. **Local Testing (`RunLocal/ABSE_ZKP`):** This version will run everything locally. The code is a legacy version which may not reflect some final changes in the latest release. Only use this for testing that the system functionally works, as it will not return any significant performance data.
2. **Full Distributed System (`RunFullSys`):** This is the production-ready, final version. It requires setting up distinct server instances equipped with Trusted Execution Environments (preferably AWS). This code tests the full distributed workflow and will reflect real-world hardware capabilities.

---

## Prerequisites (RunFullSys)

These are the required programs and cloud infrastructure to run the full system test:
1. **Three (3) AWS EC2 Instances** (refer to the *Setting up AWS* section)
2. **Android Studio Panda 4** (refer to the *Android Studio Setup Guide* section)
3. **Windows Subsystem for Linux (WSL)**

---

## 1. Setting up the AWS Infrastructure

Follow these instructions step-by-step to spin up your nodes.

### Phase 1: Launch the EC2 Instances
1. Log in to your AWS Console and navigate to the **EC2 Dashboard**.
2. If you have already created the instances, skip to Phase 2. If not, click **Launch instance**.
3. Configure the instance using the following baseline settings:
   * **Name:** Choose a recognizable name (Create 1 for `TA+IA+Blockchain`, 1 for `Edge Node`, and 1 for `Cloud Server`).
   * **OS Images (AMI):** Select **Amazon Linux 2023 AMI** (kernel-6.1).
   * **Instance type:** Select **m5.xlarge** (Recommended for stability).
   * **Network settings:** For a quick setup, leave the default. For better security, change *Allow SSH traffic from* from `0.0.0.0/0` to **My IP**.
4. **Key Pair Setup:**
   * If you have an existing key, select it from the dropdown.
   * If not, click **Create new key pair**. Name it, select **RSA**, and choose the **.pem** format. Click create to download the file. *Warning: Do NOT lose this file; it is the only way to interact with your instances.*
5. **Instance-Specific Settings (Crucial):** Before clicking launch, scroll down to **Advanced Details** and configure the **Nitro Enclave** setting based on the node you are building. Refer to the table below.
6. Click **Launch instance**.
7. Repeat this process until you have created all 3 instances.

### Phase 2: Configure Security Groups (Ports)
1. In the EC2 Dashboard, click on one of your running instances.
2. Navigate to the **Security** tab and click on the assigned **Security group**.
3. Under **Inbound rules**, click **Edit inbound rules**, then **Add rule**.
4. Configure the rule:
   * **Type:** Custom TCP
   * **Source:** Anywhere-IPv4 (`0.0.0.0/0`)
   * **Port Range:** *(See the table below)*
5. Click **Save rules**. Repeat this for all 3 instances.

### Summary of Instance Configurations
| Node / Instance Name | Nitro Enclaves (Advanced Details) | Custom TCP Port |
| :--- | :--- | :--- |
| **TA + IA + Blockchain** | **Enable** | `8081` |
| **Edge Node** | **Enable** | `8082` |
| **Cloud Server (CS)** | Disable *(Leave default)* | `8083` |

Go back to the instances dashboard and record the public IPs of all instances. Your AWS instances are now online.

---

## 2. Dependencies and Code Setup (AWS Instances)

Before deploying the code, you must prepare your local terminal and configure the fundamental cryptographic libraries on your AWS instances.

### 0. Local Machine Preparation (Do this first)
Before connecting to AWS, secure your downloaded `.pem` key file using WSL.
1. Copy the `.pem` key file into your Linux home directory: `\\wsl.localhost\Ubuntu\home\<Your_Username>\`
2. Open your Ubuntu terminal and run:
```bash
cd ~
chmod 400 <Your_key>.pem
```

### 1. Universal Server Preparation (Run on ALL 3 Instances)
Because all three nodes rely on the same heavy cryptographic libraries (OpenFHE, LibOQS) and Zero-Knowledge compilers (Circom), you must run this baseline setup on every single instance before downloading the project code.
SSH into your instance:
```bash
ssh -o ServerAliveInterval=60 -i <Your_key>.pem ec2-user@<Instance_Public_IP>
```
(Type yes when prompted to confirm the connection).
Once logged in, copy and paste this entire block to install all dependencies. Note: Compiling OpenFHE will take 10-30 minutes. Let it run until completion.
```bash
# 1. Install OS Packages and Build Tools
sudo dnf update -y
sudo dnf -y install --allowerasing \
  git cmake ninja-build gcc gcc-c++ make \
  python3 python3-pip nodejs npm \
  openssl-devel wget curl tar gzip unzip jq which patch perl

# 2. Configure Global Paths
echo 'export CMAKE_PREFIX_PATH=/usr/local:/usr/local/lib64:/usr/local/lib:$CMAKE_PREFIX_PATH' >> ~/.bashrc
echo 'export CPLUS_INCLUDE_PATH=/usr/local/include/openfhe/core:/usr/local/include/openfhe/pke:$CPLUS_INCLUDE_PATH' >> ~/.bashrc
echo 'export LIBRARY_PATH=/usr/local/lib64:/usr/local/lib:$LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# 3. Install Modern Rust-based Circom
if ! command -v circom >/dev/null 2>&1 || ! circom --version | grep -q "2."; then
  sudo npm uninstall -g circom 2>/dev/null

  wget https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 -O circom

  chmod +x circom
  sudo mv circom /usr/local/bin/circom
fi

# 4. Create Workspace
WORKDIR="${HOME}/pqabse_deps"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# 5. Build and Install LibOQS
if [ ! -f /usr/local/lib64/cmake/liboqs/liboqsConfig.cmake ] && \
   [ ! -f /usr/local/lib/cmake/liboqs/liboqsConfig.cmake ]; then

  rm -rf liboqs

  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git

  cd liboqs

  cmake -S . -B build \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON

  cmake --build build -j2

  sudo cmake --install build
  sudo ldconfig

  cd ..
fi

# 6. Build and Install OpenFHE
if [ ! -d /usr/local/include/openfhe ]; then

  rm -rf openfhe-development

  git clone \
    --branch v1.2.2 \
    --depth 1 \
    https://github.com/openfheorg/openfhe-development.git

  cd openfhe-development

  cmake -S . -B build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED=ON \
    -DBUILD_UNITTESTS=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_BENCHMARKS=OFF

  cmake --build build -j2

  sudo cmake --install build
  sudo ldconfig

  cd ..
fi
```
Repeat this setup for your TA Node, Edge Node, and Cloud Server instances before proceeding.

### 2. Deploying the TA + IA + Blockchain Instance
Download the TA-specific code:
```bash
cd ~
git clone --no-checkout --sparse --filter=blob:none \
  https://github.com/DayDream42199/PQABSE-SRM.git
cd PQABSE-SRM
git sparse-checkout set "RunFullSys/TA+IA+Blockchain"
git checkout main
```
Build the C++ core and start the HTTP service:
```bash
cd RunFullSys/TA+IA+Blockchain/app
npm install
mkdir -p build-wsl
cd build-wsl
cmake ..
cmake --build . -j2

cd ..
echo '/usr/local/lib' | sudo tee /etc/ld.so.conf.d/openfhe.conf
echo '/usr/local/lib64' | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
./build-wsl/phase1_setup
cd ..
bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081
```

### 3. Deploying the Edge Node Instance
Download the Edge-specific code:
```bash
cd ~
git clone --no-checkout --sparse --filter=blob:none \
  https://github.com/DayDream42199/PQABSE-SRM.git
cd PQABSE-SRM
git sparse-checkout set "RunFullSys/Edge node/"
git checkout main
```
Build the C++ core and start the HTTP service (Replace <Your_TA_instance_publicIP> with your actual TA IP):
```bash
cd "RunFullSys/Edge node/app/"
npm install
mkdir -p build-wsl
cd build-wsl
cmake ..
cmake --build . -j2

cd ../..
echo '/usr/local/lib' | sudo tee /etc/ld.so.conf.d/openfhe.conf
echo '/usr/local/lib64' | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
PQ_ABSE_TA_URL="http://<Your_TA_instance_publicIP>:8081" bash ./edge_node.sh serve-http 0.0.0.0 8082
```
### 4. Deploying the Cloud Server (CS) Instance
Download the CS-specific code:
```bash
cd ~
git clone --no-checkout --sparse --filter=blob:none \
  https://github.com/DayDream42199/PQABSE-SRM.git
cd PQABSE-SRM
git sparse-checkout set "RunFullSys/CS"
git checkout main
```
Build the C++ core and start the HTTP service (Replace <Your_TA_instance_publicIP> with your actual TA IP):
```bash
cd RunFullSys/CS/app
npm install
mkdir -p build-wsl
cd build-wsl
cmake ..
cmake --build . -j2

cd ../..
echo '/usr/local/lib' | sudo tee /etc/ld.so.conf.d/openfhe.conf
echo '/usr/local/lib64' | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
PQ_ABSE_TA_URL="http://<Your_TA_instance_publicIP>:8081" bash ./cs.sh serve-http 0.0.0.0 8083
```

---

## 3. Setting up the Mobile Client

This section explains how to prepare the Android demo app for the mobile Android emulator. Keep the complete repository and native helper scripts inside WSL Ubuntu, then copy only the Android application folder (`PQABSESRMMobileHTTP`) into Windows and open that copied folder with Android Studio. This avoids Gradle, CMake, and emulator stability issues that can occur when Android Studio opens a WSL path directly.

### 3.1 Prerequisites

Install and configure the following before starting:

1. **Android Studio** on Windows
2. **WSL with Ubuntu**
3. **Git LFS** inside WSL

### 3.2 Repository Setup in WSL Ubuntu

Run the repository setup commands inside your WSL Ubuntu terminal:

```bash
cd ~
sudo apt update
sudo apt install -y git git-lfs
git lfs install
git clone https://github.com/DayDream42199/PQABSE-SRM.git
cd PQABSE-SRM
git lfs pull
```

### 3.3 Copy the Android App Folder into Windows

After the repository has been cloned in WSL, copy only the Android app folder into a normal Windows path. Run this in Windows PowerShell:

```powershell
Copy-Item "\\wsl.localhost\Ubuntu-24.04\home\<your-wsl-user>\PQABSE-SRM\PQABSESRMMobileHTTP" `
  "C:\Users\<your-windows-user>\Desktop\PQABSESRMMobileHTTP" `
  -Recurse -Force
```

If your WSL distribution is named `Ubuntu` instead of `Ubuntu-24.04`, adjust the source path accordingly.

Warning: Do not open the WSL path directly in Android Studio. Open the copied Windows folder instead:

```text
C:\Users\<your-windows-user>\Desktop\PQABSESRMMobileHTTP
```

Prebuilt native libraries are already included at:

```text
PQABSESRMMobileHTTP/app/src/main/native-prebuilt
```

### 3.4 Android Studio Configuration

Open Android Studio, go to **More Actions > SDK Manager**, and verify that these components are installed:

In the **SDK Platforms** tab:

1. Android SDK Platform for the app compile SDK, such as **Android 14.0 ("UpsideDownCake")**.

In the **SDK Tools** tab:

2. Android SDK Build-Tools
3. Android SDK Platform-Tools
4. Android SDK Command-line Tools
5. NDK (Side by side)
6. CMake
7. Android Emulator

Then configure the Gradle JDK:

1. Open **Settings > Build, Execution, Deployment > Build Tools > Gradle**.
2. Set **Gradle JDK** to version `21`.
3. Select **JetBrains** as the vendor if Android Studio shows that option.

This helps prevent Gradle toolchain download failures on Windows.

### 3.5 Emulator Setup

In Android Studio:

1. Open **More Actions > Virtual Device Manager**.
2. Click **Create a virtual device**.
3. Select a recent Pixel device profile, such as **Pixel 7**.
4. Install a recent Android system image.
5. Click **Finish** and boot the emulator once to initialize it.

### 3.6 Build and Install the App

Open the copied Windows app folder in Android Studio:

```text
C:\Users\<your-windows-user>\Desktop\PQABSESRMMobileHTTP
```

Wait for the initial Gradle sync to finish. To verify the build and install from the command line, use Android Studio's bundled JDK in Windows PowerShell.

Build the debug APK:

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
cd "C:\Users\<your-windows-user>\Desktop\PQABSESRMMobileHTTP"

.\gradlew.bat :app:assembleDebug
```

Install the debug APK on the running emulator:

```powershell
.\gradlew.bat :app:installDebug
```

### 3.7 Cloud Service Integration

Once the app is running, configure the cloud endpoints inside the app settings. These must point to the public IP addresses of your EC2 instances.

| Service Node | App Setting Key | Configuration Format |
| :--- | :--- | :--- |
| TA Node | TA URL | `http://<TA_IP>:8081` |
| Edge Node | Edge URL | `http://<EDGE_IP>:8082` |
| Cloud Server | CS URL | `http://<CS_IP>:8083` |

Warning: Do not use `127.0.0.1` or private `172.x.x.x` addresses if the services are hosted on EC2 and the emulator is running locally.

### 3.8 First Validation Flow

After setup, verify the Android demo app with this sequence:

1. Boot the emulator and open the installed debug app.
2. Enter your cloud TA, Edge, and CS URLs in the configuration menu.
3. Register or refresh a test user.
4. Encrypt a test file.
5. Generate query artifacts.
6. Submit the query.
7. Decrypt the result.

If this flow completes successfully, the Android demo application is fully configured and ready to use.

### 3.9 Troubleshooting

**Gradle JDK or zip timestamp errors**

If Gradle fails because of a JDK download issue or invalid zip timestamp, force PowerShell to use Android Studio's bundled JDK:

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
.\gradlew.bat :app:installDebug
```

**ADB not recognized**

If `adb` commands fail, use the absolute path to the executable:

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" devices
```

**Emulator shows old app behavior or UI**

Perform a clean uninstall and reinstall:

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" uninstall com.example.pqabse_srmmobilehttp
.\gradlew.bat :app:installDebug
```

**Cloud connection issues**

If the app reaches Edge directly but encryption fails, the follow-up Cloud Server import may have failed rather than the Edge encryption itself. Check the CS `/health` endpoint, review `cs_http.log`, verify executable permissions on `cs.sh`, and confirm the Cloud endpoint URL inside the app.

If cloud endpoints work in the terminal but not in the app, double-check that the Android app is configured with public EC2 IP addresses instead of local or private IPs.

---

## 4. Running the Demo
While testing the system capabilities via the Android app, you should actively monitor the terminal outputs for all three AWS instances (TA, Edge, and CS).

Expected Behavior & Status Codes
**Successful Operations (200 OK):** A fully successful end-to-end flow will typically result in a 200 HTTP status code appearing across all relevant server logs.

**State Updates & Revocation (500 Internal Server Error):** When a user is revoked, the global system state (epoch) advances. If an active, non-revoked user attempts to generate a query artifact immediately after a revocation event, the server will intentionally reject it and throw a 500 status code because their keys are out of date.

**The Fix (Valid Users):** The user must refresh their key to sync with the new epoch before trying again. Follow the Revocation steps below.

**The Lockout (Revoked Users):** If a revoked user attempts to refresh their key, the TA node will permanently reject the request, and the 500 error will persist, proving the zero-knowledge lockout is functional.

### 4.1 Keygen
In the MDU Bootstrap tab, enter the user GID and attribute. Then press Register User.

### 4.2 Encrypt
In the MDO Encrypt tab, enter the bundle label and plaintext (file), keywords, and policy. Then, press Encrypt with Edge.

### 4.3 Search and Decrypt
In the MDU Query tab, enter the searcher GID (Which user are we) and keywords (min-match). Then, press generate query artifact, submits query to CS, and decrypt latest query result.

### 4.4 Revocation
In the Revocation and Refresh tab, enter the revoke target GID and press revoke target user. Then, when you wanted to search again using other GID (key of other user), you must enter that in refresh target GID, and press refresh current user.

---

## 5. Running the Experimentation
The experimentation is divided into two parts:

1. **Cloud experimentation** measures the deployed TA, Edge, and CS HTTP services.
2. **Local mobile experimentation** measures Android/emulator-side mobile primitives and native fixture work.

Run both parts if you want the complete experiment data. The cloud runners do not collect Android local timing, and the local mobile runner does not contact the cloud unless you explicitly run the normal app workflow.

### 5.1 Cloud Experimentation

Cloud experimentation is stored in `benchmarks/`. It measures these experiment families:

| Experiment family | Metric | Parameter sweep |
| --- | --- | --- |
| Edge bundle encryption | `encrypt_bundle_ms` | keyword counts `10, 50, 300, 500` |
| CS search candidate generation | `candidate_generation_ms` | keyword counts `10, 50, 300, 500` |
| TA trapdoor generation | `trapdoor_gen_ms` | keyword counts `10, 50, 300, 500` |
| TA key generation | `keygen_ms` | attribute counts `10, 20, 30, 40, 50` |
| TA revoke/update-token write | `update_token_write_ms` | user counts `10, 20, 30, 40, 50` |

The cloud experiment outputs are CSV files:

- averaged results: `cloud_benchmark_results.csv`
- per-run results: `cloud_benchmark_runs.csv`

#### Cloud Reference Models

The cloud/search-side reference experiment code is:

```text
benchmarks/run_cloud_reference_benchmarks.py
```

Use this runner when you need competing-paper reference curves for cloud-side comparison. It is separate from the Android mobile benchmark pack and does not run emulator tests.

The included reference models are:

| Paper/model | Model type | Supported metrics |
| --- | --- | --- |
| `b20` | `reference_model` | `search`, `encryption`, `decryption`, `trapdoor` |
| `b30` | `primitive_surrogate` | `keygen` |
| `b31` | `primitive_surrogate` | `keygen`, `encryption`, `decryption` |
| `b32` | `primitive_surrogate` | `search`, `trapdoor` |
| `b33` | `primitive_surrogate` | `search`, `trapdoor`, `encryption` |

To print the model descriptions and assumptions:

```bash
cd ~/PQABSE-SRM
python3 benchmarks/run_cloud_reference_benchmarks.py --list-models
```

To run all cloud reference models for all supported metrics:

```bash
cd ~/PQABSE-SRM
python3 benchmarks/run_cloud_reference_benchmarks.py \
  --metrics keygen,search,encryption,decryption,trapdoor \
  --papers all \
  --runs 5 \
  --out RunFullSys/experiment_results/cloud_reference_results.csv
```

The `--out` value is an output hint. When a CSV path is supplied, the runner writes these two files next to it:

- `RunFullSys/experiment_results/cloud_reference_raw.csv`
- `RunFullSys/experiment_results/cloud_reference_averages.csv`

The reference CSV columns include:

- raw CSV: `paper`, `metric`, `scale_type`, `scale_value`, `run`, `ms`, `status`, `message`, `model_type`, `candidate_count`, `exact_match_count`
- averages CSV: `paper`, `metric`, `scale_type`, `scale_value`, `runs`, `avg_ms`, `ok_runs`, `total_runs`, `status`, `message`, `model_type`, `avg_candidate_count`, `avg_exact_match_count`

To run only selected papers or metrics, pass comma-separated values:

```bash
python3 benchmarks/run_cloud_reference_benchmarks.py \
  --papers b20,b32,b33 \
  --metrics search,trapdoor \
  --runs 5 \
  --out RunFullSys/experiment_results/cloud_reference_results.csv
```

These rows are labeled as `reference_model` or `primitive_surrogate` in the CSV. They are benchmark-compatible reference curves, not full apples-to-apples implementations of the cited systems.

#### Step 1: Rebuild the Cloud Services

Run these commands on the matching cloud instances before benchmarking, so the HTTP services include the timing fields used by the experiment scripts.

TA:

```bash
cd ~/PQABSE-SRM/RunFullSys/TA+IA+Blockchain/app/build-wsl
cmake ..
cmake --build . -j2
```

Edge:

```bash
cd ~/PQABSE-SRM/"RunFullSys/Edge node"/app/build-wsl
cmake ..
cmake --build . -j2
```

CS:

```bash
cd ~/PQABSE-SRM/RunFullSys/CS/app/build-wsl
cmake ..
cmake --build . -j2
```

#### Step 2: Restart the Cloud Services

On the TA instance:

```bash
pkill -f "ta_ia_blockchain.sh serve-http"
cd ~/PQABSE-SRM/RunFullSys/TA+IA+Blockchain
nohup bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081 > ta_http.log 2>&1 &
```

On the Edge instance:

```bash
pkill -f "edge_node.sh serve-http"
cd ~/PQABSE-SRM/"RunFullSys/Edge node"
nohup env PQ_ABSE_TA_URL="http://<TA_IP>:8081" bash ./edge_node.sh serve-http 0.0.0.0 8082 > edge_http.log 2>&1 &
```

On the CS instance:

```bash
pkill -f "cs.sh serve-http"
cd ~/PQABSE-SRM/RunFullSys/CS
nohup env PQ_ABSE_TA_URL="http://<TA_IP>:8081" bash ./cs.sh serve-http 0.0.0.0 8083 > cs_http.log 2>&1 &
```

Replace `<TA_IP>`, `<EDGE_IP>`, and `<CS_IP>` with the public IP addresses or reachable hostnames for your deployment.

#### Step 3: Run the Cloud Benchmarks

From a machine that can reach all three cloud services:

```bash
cd ~/PQABSE-SRM
python3 benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083
```

To run only one cloud suite:

```bash
python3 benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083 \
  --suite keyword
```

```bash
python3 benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083 \
  --suite keygen
```

```bash
python3 benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083 \
  --suite revoke
```

To change the repeat count, add `--repeats`, for example:

```bash
python3 benchmarks/run_cloud_server_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083 \
  --repeats 3
```

#### Step 4: Run Dedicated Cloud Benchmarks, If Needed

Use these scripts when you want one CSV family per experiment instead of one combined cloud run.

CS search only:

```bash
python3 benchmarks/run_cloud_cs_search_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082 \
  --cs-url http://<CS_IP>:8083
```

Edge encryption only:

```bash
python3 benchmarks/run_cloud_edge_encrypt_experiments.py \
  --ta-url http://<TA_IP>:8081 \
  --edge-url http://<EDGE_IP>:8082
```

TA key generation only:

```bash
python3 benchmarks/run_cloud_ta_keygen_experiments.py \
  --ta-url http://<TA_IP>:8081
```

TA trapdoor generation only:

```bash
python3 benchmarks/run_cloud_ta_trapdoor_experiments.py \
  --ta-url http://<TA_IP>:8081
```

TA revoke/update-token only:

```bash
python3 benchmarks/run_cloud_ta_revoke_experiments.py \
  --ta-url http://<TA_IP>:8081
```

### 5.2 Local Mobile Experimentation

Local mobile experimentation is stored in `PQABSESRMMobileHTTP/benchmark-pack/`. It runs Android instrumentation tests on the Panda4 emulator and writes CSV results under the app's external files directory.

There are three mobile benchmark modes:

| Mode | Output folder | What it measures |
| --- | --- | --- |
| `reference` | `reference_mobile_primitives` | reference-paper mobile baselines: ChaCha20-Poly1305 encryption, HMAC-SHA256 trapdoor generation, and ChaCha20-Poly1305 decryption |
| `payload` | `payload_mobile_primitives` | lightweight payload encryption only: ChaCha20-Poly1305, excluding ABSE, secure-index construction, JNI native crypto, network, cloud, and Edge/TEE work |
| `fixtures` | `native_fixture_primitives` | Android JNI native fixture work: local bundle construction, trapdoor generation, and optionally decryption when fixture files are available |

The reference experiment is the `reference` mode. It produces:

- `reference_mobile_primitives/reference_mobile_primitives_raw.csv`
- `reference_mobile_primitives/reference_mobile_primitives_averages.csv`

The reference CSV contains these primitive labels:

- `reference_encrypt_chacha20_poly1305`
- `reference_trapdoor_hmac_sha256`
- `reference_decrypt_chacha20_poly1305`

#### Step 1: Open the Android Project

Copy/open the Android project in Windows, not directly from the WSL path:

```text
PQABSESRMMobileHTTP
```

In Android Studio Panda:

1. Open `PQABSESRMMobileHTTP`.
2. Start the Panda4 emulator.
3. Make sure the emulator is visible to `adb`.

From Windows PowerShell in the Android project root:

```powershell
cd C:\Users\User\AndroidStudioProjects\PQABSESRMMobileHTTP
$adb="$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
$pkg="com.example.pqabse_srmmobilehttp"
& $adb devices
```

#### Step 2: Build and Install the App/Test APK

If you need native fixture mode, set the Android native prebuilt root before building:

```powershell
$env:ABSE_ANDROID_PREBUILT_ROOT="C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt"
```

Install the debug app and Android test APK:

```powershell
.\gradlew.bat :app:installDebug :app:installDebugAndroidTest
```

If native C++ or JNI code changed, run a clean build once:

```powershell
.\gradlew.bat clean :app:installDebug :app:installDebugAndroidTest
```

#### Step 3: Run the Reference Mobile Experiment

This is the reference-paper mobile primitive experiment.

```powershell
.\benchmark-pack\run_mobile_benchmarks.ps1 `
  -Mode reference `
  -KeywordCounts 10,50,300,500 `
  -Runs 30 `
  -WarmupRuns 30 `
  -PayloadBytes 4096
```

The helper script installs the app/test APK, runs instrumentation, and pulls CSV files into:

```text
PQABSESRMMobileHTTP\benchmark-pack\results
```

Read the reference averages:

```powershell
Get-Content benchmark-pack\results\reference_mobile_primitives\reference_mobile_primitives_averages.csv
```

You can also run the same reference experiment manually with `adb`:

```powershell
& $adb shell am instrument -w `
  -e benchmarkMode reference `
  -e keywordCounts 10,50,300,500 `
  -e runs 30 `
  -e warmupRuns 30 `
  -e payloadBytes 4096 `
  -e class com.example.pqabse_srmmobilehttp.MobileBenchmarkPackInstrumentedTest#runBenchmarkPack `
  com.example.pqabse_srmmobilehttp.test/androidx.test.runner.AndroidJUnitRunner
```

#### Step 4: Run the Payload-Only Mobile Encryption Experiment

Use this mode for the paper-aligned lightweight mobile payload encryption number. It measures only ChaCha20-Poly1305 payload encryption, so the results should be nearly flat across keyword counts.

```powershell
.\benchmark-pack\run_mobile_benchmarks.ps1 `
  -Mode payload `
  -KeywordCounts 10,50,300,500 `
  -Runs 30 `
  -WarmupRuns 30 `
  -PayloadBytes 4096
```

Read the payload averages:

```powershell
Get-Content benchmark-pack\results\payload_mobile_primitives\payload_mobile_primitives_averages.csv
```

#### Step 5: Run the Native Fixture Experiment

Use this mode when you want Android-side native/JNI measurements without cloud HTTP calls.

At minimum, fixture mode needs:

```text
PQABSESRMMobileHTTP\benchmark-pack\fixtures\phase1_params.txt
```

For trapdoor and decryption, also provide:

```text
PQABSESRMMobileHTTP\benchmark-pack\fixtures\user_key.bin
PQABSESRMMobileHTTP\benchmark-pack\fixtures\bundles\keywords_0010_bundle.bin
PQABSESRMMobileHTTP\benchmark-pack\fixtures\bundles\keywords_0050_bundle.bin
PQABSESRMMobileHTTP\benchmark-pack\fixtures\bundles\keywords_0300_bundle.bin
PQABSESRMMobileHTTP\benchmark-pack\fixtures\bundles\keywords_0500_bundle.bin
```

Generate matching mobile decrypt fixtures from WSL if needed:

```powershell
wsl.exe bash -lc "cd /home/<your-wsl-user>/PQABSE-SRM/PQABSESRMMobileHTTP && python3 benchmark-pack/generate_mobile_decrypt_fixtures.py"
```

Then run fixture mode without the slow decryption pass:

```powershell
.\benchmark-pack\run_mobile_benchmarks.ps1 `
  -Mode fixtures `
  -KeywordCounts 10,50,300,500 `
  -Runs 5 `
  -IncludeDecryption $false
```

Read the fixture averages:

```powershell
Get-Content benchmark-pack\results\native_fixture_primitives\native_fixture_primitives_averages.csv
```

#### Step 6: Check Mobile Output Locations

On the emulator, benchmark output is written under:

```text
/sdcard/Android/data/com.example.pqabse_srmmobilehttp/files/benchmark-pack
```

After the helper script pulls results, local copies are under:

```text
PQABSESRMMobileHTTP\benchmark-pack\results
```

Expected mobile result files include:

- `native_status.txt`
- `payload_mobile_primitives/payload_mobile_primitives_raw.csv`
- `payload_mobile_primitives/payload_mobile_primitives_averages.csv`
- `reference_mobile_primitives/reference_mobile_primitives_raw.csv`
- `reference_mobile_primitives/reference_mobile_primitives_averages.csv`
- `native_fixture_primitives/native_fixture_primitives_raw.csv`
- `native_fixture_primitives/native_fixture_primitives_averages.csv`

Always pull fresh results after each benchmark run. Reading an old CSV from `benchmark-pack\results` is the easiest way to accidentally inspect stale data.
