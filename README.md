# ReadMeTestSigmaChangeDuaiNa

## Introduction
…

## Overall system
…
<Structure Image>
…

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
