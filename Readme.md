# Modernized Kill Lab - Master Builder

## Overview
This Python script (`master_build.py`) is a fully automated "Infrastructure as Code" tool designed to deploy a complex, vulnerable cybersecurity training range. It replaces manual setup by automatically detecting your OS, downloading necessary ISOs, and instructing **Packer** and **VirtualBox** to build two highly configured virtual machines.

## 🛠️ What The Script Does

### 1. Automated Infrastructure Management
* **OS Detection:** Identifies if you are running Windows, macOS (Intel), or Linux.
* **Dependency Handling:** Checks for **VirtualBox** and **Packer**. If missing, it offers to install them using your system's native package manager (`winget`, `brew`, `apt`, `pacman`, etc.).
* **ISO Management:**
    * Automatically downloads **Windows Server 2022 Evaluation** and **Debian 12** directly from official sources.
    * Enforces correct filenames (`ws2022.iso`, `debian.iso`) to ensure build compatibility.
    * Includes a manual fallback prompt if automatic downloads fail.

### 2. "Lab-DC01" (The Target Domain Controller)
Builds a Windows Server 2022 Domain Controller (`10.0.0.10`) with the following features:
* **Active Directory:** Promoted to DC for the `LAB.local` domain.
* **Vulnerable SQL Server:** Installs SQL Server Express with `sa` disabled but a weak service account (`LAB\svc_sql`) configured.
* **Legacy HR Portal (SQLi):** Deploys a custom PHP application on XAMPP that contains a classic **SQL Injection** vulnerability connected directly to the `HR_DB` database.
* **AD CS (Certificate Services):** Installs Active Directory Certificate Services with **Web Enrollment** enabled, opening the door for NTLM Relay attacks (ESC8).
* **Fake Cloud Identity:** Plants a decoy "Azure AD Sync" configuration file containing a reversible encrypted password, mimicking a common Hybrid Identity lateral movement path.

### 3. "Lab-Web01" (The Modern Application Server)
Builds a Debian 12 Linux server (`10.0.0.20`) focused on modern appsec:
* **Kubernetes (K3s):** Installs a lightweight Kubernetes cluster for container orchestration testing.
* **Insecure AI Agent:** Deploys a custom Python/Flask application simulating an internal AI tool vulnerable to **Prompt Injection** and **Remote Code Execution (RCE)**.
* **API Security Targets:** Runs Docker containers for **vAPI** (Vulnerable API), **crAPI**, and **OWASP Juice Shop**.

### 4. Networking & Cleanup
* **Isolation:** Configures a private Host-Only network (`psycholab`) so VMs can communicate safely without exposing them to the open internet.
* **Idempotency:** Checks for existing VMs and offers to "nuke" (delete) them before starting a fresh build.

## 📋 Requirements
To run this script successfully, you need:
* **Python 3:** Installed on your host machine.
* **Virtualization Support:** VT-x/AMD-V enabled in BIOS/UEFI.
* **Disk Space:** ~100GB free (for ISOs + uncompressed VM disks).
* **RAM:** 16GB recommended (8GB minimum).
* **Internet:** Required for downloading ISOs and packages.

## 🚀 Usage
```bash
python3 master_build.py
