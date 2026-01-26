# ☠️ PROJECT: MODERN KILL LAB (MKL)
### Automated Cyber Range Deployment System // v2.0.0

![Build Status](https://img.shields.io/badge/Build-PASSING-brightgreen?style=for-the-badge&logo=github)
![Platform](https://img.shields.io/badge/Platform-CROSS--PLATFORM-blueviolet?style=for-the-badge&logo=linux)
![Security Level](https://img.shields.io/badge/Security-OFFENSIVE-red?style=for-the-badge&logo=kali-linux)
![Author](https://img.shields.io/badge/Operator-NEURAL_PHANTOM-orange?style=for-the-badge)

```text
 █▀▄▀█ █▀▀█ █▀▀▄ █▀▀ █▀▀█ █▀▀▄    █ █ █ █ █    █      █▀▀█ █▀▀▄ 
 █ ▀ █ █  █ █  █ █▀▀ █▄▄█ █▄▄▀    █▄▀▄█ █ █    █      █▄▄█ █▀▀▄ 
 ▀   ▀ ▀▀▀▀ ▀▀▀  ▀▀▀ ▀  ▀ ▀  ▀    ▀   ▀ ▀ ▀▄▄  █▄▄▄   ▀  ▀ ▀▀▀  
```

---

## MISSION BRIEFING

**Modern Kill Lab (MKL)** is a weaponized "Infrastructure-as-Code" deployment tool. It abandons legacy lab setups in favor of Hybrid Identity, AI-driven vulnerabilities, and Kubernetes attack vectors.

This script does not just "install VMs." It orchestrates a hostile environment designed to test your skills against current TTPs (Tactics, Techniques, and Procedures).

---

## 🏗️ ARSENAL (What Gets Built)

### 🎯 TARGET ALPHA: Lab-DC01 (The Stronghold)

| Property | Value |
|----------|-------|
| **OS** | Windows Server 2022 (Evaluation) |
| **Role** | Domain Controller (LAB.local) |

**Vulnerability Matrix:**

| Severity | Vulnerability |
|----------|---------------|
| `CRITICAL` | **AD CS Web Enrollment:** Misconfigured Certificate Authority vulnerable to NTLM Relay (ESC8). |
| `HIGH` | **Legacy HR Portal:** Custom PHP app with blind & error-based SQL Injection. |
| `HIGH` | **Hybrid Identity Bait:** Decoy "Azure AD Connect" config with reversible credentials. |
| `MEDIUM` | **Weak Service Accounts:** `LAB\svc_sql` running privileged services. |

---

### 🎯 TARGET BRAVO: Lab-Web01 (The Modern Surface)

| Property | Value |
|----------|-------|
| **OS** | Debian 12 (Bookworm) |
| **Role** | AppSec & Container Host |

**Vulnerability Matrix:**

| Severity | Vulnerability |
|----------|---------------|
| `CRITICAL` | **Insecure AI Agent:** Internal LLM tool vulnerable to Prompt Injection & RCE. |
| `HIGH` | **Unsecured Kubernetes:** K3s cluster with default configs. |
| `HIGH` | **vAPI & crAPI:** Broken Object Level Auth (BOLA) and Mass Assignment labs. |
| `MEDIUM` | **Juice Shop:** The gold standard for OWASP Top 10 training. |

---

## ⚡ DEPLOYMENT PROTOCOL

### 1. Prerequisites

| Requirement | Specification |
|-------------|---------------|
| **Hardware** | 16GB RAM / 100GB Disk / VT-x Enabled CPU |
| **Software** | Python 3.x installed |
| **Network** | Unrestricted internet access (for ISO/Package retrieval) |

### 2. Execution

Clone the repo, navigate to the directory, and execute the master builder.

```bash
# Initialize the build sequence
python3 master_build.py
```

### 3. Automated Sequence

1. **Recon:** Script detects OS (Windows/Linux/macOS) and hunts for dependencies.
2. **Acquisition:** Auto-downloads Windows Server 2022 & Debian ISOs (forced naming convention).
3. **Construction:** Packer spins up headless VirtualBox instances and injects the vulnerable configuration.
4. **Networking:** Deploys a private air-gapped network (`psycholab`) to contain the threat.

---

## 💀 KILL CHAIN ACCESS

| SYSTEM | IP ADDRESS | SERVICE | CREDENTIALS |
|--------|------------|---------|-------------|
| Lab-DC01 | `10.0.0.10` | RDP / WinRM | `LAB\vagrant` / `Vagrant!123` |
| | | SQL DB | `LAB\svc_sql` / `Password123!` |
| | | HR Portal | `http://10.0.0.10/hr_portal` |
| | | AD CS | `http://10.0.0.10/certsrv` |
| Lab-Web01 | `10.0.0.20` | SSH | `vagrant` / `vagrant` |
| | | AI Agent | `http://10.0.0.20:5000` |
| | | vAPI | `http://10.0.0.20:5002` |

---

## ⚠️ DISCLAIMER

> **Authorized for educational use and authorized penetration testing only.**

This lab environment is designed for learning offensive security techniques in a safe, isolated environment. Do not use these techniques against systems you do not own or have explicit written permission to test.

---

**Happy Hunting.** 🎯
