# ☠️ PROJECT: MODERN KILL LAB (MKL)
### Automated Cyber Range Deployment System // v2.2.0

![Build Status](https://img.shields.io/badge/Build-PASSING-brightgreen?style=for-the-badge&logo=github)
![Platform](https://img.shields.io/badge/Platform-CROSS--PLATFORM-blueviolet?style=for-the-badge&logo=linux)
![Security Level](https://img.shields.io/badge/Security-OFFENSIVE-red?style=for-the-badge&logo=kali-linux)
![Author](https://img.shields.io/badge/Operator-NEURAL_PHANTOM-orange?style=for-the-badge)

```
███╗   ███╗ ██████╗ ██████╗ ███████╗██████╗ ███╗   ██╗
████╗ ████║██╔═══██╗██╔══██╗██╔════╝██╔══██╗████╗  ██║
██╔████╔██║██║   ██║██║  ██║█████╗  ██████╔╝██╔██╗ ██║
██║╚██╔╝██║██║   ██║██║  ██║██╔══╝  ██╔══██╗██║╚██╗██║
██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                       
██╗  ██╗██╗██╗     ██╗         ██╗      █████╗ ██████╗ 
██║ ██╔╝██║██║     ██║         ██║     ██╔══██╗██╔══██╗
█████╔╝ ██║██║     ██║         ██║     ███████║██████╔╝
██╔═██╗ ██║██║     ██║         ██║     ██╔══██║██╔══██╗
██║  ██╗██║███████╗███████╗    ███████╗██║  ██║██████╔╝
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═════╝ 
```

---

## MISSION BRIEFING

**Modern Kill Lab (MKL)** is a weaponized "Infrastructure-as-Code" deployment tool. It abandons legacy lab setups in favor of Hybrid Identity, AI-driven vulnerabilities, EDR evasion techniques, and Kubernetes attack vectors.

This script orchestrates a hostile environment designed to test your skills against current TTPs (Tactics, Techniques, and Procedures), moving beyond simple exploits into complex identity attacks, in-memory execution, and defense evasion.

---

## 🏗️ ARSENAL (What Gets Built)

### 🎯 TARGET ALPHA: Lab-DC01 (The Stronghold)

| Property | Value |
|----------|-------|
| **OS** | Windows Server 2022 (Evaluation) |
| **Role** | Domain Controller (LAB.local) |

**Core Vulnerability Matrix:**

| Severity | Vulnerability |
|----------|---------------|
| `CRITICAL` | **AD CS Web Enrollment:** Misconfigured CA vulnerable to NTLM Relay (ESC8). |
| `HIGH` | **Legacy HR Portal:** Custom PHP app with blind & error-based SQL Injection. |
| `HIGH` | **Hybrid Identity Bait:** Decoy "Azure AD Connect" config with reversible credentials. |
| `HIGH` | **AS-REP Roasting:** `svc_backup` configured with "Do not require Kerberos preauthentication". |
| `HIGH` | **Kerberoasting:** `svc_sql` has a Service Principal Name (SPN) registered. |

**Advanced Offensive Labs (`C:\Tools\`):**

| Lab | Path | Purpose |
|-----|------|---------|
| **AMSI Bypass** | `C:\Tools\AMSILab` | Weak ACLs on AMSI providers, vulnerable loader scripts |
| **VEH Bypass** | `C:\Tools\VEHLab` | FakeEDR.exe using Vectored Exception Handlers |
| **Reflective Injection** | `C:\Tools\ReflectiveLab` | Vulnerable .NET Assembly.Load application |
| **Process Hollowing** | `C:\Tools\HollowingLab` | Target process list and technique documentation |
| **Credential Dumping** | `C:\Tools\CredLab` | SAM/SYSTEM/SECURITY hive backups, Credential Manager entries |
| **LOLBins** | `C:\Tools\LOLBinLab` | MSBuild payload, WMIC/Certutil exercises |
| **Vulnerable Drivers** | `C:\Tools\DriverLab` | BYOVD documentation (RTCore64, DBUtil) |
| **Persistence** | `C:\Tools\PersistenceLab` | Hidden scheduled task ("WindowsDefenderUpdate") |

**Logging & Telemetry (For Bypass Practice):**
- PowerShell ScriptBlock Logging: **ENABLED**
- Command Line Auditing: **ENABLED**

---

### 🎯 TARGET BRAVO: Lab-Web01 (The Modern Surface)

| Property | Value |
|----------|-------|
| **OS** | Debian 12 (Bookworm) |
| **Role** | AppSec & Container Host |

**Core Vulnerability Matrix:**

| Severity | Vulnerability |
|----------|---------------|
| `CRITICAL` | **Insecure AI Agent:** Internal LLM tool vulnerable to Prompt Injection & RCE. |
| `HIGH` | **Unsecured Kubernetes:** K3s cluster with overly permissive ServiceAccount. |
| `HIGH` | **vAPI & crAPI:** Broken Object Level Auth (BOLA) and Mass Assignment labs. |
| `MEDIUM` | **Juice Shop:** The gold standard for OWASP Top 10 training. |

**Container & Cloud Labs:**

| Lab | Path | Purpose |
|-----|------|---------|
| **Container Escapes** | `/home/vagrant/container_lab` | Privileged container, Docker socket mount |
| **Kubernetes Attacks** | `/home/vagrant/k8s_lab` | `vuln-admin-sa` with cluster-admin binding |
| **Data Exfiltration** | `/home/vagrant/exfil_lab` | Fake API keys and AWS credentials |

**Linux Privilege Escalation:**

| Technique | Configuration |
|-----------|---------------|
| **Sudo Abuse** | `vagrant` can run `/usr/bin/vim` as root (NOPASSWD) |
| **Capabilities** | `/usr/local/bin/python_cap` has `cap_setuid+ep` |

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
| | | Backup Svc | `LAB\svc_backup` / `Backup2024!` |
| | | Helpdesk | `LAB\helpdesk` / `Help123!` |
| | | HR Portal | `http://10.0.0.10/hr_portal` |
| | | AD CS | `http://10.0.0.10/certsrv` |
| | | Cred Manager | `fileserver.lab.local` → `BackupP@ss123!` |
| | | Cred Manager | `sqlserver.lab.local` → `SQLAdm1n!` |
| Lab-Web01 | `10.0.0.20` | SSH | `vagrant` / `vagrant` |
| | | AI Agent | `http://10.0.0.20:5000` |
| | | vAPI | `http://10.0.0.20:5002` |
| | | Juice Shop | `http://10.0.0.20:3000` |

---

## 🗂️ TOOL DIRECTORIES

### Windows (`C:\Tools\`)
```
C:\Tools\
├── AMSILab\              # AMSI bypass exercises
│   └── vulnerable_loader.ps1
├── VEHLab\               # VEH/EDR bypass
│   ├── FakeEDR.cs
│   └── FakeEDR.exe
├── ReflectiveLab\        # Reflective injection
│   └── VulnerableLoader.cs
├── HollowingLab\         # Process hollowing targets
│   └── README.txt
├── CredLab\              # Credential extraction
│   ├── SAM.bak
│   ├── SYSTEM.bak
│   └── SECURITY.bak
├── LOLBinLab\            # Living off the land
│   └── payload.csproj
├── DriverLab\            # BYOVD exercises
│   └── README.md
└── PersistenceLab\       # Persistence mechanisms
```

### Linux (`/home/vagrant/`)
```
/home/vagrant/
├── ai_agent/             # Vulnerable AI app
│   └── app.py
├── container_lab/        # Docker escape scenarios
│   └── docker-compose-vuln.yml
├── k8s_lab/              # Kubernetes attacks
│   └── vuln-sa.yaml
├── exfil_lab/            # Data exfiltration
│   └── .env
└── crapi/                # OWASP crAPI
    └── docker-compose.yml
```

---

## ⚠️ DISCLAIMER

> **Authorized for educational use and authorized penetration testing only.**

This lab environment is designed for learning offensive security techniques in a safe, isolated environment. Do not use these techniques against systems you do not own or have explicit written permission to test.

---

**Happy Hunting.** 🎯
