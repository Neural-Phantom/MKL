# ☠️ PROJECT: MODERN KILL LAB (MKL)
### Automated Cyber Range Deployment System // v2.2.0

![Build Status](https://img.shields.io/badge/Build-PASSING-brightgreen?style=for-the-badge&logo=github)
![Platform](https://img.shields.io/badge/Platform-CROSS--PLATFORM-blueviolet?style=for-the-badge&logo=linux)
![Security Level](https://img.shields.io/badge/Security-OFFENSIVE-red?style=for-the-badge&logo=kali-linux)
![Vectors](https://img.shields.io/badge/Attack_Vectors-18-critical?style=for-the-badge)
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

**Modern Kill Lab (MKL)** is a weaponized "Infrastructure-as-Code" deployment tool featuring **18 distinct attack vectors** across Windows Active Directory, Linux containers, and cloud-native infrastructure.

This lab supports **BOTH** Red Team and Blue Team training:
- 🔴 **Red Team:** Execute modern attack chains and TTPs
- 🔵 **Blue Team:** Detect, hunt, and respond to attacks

---

## 📊 ATTACK VECTOR MATRIX

| # | Vector | Target | Category | MITRE | Difficulty |
|---|--------|--------|----------|-------|------------|
| 1 | SQL Injection | DC01 | Initial Access | T1190 | 🟢 Easy |
| 2 | AI Prompt Injection / RCE | Web01 | Execution | T1059 | 🟢 Easy |
| 3 | AS-REP Roasting | DC01 | Credential Access | T1558.004 | 🟢 Easy |
| 4 | Kerberoasting | DC01 | Credential Access | T1558.003 | 🟢 Easy |
| 5 | Hybrid Identity Attack | DC01 | Credential Access | T1552.001 | 🟡 Medium |
| 6 | AD CS Relay (ESC8) | DC01 | Privilege Escalation | T1557.001 | 🟡 Medium |
| 7 | AMSI Bypass | DC01 | Defense Evasion | T1562.001 | 🟡 Medium |
| 8 | VEH/EDR Bypass | DC01 | Defense Evasion | T1562.001 | 🔴 Hard |
| 9 | Reflective Code Injection | DC01 | Defense Evasion | T1620 | 🔴 Hard |
| 10 | Process Hollowing | DC01 | Defense Evasion | T1055.012 | 🔴 Hard |
| 11 | Credential Dumping | DC01 | Credential Access | T1003 | 🟡 Medium |
| 12 | LOLBin Execution | DC01 | Execution | T1218 | 🟢 Easy |
| 13 | ETW/Logging Bypass | DC01 | Defense Evasion | T1562.002 | 🟡 Medium |
| 14 | Persistence Mechanisms | DC01 | Persistence | T1053.005 | 🟡 Medium |
| 15 | Container Escape | Web01 | Privilege Escalation | T1611 | 🟡 Medium |
| 16 | Kubernetes Attacks | Web01 | Privilege Escalation | T1610 | 🟡 Medium |
| 17 | Linux Privilege Escalation | Web01 | Privilege Escalation | T1548 | 🟢 Easy |
| 18 | Data Exfiltration | Web01 | Exfiltration | T1048 | 🟢 Easy |

---

## 🏗️ ARSENAL

### 🎯 TARGET ALPHA: Lab-DC01

| Property | Value |
|----------|-------|
| **OS** | Windows Server 2022 |
| **Role** | Domain Controller (LAB.local) |
| **IP Address** | 10.0.0.10 |
| **Attack Vectors** | 14 |

#### Vulnerabilities Deployed

| Vector | Component | Vulnerability |
|--------|-----------|---------------|
| SQLi | HR Portal | Unsanitized `$_GET["id"]` parameter |
| AS-REP | `svc_backup` | `DoesNotRequirePreAuth = True` |
| Kerberoasting | `svc_sql` | SPN: `MSSQLSvc/dc01.lab.local:1433` |
| Hybrid Identity | Azure AD Sync | Base64 password in `connection.xml` |
| AD CS (ESC8) | Certificate Authority | HTTP Web Enrollment (no HTTPS) |
| AMSI | Registry | Weak ACLs on AMSI Providers key |
| VEH | FakeEDR.exe | Removable exception handlers |
| Reflective Injection | VulnerableLoader | Unvalidated `Assembly.Load()` |
| Credential Dumping | Multiple | SAM/SYSTEM backups, Credential Manager |
| LOLBins | MSBuild, etc. | Pre-staged payloads |
| Logging | ScriptBlock | Enabled (for bypass practice) |
| Persistence | Scheduled Task | Hidden "WindowsDefenderUpdate" |

---

### 🎯 TARGET BRAVO: Lab-Web01

| Property | Value |
|----------|-------|
| **OS** | Debian 12 (Bookworm) |
| **Role** | Container & AppSec Host |
| **IP Address** | 10.0.0.20 |
| **Attack Vectors** | 4 |

#### Vulnerabilities Deployed

| Vector | Component | Vulnerability |
|--------|-----------|---------------|
| AI RCE | Flask App | `subprocess.check_output(query, shell=True)` |
| Container Escape | Docker | Privileged container, socket mount |
| Kubernetes | K3s | `vuln-admin-sa` with cluster-admin |
| Linux PrivEsc | sudo/caps | NOPASSWD vim, python with cap_setuid |
| Exfiltration | .env file | Fake API keys and AWS creds |

---

## ⚡ DEPLOYMENT

### Prerequisites

| Requirement | Specification |
|-------------|---------------|
| **Hardware** | 16GB RAM / 100GB Disk / VT-x CPU |
| **Software** | Python 3.x, VirtualBox, Packer |
| **Network** | Internet access for ISO downloads |

### Execution

```bash
git clone <repo_url>
cd ModernKillLab
python3 master_build.py
```

---

## 💀 CREDENTIALS

### Domain Accounts

| Account | Password | Notes |
|---------|----------|-------|
| `LAB\vagrant` | `Vagrant!123` | Admin access |
| `LAB\Administrator` | `Vagrant!123` | Domain Admin |
| `LAB\svc_sql` | `Password123!` | Kerberoastable |
| `LAB\svc_backup` | `Backup2024!` | AS-REP Roastable |
| `LAB\helpdesk` | `Help123!` | Low-priv user |
| `svc_adsync` | `Valhalla123!` | In Azure AD Sync XML |

### Credential Manager

| Target | Credential |
|--------|------------|
| `fileserver.lab.local` | `LAB\backup_admin` : `BackupP@ss123!` |
| `sqlserver.lab.local` | `sa` : `SQLAdm1n!` |

### Linux

| Account | Password |
|---------|----------|
| `vagrant` | `vagrant` |

---

## 🌐 SERVICES

| System | Port | Service |
|--------|------|---------|
| DC01 (10.0.0.10) | 3389 | RDP |
| | 5985 | WinRM |
| | 80 | HR Portal / AD CS |
| | 1433 | SQL Server |
| | 88 | Kerberos |
| | 389 | LDAP |
| Web01 (10.0.0.20) | 22 | SSH |
| | 5000 | AI Agent |
| | 3000 | Juice Shop |
| | 5002 | vAPI |
| | 6443 | K3s API |

---

## 🛡️ BLUE TEAM CAPABILITIES

### Logging & Telemetry Enabled

| Feature | Status | Log Location |
|---------|--------|--------------|
| PowerShell ScriptBlock Logging | ✅ ON | Event ID 4104 |
| Command Line Auditing | ✅ ON | Event ID 4688 |
| Kerberos Ticket Events | ✅ ON | Event ID 4768, 4769 |
| Object Access Auditing | ✅ ON | Event ID 4656, 4663 |
| Scheduled Task Auditing | ✅ ON | Event ID 4698 |

### Detection Tools (Recommended Install)

| Tool | Purpose | Install |
|------|---------|---------|
| Sysmon | Enhanced logging | `choco install sysmon` |
| Winlogbeat | Log shipping | ELK Stack integration |
| Velociraptor | DFIR & Hunting | Agent-based |
| YARA | Malware scanning | Signature-based |
| auditd | Linux audit | `apt install auditd` |
| Falco | Container security | K8s runtime detection |

---

## 📁 DIRECTORY STRUCTURE

### Windows (`C:\Tools\`)
```
C:\Tools\
├── AMSILab\              # AMSI bypass exercises
├── VEHLab\               # VEH/EDR bypass
├── ReflectiveLab\        # Reflective injection
├── HollowingLab\         # Process hollowing
├── CredLab\              # SAM/SYSTEM/SECURITY backups
├── LOLBinLab\            # LOLBin payloads
├── DriverLab\            # BYOVD documentation
└── PersistenceLab\       # Persistence exercises
```

### Linux (`/home/vagrant/`)
```
/home/vagrant/
├── ai_agent/             # Vulnerable Flask app
├── container_lab/        # Docker escape scenarios
├── k8s_lab/              # Kubernetes attacks
├── exfil_lab/            # Exfiltration targets
└── crapi/                # OWASP crAPI
```

---

## 📚 REFERENCES

| Resource | URL |
|----------|-----|
| MITRE ATT&CK | https://attack.mitre.org/ |
| LOLBAS | https://lolbas-project.github.io/ |
| GTFOBins | https://gtfobins.github.io/ |
| Sigma Rules | https://github.com/SigmaHQ/sigma |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |

---

## ⚠️ DISCLAIMER

> **Authorized for educational use and authorized penetration testing only.**

Do not use these techniques against systems without explicit written permission.

---

**Happy Hunting.** 🎯
