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

This lab covers modern TTPs including: identity attacks, EDR/AMSI evasion, in-memory execution, process injection, container escapes, Kubernetes exploitation, and more.

---

## 📊 ATTACK VECTOR SUMMARY

| # | Vector | Target | Category | MITRE ATT&CK |
|---|--------|--------|----------|--------------|
| 1 | SQL Injection | DC01 | Initial Access | T1190 |
| 2 | AI Prompt Injection / RCE | Web01 | Execution | T1059 |
| 3 | AS-REP Roasting | DC01 | Credential Access | T1558.004 |
| 4 | Kerberoasting | DC01 | Credential Access | T1558.003 |
| 5 | Hybrid Identity Attack | DC01 | Credential Access | T1552.001 |
| 6 | AD CS Relay (ESC8) | DC01 | Privilege Escalation | T1557.001 |
| 7 | AMSI Bypass | DC01 | Defense Evasion | T1562.001 |
| 8 | VEH/EDR Bypass | DC01 | Defense Evasion | T1562.001 |
| 9 | Reflective Code Injection | DC01 | Defense Evasion | T1620 |
| 10 | Process Hollowing | DC01 | Defense Evasion | T1055.012 |
| 11 | Credential Dumping | DC01 | Credential Access | T1003 |
| 12 | LOLBin Execution | DC01 | Execution | T1218 |
| 13 | ETW/Logging Bypass | DC01 | Defense Evasion | T1562.002 |
| 14 | Persistence Mechanisms | DC01 | Persistence | T1053.005 |
| 15 | Container Escape | Web01 | Privilege Escalation | T1611 |
| 16 | Kubernetes Attacks | Web01 | Privilege Escalation | T1610 |
| 17 | Linux Privilege Escalation | Web01 | Privilege Escalation | T1548 |
| 18 | Data Exfiltration | Web01 | Exfiltration | T1048 |

---

## 🏗️ ARSENAL (What Gets Built)

### 🎯 TARGET ALPHA: Lab-DC01 (The Stronghold)

| Property | Value |
|----------|-------|
| **OS** | Windows Server 2022 (Evaluation) |
| **Role** | Domain Controller (LAB.local) |
| **IP Address** | 10.0.0.10 |
| **Attack Vectors** | 14 |

---

#### 🔴 CORE IDENTITY & WEB ATTACKS

| # | Vector | Severity | Description | Exploit Path |
|---|--------|----------|-------------|--------------|
| **1** | **SQL Injection** | `CRITICAL` | Legacy HR Portal with unsanitized input | `http://10.0.0.10/hr_portal?id=1' UNION SELECT...` |
| **3** | **AS-REP Roasting** | `HIGH` | `svc_backup` has "Do not require Kerberos preauth" | `GetNPUsers.py LAB.local/svc_backup -no-pass` |
| **4** | **Kerberoasting** | `HIGH` | `svc_sql` has SPN `MSSQLSvc/dc01.lab.local:1433` | `GetUserSPNs.py LAB.local/helpdesk:Help123!` |
| **5** | **Hybrid Identity** | `HIGH` | Azure AD Connect decoy with Base64 "encrypted" creds | `C:\Program Files\Azure AD Sync\connection.xml` |
| **6** | **AD CS Relay (ESC8)** | `CRITICAL` | CA Web Enrollment over HTTP (NTLM relay) | `ntlmrelayx.py -t http://10.0.0.10/certsrv/...` |

---

#### 🟠 DEFENSE EVASION & IN-MEMORY ATTACKS

| # | Vector | Severity | Description | Lab Path |
|---|--------|----------|-------------|----------|
| **7** | **AMSI Bypass** | `HIGH` | Weak ACLs on AMSI provider registry keys | `C:\Tools\AMSILab\` |
| **8** | **VEH/EDR Bypass** | `HIGH` | FakeEDR.exe using Vectored Exception Handlers | `C:\Tools\VEHLab\` |
| **9** | **Reflective Injection** | `HIGH` | Vulnerable .NET `Assembly.Load()` application | `C:\Tools\ReflectiveLab\` |
| **10** | **Process Hollowing** | `HIGH` | Target process list (notepad, svchost, werfault) | `C:\Tools\HollowingLab\` |

**Techniques to Practice:**
- Patch `AmsiScanBuffer` in memory
- Remove/hijack VEH handlers, clear DR0-DR7 registers
- sRDI (Shellcode Reflective DLL Injection)
- `NtUnmapViewOfSection` + PE injection

---

#### 🟡 CREDENTIAL ACCESS & DUMPING

| # | Vector | Severity | Description | Artifacts |
|---|--------|----------|-------------|-----------|
| **11** | **Credential Dumping** | `CRITICAL` | Multiple credential stores available | `C:\Tools\CredLab\` |

**Available Targets:**

| Source | Credential | Location/Method |
|--------|------------|-----------------|
| Credential Manager | `LAB\backup_admin` : `BackupP@ss123!` | `cmdkey /list` → Mimikatz |
| Credential Manager | `sa` : `SQLAdm1n!` | `cmdkey /list` → Mimikatz |
| SAM Hive | Local account hashes | `C:\Tools\CredLab\SAM.bak` |
| SYSTEM Hive | Boot key for SAM decryption | `C:\Tools\CredLab\SYSTEM.bak` |
| SECURITY Hive | Cached domain credentials | `C:\Tools\CredLab\SECURITY.bak` |
| LSASS | Domain credentials in memory | procdump, comsvcs.dll, nanodump |

---

#### 🔵 EXECUTION & PERSISTENCE

| # | Vector | Severity | Description | Example |
|---|--------|----------|-------------|---------|
| **12** | **LOLBin Execution** | `MEDIUM` | Pre-staged MSBuild, Certutil, WMIC payloads | `C:\Tools\LOLBinLab\` |
| **13** | **ETW/Logging Bypass** | `MEDIUM` | ScriptBlock Logging enabled (for bypass practice) | Patch `EtwEventWrite` |
| **14** | **Persistence** | `MEDIUM` | Hidden scheduled task + lab exercises | Task: `WindowsDefenderUpdate` |

**LOLBins Available:**

| Binary | Technique | Payload |
|--------|-----------|---------|
| `MSBuild.exe` | Inline C# task execution | `C:\Tools\LOLBinLab\payload.csproj` |
| `Certutil.exe` | Download & decode | `-urlcache -split -f` |
| `WMIC.exe` | XSL script execution | `/format:` payload |
| `MSHTA.exe` | HTA/VBScript execution | `.hta` payload |
| `Rundll32.exe` | JavaScript execution | `javascript:` protocol |

**Persistence Mechanisms to Practice:**
- Scheduled Tasks (hidden)
- WMI Event Subscriptions
- Registry Run Keys
- COM Hijacking
- DLL Search Order Hijacking

---

#### 📁 WINDOWS TOOL DIRECTORY STRUCTURE

```
C:\Tools\
├── AMSILab\
│   └── vulnerable_loader.ps1      # AMSI test harness
├── VEHLab\
│   ├── FakeEDR.cs                 # Source code
│   └── FakeEDR.exe                # Compiled monitor
├── ReflectiveLab\
│   └── VulnerableLoader.cs        # Assembly.Load vulnerability
├── HollowingLab\
│   └── README.txt                 # Target process list
├── CredLab\
│   ├── SAM.bak                    # Registry hive backup
│   ├── SYSTEM.bak                 # Registry hive backup
│   └── SECURITY.bak               # Registry hive backup
├── LOLBinLab\
│   └── payload.csproj             # MSBuild payload
├── DriverLab\
│   └── README.md                  # BYOVD instructions
└── PersistenceLab\
    └── (exercises)
```

---

### 🎯 TARGET BRAVO: Lab-Web01 (The Modern Surface)

| Property | Value |
|----------|-------|
| **OS** | Debian 12 (Bookworm) |
| **Role** | AppSec & Container Host |
| **IP Address** | 10.0.0.20 |
| **Attack Vectors** | 4 |

---

#### 🔴 AI & APPLICATION SECURITY

| # | Vector | Severity | Description | Exploit Path |
|---|--------|----------|-------------|--------------|
| **2** | **AI Prompt Injection / RCE** | `CRITICAL` | Flask app passes query directly to `subprocess.check_output(shell=True)` | `http://10.0.0.20:5000/ask?query=id` |

**Additional Web Apps:**

| Application | Port | Vulnerabilities |
|-------------|------|-----------------|
| OWASP Juice Shop | 3000 | OWASP Top 10 training |
| vAPI | 5002 | BOLA, Mass Assignment |
| crAPI | 8888 | Broken Auth, IDOR, SSRF |

---

#### 🟠 CONTAINER & KUBERNETES ATTACKS

| # | Vector | Severity | Description | Lab Path |
|---|--------|----------|-------------|----------|
| **15** | **Container Escape** | `CRITICAL` | Privileged container + Docker socket mount | `/home/vagrant/container_lab/` |
| **16** | **Kubernetes Attacks** | `CRITICAL` | `vuln-admin-sa` with cluster-admin binding | `/home/vagrant/k8s_lab/` |

**Container Escape Scenarios:**

| Container | Vulnerability | Escape Method |
|-----------|---------------|---------------|
| `vuln_privileged` | `privileged: true` | Mount host filesystem, chroot |
| `vuln_hostsock` | Docker socket mounted | Create privileged container from within |

**Kubernetes Attack Paths:**

| Misconfiguration | Impact | Exploitation |
|------------------|--------|--------------|
| Overly permissive ServiceAccount | Cluster takeover | `kubectl --as=system:serviceaccount:default:vuln-admin-sa get secrets -A` |
| No network policies | Lateral movement | Pod-to-pod communication unrestricted |
| Host path mounts | Node compromise | Read `/etc/shadow`, write cron jobs |

---

#### 🟡 LINUX PRIVILEGE ESCALATION

| # | Vector | Severity | Description | Exploit |
|---|--------|----------|-------------|---------|
| **17** | **Linux PrivEsc** | `HIGH` | Multiple sudo/capability misconfigurations | See table below |

**Privilege Escalation Paths:**

| Technique | Configuration | Exploit Command |
|-----------|---------------|-----------------|
| Sudo vim | `vagrant ALL=(ALL) NOPASSWD: /usr/bin/vim` | `sudo vim -c ':!/bin/bash'` |
| Python Capabilities | `/usr/local/bin/python_cap` has `cap_setuid+ep` | `python_cap -c 'import os; os.setuid(0); os.system("/bin/bash")'` |

---

#### 🔵 DATA EXFILTRATION

| # | Vector | Severity | Description | Lab Path |
|---|--------|----------|-------------|----------|
| **18** | **Data Exfiltration** | `MEDIUM` | Fake secrets (API keys, AWS creds) | `/home/vagrant/exfil_lab/.env` |

**Sample Data to Exfiltrate:**
```
API_KEY=sk_live_1234567890abcdef
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Exfiltration Techniques to Practice:**
- DNS tunneling
- ICMP data embedding
- HTTP/S POST exfil
- Base64 encoding in GET parameters
- Steganography

---

#### 📁 LINUX DIRECTORY STRUCTURE

```
/home/vagrant/
├── ai_agent/
│   └── app.py                     # Vulnerable Flask app
├── container_lab/
│   └── docker-compose-vuln.yml    # Escape scenarios
├── k8s_lab/
│   └── vuln-sa.yaml               # Overprivileged ServiceAccount
├── exfil_lab/
│   └── .env                       # Fake secrets
├── crapi/
│   └── docker-compose.yml         # OWASP crAPI
└── .kube/
    └── config                     # K3s admin kubeconfig
```

---

## ⚡ DEPLOYMENT PROTOCOL

### 1. Prerequisites

| Requirement | Specification |
|-------------|---------------|
| **Hardware** | 16GB RAM / 100GB Disk / VT-x Enabled CPU |
| **Software** | Python 3.x installed |
| **Network** | Unrestricted internet access (for ISO/Package retrieval) |

### 2. Execution

```bash
# Clone the repository
git clone <repo_url>
cd ModernKillLab

# Initialize the build sequence
python3 master_build.py
```

### 3. Automated Sequence

1. **Recon:** Detects OS and validates dependencies (Packer, VirtualBox)
2. **Acquisition:** Downloads Windows Server 2022 & Debian 12 ISOs
3. **Construction:** Packer builds VMs with vulnerable configurations
4. **Networking:** Creates isolated `psycholab` network

---

## 💀 KILL CHAIN ACCESS

### Domain Credentials

| Account | Password | Vulnerabilities |
|---------|----------|-----------------|
| `LAB\vagrant` | `Vagrant!123` | Initial access (RDP/WinRM) |
| `LAB\Administrator` | `Vagrant!123` | Domain Admin |
| `LAB\svc_sql` | `Password123!` | Kerberoastable (SPN), db_owner |
| `LAB\svc_backup` | `Backup2024!` | AS-REP Roastable |
| `LAB\helpdesk` | `Help123!` | Low-privilege domain user |
| `svc_adsync` | `Valhalla123!` | Hybrid identity (Base64 in XML) |

### Credential Manager (Windows)

| Target | Username | Password |
|--------|----------|----------|
| `fileserver.lab.local` | `LAB\backup_admin` | `BackupP@ss123!` |
| `sqlserver.lab.local` | `sa` | `SQLAdm1n!` |

### Linux Credentials

| Account | Password | Access |
|---------|----------|--------|
| `vagrant` | `vagrant` | SSH, sudo (limited) |
| `root` | N/A | `sudo su` or privesc |

---

## 🌐 NETWORK & SERVICES

| System | IP | Port | Service |
|--------|-----|------|---------|
| Lab-DC01 | 10.0.0.10 | 3389 | RDP |
| | | 5985 | WinRM |
| | | 80 | IIS (AD CS) |
| | | 80 | XAMPP (HR Portal) |
| | | 1433 | SQL Server |
| | | 389/636 | LDAP/LDAPS |
| | | 88 | Kerberos |
| Lab-Web01 | 10.0.0.20 | 22 | SSH |
| | | 5000 | AI Agent |
| | | 3000 | Juice Shop |
| | | 5002 | vAPI |
| | | 8888 | crAPI |
| | | 6443 | K3s API |

---

## 🛡️ BLUE TEAM NOTES

The following logging/telemetry is **ENABLED** for detection practice:

| Feature | Status | Purpose |
|---------|--------|---------|
| PowerShell ScriptBlock Logging | ✅ Enabled | Detect malicious scripts |
| Command Line Auditing | ✅ Enabled | Process creation visibility |
| Windows Defender | ❌ Disabled | Allow offensive tools |

**Detection Opportunities:**
- AS-REP/Kerberoasting: Event ID 4768, 4769
- LSASS Access: Event ID 4656, 4663
- Scheduled Task Creation: Event ID 4698
- PowerShell Execution: Event ID 4104

---

## 📚 REFERENCE MATERIALS

| Resource | URL |
|----------|-----|
| MITRE ATT&CK | https://attack.mitre.org/ |
| LOLBAS Project | https://lolbas-project.github.io/ |
| LOLDrivers | https://www.loldrivers.io/ |
| GTFOBins | https://gtfobins.github.io/ |
| HackTricks | https://book.hacktricks.xyz/ |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |

---

## ⚠️ DISCLAIMER

> **Authorized for educational use and authorized penetration testing only.**

This lab environment is designed for learning offensive security techniques in a safe, isolated environment. Do not use these techniques against systems you do not own or have explicit written permission to test.

---

**Happy Hunting.** 🎯
