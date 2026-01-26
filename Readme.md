# ☠️ PROJECT: MODERN KILL LAB (MKL)
### Automated Cyber Range Deployment System // v2.3.0

![Build Status](https://img.shields.io/badge/Build-PASSING-brightgreen?style=for-the-badge&logo=github)
![Platform](https://img.shields.io/badge/Platform-CROSS--PLATFORM-blueviolet?style=for-the-badge&logo=linux)
![Security Level](https://img.shields.io/badge/Security-OFFENSIVE-red?style=for-the-badge&logo=kali-linux)
![Vectors](https://img.shields.io/badge/Attack_Vectors-18-critical?style=for-the-badge)

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
- 🔵 **Blue Team:** Detect, hunt, and respond using pre-installed Sysmon & auditd

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

### 🎯 TARGET ALPHA: Lab-DC01 (Windows)

| Property | Value |
|----------|-------|
| **OS** | Windows Server 2022 |
| **Role** | Domain Controller (LAB.local) |
| **IP Address** | 10.0.0.10 |
| **Attack Vectors** | 14 |

#### Services & Ports

| Port | Service | Description |
|------|---------|-------------|
| **80** | IIS | AD CS Web Enrollment (`/certsrv`) |
| **8080** | XAMPP Apache | Legacy HR Portal (`/hr_portal`) |
| **1433** | SQL Server Express | Database |
| **3389** | RDP | Remote Desktop |
| **5985** | WinRM | Windows Remote Management |
| **88** | Kerberos | Authentication |
| **389** | LDAP | Directory Services |
| **636** | LDAPS | Secure LDAP |
| **53** | DNS | Domain Name Services |

#### Web Applications

| Application | URL | Vulnerability |
|-------------|-----|---------------|
| **AD CS Web Enrollment** | `http://10.0.0.10/certsrv` | ESC8 - HTTP NTLM Relay |
| **Legacy HR Portal** | `http://10.0.0.10:8080/hr_portal` | SQL Injection |

#### Vulnerabilities Deployed

| Vector | Component | Configuration |
|--------|-----------|---------------|
| SQLi | HR Portal | ODBC connection, unsanitized `$_GET["id"]` |
| AS-REP | `svc_backup` | `DoesNotRequirePreAuth = True` |
| Kerberoasting | `svc_sql` | SPN: `MSSQLSvc/dc01.lab.local:1433` |
| Hybrid Identity | Azure AD Sync | Base64 password in `connection.xml` |
| AD CS (ESC8) | IIS | HTTP Web Enrollment enabled (no HTTPS) |
| AMSI | Registry | Weak ACLs on `HKLM:\SOFTWARE\Microsoft\AMSI\Providers` |
| VEH | FakeEDR.exe | Compiled C# VEH monitor |
| Reflective Injection | VulnerableLoader.cs | Unvalidated `Assembly.Load()` |
| Credential Dumping | Multiple | SAM/SYSTEM/SECURITY backups, Credential Manager |
| LOLBins | MSBuild | Pre-staged `payload.csproj` |
| ETW/Logging | Registry | ScriptBlock Logging enabled |
| Persistence | Scheduled Task | Hidden task: `WindowsDefenderUpdate` |

#### Blue Team Tools (Pre-Installed)

| Tool | Status | Configuration |
|------|--------|---------------|
| **Sysmon** | ✅ Active | SwiftOnSecurity config at `C:\Tools\Sysmon\config.xml` |
| **ScriptBlock Logging** | ✅ Enabled | PowerShell Event ID 4104 |

---

### 🎯 TARGET BRAVO: Lab-Web01 (Linux)

| Property | Value |
|----------|-------|
| **OS** | Debian 12 (Bookworm) |
| **Role** | Container & AppSec Host |
| **IP Address** | 10.0.0.20 |
| **Attack Vectors** | 4 |

#### Services & Ports

| Port | Service | Description |
|------|---------|-------------|
| **22** | SSH | OpenSSH |
| **5000** | AI Agent | Vulnerable Flask App (runs as root) |
| **3000** | Juice Shop | OWASP Training App |
| **5002** | vAPI | API Security Lab |
| **445** | Samba | SMB File Share (`/home/vagrant/share`) |
| **6443** | K3s API | Kubernetes API Server |

#### Vulnerabilities Deployed

| Vector | Component | Configuration |
|--------|-----------|---------------|
| AI RCE | Flask App | `subprocess.check_output(query, shell=True)` as root |
| Container Escape | Docker | `vuln_privileged` (privileged:true), `vuln_hostsock` (socket mount) |
| Kubernetes | K3s | `vuln-admin-sa` ServiceAccount with cluster-admin |
| Linux PrivEsc | sudo | `vagrant ALL=(ALL) NOPASSWD: /usr/bin/vim` |
| Linux PrivEsc | Capabilities | `/usr/local/bin/python_cap` has `cap_setuid+ep` |
| Exfiltration | Files | Fake secrets in `/home/vagrant/exfil_lab/.env` |
| SMB | Samba | World-writable share at `/home/vagrant/share` |

#### Blue Team Tools (Pre-Installed)

| Tool | Status | Configuration |
|------|--------|---------------|
| **auditd** | ✅ Active | Monitoring `/etc/passwd` (key: identity) and `/bin/bash` (key: exec) |

---

## ⚡ DEPLOYMENT

### Prerequisites

| Requirement | Specification |
|-------------|---------------|
| **Hardware** | 16GB RAM / 100GB Disk / VT-x CPU |
| **Software** | Python 3.x, VirtualBox, Packer (auto-install offered) |
| **Network** | Internet access for ISO/package downloads |

### Execution

```bash
git clone <repo_url>
cd ModernKillLab
python3 master_build.py
```

### Build Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| 1 | ~5 min | Dependency check, ISO download |
| 2 | ~45-60 min | DC01 build (Windows + AD + Apps) |
| 3 | ~15-20 min | Web01 build (Debian + Docker + K3s) |
| 4 | ~1 min | Network configuration |

---

## 💀 CREDENTIALS

### Domain Accounts (LAB.local)

| Account | Password | Notes |
|---------|----------|-------|
| `LAB\vagrant` | `Vagrant!123` | Local & Domain Admin |
| `LAB\Administrator` | `Vagrant!123` | Domain Admin |
| `LAB\svc_sql` | `Password123!` | Kerberoastable (has SPN) |
| `LAB\svc_backup` | `Backup2024!` | AS-REP Roastable |
| `LAB\helpdesk` | `Help123!` | Standard domain user |
| `svc_adsync` | `Valhalla123!` | In Azure AD Sync XML (Base64) |

### Credential Manager (Stored on DC01)

| Target Server | Username | Password |
|---------------|----------|----------|
| `fileserver.lab.local` | `LAB\backup_admin` | `BackupP@ss123!` |
| `sqlserver.lab.local` | `sa` | `SQLAdm1n!` |

### Linux Accounts

| Account | Password | Notes |
|---------|----------|-------|
| `vagrant` | `vagrant` | sudo access |

### Other Credentials

| Service | Credential | Location |
|---------|------------|----------|
| DSRM | `Vulnerable123!` | AD Safe Mode |
| SQL Express | Windows Auth | Uses `LAB\svc_sql` |

---

## 🌐 QUICK ACCESS REFERENCE

### Web Services

| Service | URL |
|---------|-----|
| **AD CS Web Enrollment** | http://10.0.0.10/certsrv |
| **Legacy HR Portal** | http://10.0.0.10:8080/hr_portal |
| **AI Agent** | http://10.0.0.20:5000 |
| **Juice Shop** | http://10.0.0.20:3000 |
| **vAPI** | http://10.0.0.20:5002 |

### Remote Access Commands

**Windows (DC01):**
```bash
# RDP
xfreerdp /v:10.0.0.10 /u:LAB\\vagrant /p:'Vagrant!123' /cert:ignore

# WinRM (Evil-WinRM)
evil-winrm -i 10.0.0.10 -u vagrant -p 'Vagrant!123'

# WinRM (PowerShell)
Enter-PSSession -ComputerName 10.0.0.10 -Credential LAB\vagrant
```

**Linux (Web01):**
```bash
# SSH
ssh vagrant@10.0.0.20
# Password: vagrant

# SMB
smbclient //10.0.0.20/share -N
```

---

## 🛡️ BLUE TEAM QUICK START

### Windows (DC01) - Sysmon Queries

```powershell
# View all Sysmon events
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 100

# Process Creation (Event ID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 50

# Network Connections (Event ID 3)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3} -MaxEvents 50

# Process Access (Event ID 10) - LSASS monitoring
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} |
    Where-Object {$_.Properties[8].Value -like "*lsass*"}
```

### Linux (Web01) - auditd Queries

```bash
# View all audit events
sudo ausearch -i

# Identity file changes (key: identity)
sudo ausearch -k identity -i

# Command execution (key: exec)
sudo ausearch -k exec -i

# Real-time monitoring
sudo tail -f /var/log/audit/audit.log
```

---

## 📁 DIRECTORY STRUCTURE

### Windows (`C:\Tools\`)
```
C:\Tools\
├── Sysmon\
│   ├── Sysmon64.exe
│   └── config.xml                  # SwiftOnSecurity config
├── AMSILab\
│   └── vulnerable_loader.ps1       # AMSI test harness
├── VEHLab\
│   ├── FakeEDR.cs                  # Source
│   └── FakeEDR.exe                 # Compiled
├── ReflectiveLab\
│   └── VulnerableLoader.cs         # Assembly.Load vuln
├── HollowingLab\
│   └── README.txt                  # Target processes
├── CredLab\
│   ├── SAM.bak                     # Registry backup
│   ├── SYSTEM.bak                  # Registry backup
│   └── SECURITY.bak                # Registry backup
├── LOLBinLab\
│   └── payload.csproj              # MSBuild payload
├── DriverLab\
│   └── README.md                   # BYOVD instructions
└── PersistenceLab\
```

### Linux (`/home/vagrant/`)
```
/home/vagrant/
├── ai_agent/
│   └── app.py                      # Vulnerable Flask app
├── container_lab/
│   └── docker-compose-vuln.yml     # Escape scenarios
├── k8s_lab/
│   └── vuln-sa.yaml                # Overprivileged SA
├── exfil_lab/
│   └── .env                        # Fake API keys
├── crapi/
│   └── docker-compose.yml          # OWASP crAPI
├── share/                          # Samba share (777)
└── .kube/
    └── config                      # K3s kubeconfig
```

---

## 📚 REFERENCES

| Resource | URL |
|----------|-----|
| MITRE ATT&CK | https://attack.mitre.org/ |
| LOLBAS Project | https://lolbas-project.github.io/ |
| GTFOBins | https://gtfobins.github.io/ |
| Sigma Rules | https://github.com/SigmaHQ/sigma |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |
| Sysmon Config | https://github.com/SwiftOnSecurity/sysmon-config |

---

## ⚠️ DISCLAIMER

> **For authorized educational use and penetration testing only.**

Do not use these techniques against systems without explicit written permission.

---

**Happy Hunting.** 🎯
