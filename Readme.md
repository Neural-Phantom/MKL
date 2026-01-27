# ☠️ PROJECT: MODERN KILL LAB (MKL)
### Automated Cyber Range Deployment System // v8.0 Gold Master

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

## 🎯 TARGET ALPHA: Lab-DC01 (Windows Server 2022)

**Role:** Domain Controller, Database Server, Certificate Authority  
**IP Address:** 10.0.0.10

| Vulnerability | Configuration Detail | Exploitation Method | Tools |
|---------------|----------------------|---------------------|-------|
| **AS-REP Roasting** | User `svc_backup` has "Do not require Kerberos preauthentication" enabled. | Request a TGT for svc_backup. The DC returns an encrypted TGT without asking for a password. Crack the hash offline to get the password (`Backup2024!`). | Impacket `GetNPUsers.py`, Rubeus |
| **Kerberoasting** | User `svc_sql` has a Service Principal Name (SPN) `MSSQLSvc/dc01.lab.local:1433`. | Request a TGS ticket for the SQL service. The ticket is encrypted with the service account's NTLM hash. Crack this offline to get the password (`Password123!`). | Impacket `GetUserSPNs.py`, Rubeus |
| **Golden Ticket** | The `krbtgt` account password is statically set to `GodMode123!`. | Use the known password/hash of the krbtgt account to forge a TGT ticket for any user (e.g., Administrator) with infinite validity and arbitrary groups. | Impacket `ticketer.py`, Mimikatz |
| **AD CS Misconfiguration (ESC8)** | AD CS Web Enrollment is installed on Port 80 without Extended Protection for Authentication (EPA). | Force the DC to authenticate to your attacker machine (e.g., via Coercer or SQLi). Relay that authentication to the AD CS web portal to request a certificate for the DC. | `ntlmrelayx.py`, PetitPotam, Coercer |
| **SQL Injection** | Custom PHP HR Portal on Port 8080 uses unsanitized input: `SELECT ... WHERE ID = $id`. | Inject SQL commands into the `id` parameter. Use `UNION SELECT` to dump data or enable `xp_cmdshell` to execute OS commands. | SQLMap, Burp Suite, Browser |
| **Weak Service Permissions** | The `svc_sql` account is a member of the `sysadmin` role in SQL Server. | Once you compromise the SQL service (via SQLi), you have full control over the database and underlying OS through `xp_cmdshell` (which you can enable as sysadmin). | SQLMap, Netcat (for reverse shell) |
| **Fake Cloud Credentials** | `C:\Program Files\Azure AD Sync\connection.xml` contains a reversible encrypted password. | Read the XML file, extract the `PasswordEncrypted` string, and decrypt it (Base64 → `Valhalla123!`) to recover credentials. | PowerShell, aadconnect-extract |
| **AMSI & EDR Bypass** | Weak configurations for AMSI and a custom "Fake EDR" process. | Patch `amsi.dll` in memory to bypass PowerShell security, or use VEH (Vectored Exception Handler) manipulation to bypass the fake EDR hooks. | PowerShell, C# exploits |

### DC01 Services

| Port | Service | URL |
|------|---------|-----|
| 80 | AD CS Web Enrollment | http://10.0.0.10/certsrv |
| 8080 | Legacy HR Portal | http://10.0.0.10:8080/hr_portal |
| 1433 | SQL Server Express | TCP |
| 3389 | RDP | TCP |
| 5985 | WinRM | TCP |
| 88 | Kerberos | TCP/UDP |
| 389/636 | LDAP/LDAPS | TCP |

---

## 🎯 TARGET BRAVO: Lab-Web01 (Debian 12)

**Role:** Web Server, Application Security Host, Pivot Point  
**IP Address:** 10.0.0.20  
**Domain Status:** Joined to `LAB.local`

| Vulnerability | Configuration Detail | Exploitation Method | Tools |
|---------------|----------------------|---------------------|-------|
| **SMB Remote Code Execution** | Samba share `[backup_drop]` has `guest ok = yes`, `force user = root`. A cron job runs bash on `*.sh` files in this share every minute. | Connect anonymously. Upload a shell script (e.g., reverse shell). Wait 60 seconds for the cron job to execute it as ROOT. | `smbclient`, `net view` |
| **Insecure AI Agent** | Python Flask app on Port 5000 passes user input directly to `subprocess.check_output`. | Send a request like `/ask?query=ls -la` to achieve Command Injection. Use this to steal keys or pivot. | curl, Browser |
| **Unsecured Kubernetes** | K3s cluster has a ServiceAccount `vuln-admin-sa` with `cluster-admin` privileges. | Extract the token for vuln-admin-sa (via the AI app or local access). Use it to authenticate to the API server and take full control of the cluster. | kubectl |
| **Privileged Container** | Docker container `vuln_priv` runs with `--privileged` flag. | Mount the host's filesystem (`/dev/sda1`) inside the container and escape to the host OS. | Docker escape exploits |
| **Docker Socket Mount** | Container `vuln_sock` has `/var/run/docker.sock` mounted. | Use the socket to communicate with the host Docker daemon. Spin up a new privileged container to execute commands on the host. | docker CLI (inside container) |
| **Sudo Misconfiguration** | User `vagrant` has `NOPASSWD` sudo rights for `vim`. | Use `sudo vim -c ':!/bin/sh'` to spawn a root shell without a password. | Terminal |
| **Hardcoded API Secrets** | `.env` file in `/home/vagrant/exfil_lab` contains fake AWS/Stripe keys. | Local file enumeration or "Post-Exploitation" looting to find credential leaks. | grep, find |
| **API Logic Flaws** | vAPI and crAPI (Dockerized) contain BOLA/IDOR and Mass Assignment bugs. | Manipulate API IDs to access other users' data or reset their passwords. | Postman, Burp Suite |

### Web01 Services

| Port | Service | Description |
|------|---------|-------------|
| 22 | SSH | OpenSSH |
| 445 | SMB | Samba (`backup_drop` share) |
| 5000 | AI Agent | Vulnerable Flask App (runs as root) |
| 3000 | Juice Shop | OWASP Training App |
| 5002 | vAPI | API Security Lab |
| 8888 | crAPI | OWASP crAPI |
| 6443 | K3s API | Kubernetes API Server |

---

## ⚡ DEPLOYMENT

### Prerequisites

| Requirement | Specification |
|-------------|---------------|
| **Hardware** | 16GB RAM / 100GB Disk / VT-x CPU |
| **Software** | Python 3.x (Packer & VirtualBox auto-installed) |
| **Network** | Internet access for ISO/package downloads |

### Execution

```bash
git clone <repo_url>
cd ModernKillLab
python3 master_build.py
```

### Build Process

1. **DC01 Build:** ~45-60 minutes (Windows + AD + SQL + AD CS)
2. **DC01 Start:** Runs headless for Web01 domain join
3. **Web01 Build:** ~15-20 minutes (Debian + Docker + K3s + Domain Join)
4. **Final Config:** Internal network `psycholab`

---

## 💀 CREDENTIALS

### Domain Accounts (LAB.local)

| Account | Password | Notes |
|---------|----------|-------|
| `LAB\vagrant` | `Vagrant!123` | Domain Admin |
| `LAB\Administrator` | `Vagrant!123` | Domain Admin |
| `LAB\svc_sql` | `Password123!` | Kerberoastable, SQL sysadmin |
| `LAB\svc_backup` | `Backup2024!` | AS-REP Roastable |
| `LAB\helpdesk` | `Help123!` | Standard domain user |
| `krbtgt` | `GodMode123!` | Golden Ticket target |

### Hidden/Extractable Credentials

| Location | Credential | Notes |
|----------|------------|-------|
| `C:\Program Files\Azure AD Sync\connection.xml` | `Valhalla123!` | Base64 encoded |
| Windows Credential Manager | `LAB\backup_admin` : `BackupP@ss123!` | For fileserver.lab.local |
| `/home/vagrant/exfil_lab/.env` | `API_KEY=sk_live_1234567890abcdef` | Fake secrets |
| `/home/vagrant/exfil_lab/.env` | `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` | Fake secrets |

### Linux Accounts

| Account | Password | Notes |
|---------|----------|-------|
| `vagrant` | `vagrant` | Local user, sudo vim |
| `LAB\vagrant` | `Vagrant!123` | Domain user (after join) |

---

## 🌐 NETWORK TOPOLOGY

```
┌─────────────────────────────────────────────────────────────┐
│                    psycholab (Internal Network)             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────────┐              ┌─────────────────┐     │
│   │   Lab-DC01      │              │   Lab-Web01     │     │
│   │   10.0.0.10     │◄────────────►│   10.0.0.20     │     │
│   │                 │   Domain     │                 │     │
│   │ Windows 2022    │   Trust      │ Debian 12       │     │
│   │ AD DS / AD CS   │              │ Domain Joined   │     │
│   │ SQL Server      │              │ Docker / K3s    │     │
│   └─────────────────┘              └─────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 QUICK ACCESS

### Web Services

| Service | URL |
|---------|-----|
| AD CS Web Enrollment | http://10.0.0.10/certsrv |
| Legacy HR Portal | http://10.0.0.10:8080/hr_portal |
| AI Agent | http://10.0.0.20:5000 |
| Juice Shop | http://10.0.0.20:3000 |
| vAPI | http://10.0.0.20:5002 |
| crAPI | http://10.0.0.20:8888 |

### Remote Access

```bash
# DC01 - RDP
xfreerdp /v:10.0.0.10 /u:LAB\\vagrant /p:'Vagrant!123' /cert:ignore

# DC01 - WinRM
evil-winrm -i 10.0.0.10 -u vagrant -p 'Vagrant!123'

# Web01 - SSH (Local)
ssh vagrant@10.0.0.20

# Web01 - SSH (Domain)
ssh LAB\\vagrant@10.0.0.20

# Web01 - SMB (Anonymous)
smbclient //10.0.0.20/backup_drop -N
```

---

## 📁 DIRECTORY STRUCTURE

### Windows (C:\Tools\)
```
C:\Tools\
├── AMSILab\
│   └── vuln.ps1
├── VEHLab\
│   ├── FakeEDR.cs
│   └── FakeEDR.exe
├── CredLab\
│   ├── SAM.bak
│   ├── SYSTEM.bak
│   └── SECURITY.bak
├── LOLBinLab\
│   └── payload.csproj
└── PersistenceLab\
```

### Linux (/home/vagrant/)
```
/home/vagrant/
├── ai_agent/
│   └── app.py
├── container_lab/
│   └── docker-compose-vuln.yml
├── k8s_lab/
│   └── vuln.yaml
├── exfil_lab/
│   └── .env
├── share/                    # SMB backup_drop share
├── crapi/
│   └── docker-compose.yml
└── .kube/
    └── config
```

---

## ⚠️ DISCLAIMER

> **For authorized educational use and penetration testing only.**

Do not use these techniques against systems without explicit written permission.

---

**Happy Hunting.** 🎯
