#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
import platform
import urllib.request
from pathlib import Path

# --- CONFIGURATION ---
HOME_DIR = Path.home()
BASE_DIR = HOME_DIR / "ModernHackingLab"

# 1. ISO CONFIGURATION
WS2022_TARGET_NAME = "ws2022.iso"
WS2022_URL = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"

DEBIAN_TARGET_NAME = "debian.iso"
DEBIAN_URL = "https://cdimage.debian.org/cdimage/archive/12.5.0/amd64/iso-cd/debian-12.5.0-amd64-netinst.iso"

class Colors:
    HEADER = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def print_color(text, color=Colors.ENDC):
    print(f"{color}{text}{Colors.ENDC}")

def to_hcl(lines):
    """
    Sanitizes a list of strings for HCL (HashiCorp Configuration Language).
    1. Escapes backslashes (C:\Windows -> C:\\Windows)
    2. Escapes double quotes (" -> \")
    3. Wraps in double quotes.
    """
    sanitized = []
    for line in lines:
        # Escape backslashes first
        clean = line.replace('\\', '\\\\')
        # Escape double quotes
        clean = clean.replace('"', '\\"')
        sanitized.append(f'"{clean}"')
    
    # Join with comma and newline for HCL array
    return "[\n    " + ",\n    ".join(sanitized) + "\n  ]"

# ============================================================================
# DEPENDENCY MANAGER
# ============================================================================
class DependencyManager:
    def __init__(self):
        self.os_type = platform.system()
        self.pkg_manager = self._identify_pkg_manager()
        
    def _identify_pkg_manager(self):
        if self.os_type == "Windows": return "winget"
        if self.os_type == "Darwin": return "brew"
        if self.os_type == "Linux":
            # Simple distro check
            try:
                with open("/etc/os-release") as f:
                    data = f.read().lower()
                    if "arch" in data: return "pacman"
                    if "debian" in data or "ubuntu" in data: return "apt"
                    if "fedora" in data: return "dnf"
            except: pass
        return None

    def _run_install(self, package_map):
        mgr = self.pkg_manager
        pkg = package_map.get(mgr)
        if not pkg: return False
        
        print_color(f"    [INSTALL] Installing '{pkg}' via {mgr}...", Colors.CYAN)
        cmd = []
        if mgr == "winget": cmd = ["winget", "install", "-e", "--id", pkg]
        elif mgr == "brew": cmd = ["brew", "install", "--cask", pkg] if "virtualbox" in pkg else ["brew", "install", pkg]
        elif mgr == "pacman": cmd = ["sudo", "pacman", "-S", "--noconfirm", pkg]
        elif mgr == "apt": cmd = ["sudo", "apt-get", "install", "-y", pkg]
        elif mgr == "dnf": cmd = ["sudo", "dnf", "install", "-y", pkg]

        try:
            subprocess.run(cmd, check=True)
            print_color(f"    [SUCCESS] {pkg} installed.", Colors.GREEN)
            return True
        except:
            print_color(f"    [ERROR] Install failed for {pkg}.", Colors.FAIL)
            return False

    def check_packer(self):
        if shutil.which("packer"): return True
        print_color("\n[!] Packer is MISSING.", Colors.YELLOW)
        if input(f"    Install Packer? (y/n): ").lower() == 'y':
            return self._run_install({"winget": "HashiCorp.Packer", "brew": "packer", "pacman": "packer", "apt": "packer", "dnf": "packer"})
        return False

    def check_vbox(self):
        if self.os_type == "Windows":
            default_path = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
            if shutil.which("VBoxManage") or default_path.exists(): return True
        elif shutil.which("VBoxManage"): return True

        print_color("\n[!] VirtualBox is MISSING.", Colors.YELLOW)
        if input(f"    Install VirtualBox? (y/n): ").lower() == 'y':
            return self._run_install({"winget": "Oracle.VirtualBox", "brew": "virtualbox", "pacman": "virtualbox virtualbox-host-modules-arch", "apt": "virtualbox", "dnf": "VirtualBox"})
        return False

# ============================================================================
# UTILITIES
# ============================================================================
def nuke_vm(vm_name):
    vbox = "VBoxManage"
    if platform.system() == "Windows" and not shutil.which("VBoxManage"):
        vbox = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    
    result = subprocess.run([vbox, "list", "vms"], capture_output=True, text=True)
    if vm_name in result.stdout:
        print_color(f"    [CLEAN] Deleting {vm_name}...", Colors.FAIL)
        subprocess.run([vbox, "controlvm", vm_name, "poweroff"], stderr=subprocess.DEVNULL)
        time.sleep(2)
        subprocess.run([vbox, "unregistervm", vm_name, "--delete"], stderr=subprocess.DEVNULL)
    
    # Cleanup output dirs
    if "DC01" in vm_name: shutil.rmtree(BASE_DIR / "output-dc01", ignore_errors=True)
    if "Web01" in vm_name: shutil.rmtree(BASE_DIR / "output-web01", ignore_errors=True)

def download_file(url, dest_path):
    print_color(f"    [DOWNLOADING] Target: {dest_path.name}...", Colors.CYAN)
    try:
        def reporthook(blocknum, blocksize, totalsize):
            readsofar = blocknum * blocksize
            if totalsize > 0:
                percent = readsofar * 1e2 / totalsize
                s = "\r%5.1f%% %*d / %d" % (percent, len(str(totalsize)), readsofar, totalsize)
                sys.stderr.write(s)
                if readsofar >= totalsize: sys.stderr.write("\n")
        urllib.request.urlretrieve(url, dest_path, reporthook)
        if dest_path.stat().st_size < 1000:
            print_color("    [ERROR] File too small.", Colors.FAIL)
            dest_path.unlink(); return False
        print_color("    [SUCCESS] Download Complete.", Colors.GREEN)
        return True
    except Exception as e:
        print_color(f"\n    [ERROR] Download Failed! {e}", Colors.FAIL)
        if dest_path.exists(): dest_path.unlink()
        return False

def generate_files():
    print_color("\n>>> GENERATING CONFIGURATION FILES...", Colors.YELLOW)

    # 3A. PRESEED.CFG
    with open(BASE_DIR / "http" / "preseed.cfg", "w") as f:
        f.write("""d-i debian-installer/locale string en_US
d-i keyboard-configuration/xkb-keymap select us
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string Lab-Web01
d-i netcfg/get_domain string local
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
d-i passwd/root-login boolean false
d-i passwd/user-fullname string vagrant
d-i passwd/username string vagrant
d-i passwd/user-password password vagrant
d-i passwd/user-password-again password vagrant
d-i clock-setup/utc boolean true
d-i time/zone string UTC
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string sudo curl
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/sda
d-i preseed/late_command string \\
    echo 'vagrant ALL=(ALL) NOPASSWD: ALL' > /target/etc/sudoers.d/vagrant; \\
    chmod 440 /target/etc/sudoers.d/vagrant;
d-i finish-install/reboot_in_progress note
""")

    # 3B. PLUGINS.PKR.HCL
    with open(BASE_DIR / "plugins.pkr.hcl", "w") as f:
        f.write("""packer {
  required_plugins {
    virtualbox = {
      version = ">= 1.0.5"
      source  = "github.com/hashicorp/virtualbox"
    }
  }
}
""")

    # 3C. AUTOUNATTEND.XML
    with open(BASE_DIR / "answer_files" / "Autounattend.xml", "w") as f:
        f.write("""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
            <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DiskConfiguration>
                <Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk><CreatePartitions><CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition></CreatePartitions><ModifyPartitions><ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Active>true</Active><Format>NTFS</Format><Label>Windows</Label></ModifyPartition></ModifyPartitions></Disk>
            </DiskConfiguration>
            <ImageInstall>
                <OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>2</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage>
            </ImageInstall>
            <UserData><AcceptEula>true</AcceptEula></UserData>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <AutoLogon>
                <Password><Value>Vagrant!123</Value><PlainText>true</PlainText></Password>
                <Enabled>true</Enabled>
                <Username>vagrant</Username>
            </AutoLogon>
            <OOBE><HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
            <UserAccounts>
                <AdministratorPassword><Value>Vagrant!123</Value><PlainText>true</PlainText></AdministratorPassword>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Password><Value>Vagrant!123</Value><PlainText>true</PlainText></Password>
                        <Name>vagrant</Name>
                        <Group>Administrators</Group>
                        <DisplayName>vagrant</DisplayName>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add"><Order>1</Order><CommandLine>cmd.exe /c winrm quickconfig -q</CommandLine></SynchronousCommand>
                <SynchronousCommand wcm:action="add"><Order>2</Order><CommandLine>cmd.exe /c winrm set winrm/config/service @{AllowUnencrypted="true"}</CommandLine></SynchronousCommand>
                <SynchronousCommand wcm:action="add"><Order>3</Order><CommandLine>cmd.exe /c winrm set winrm/config/service/auth @{Basic="true"}</CommandLine></SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
""")

    # =========================================================================
    # GENERATE DC01.PKR.HCL
    # =========================================================================
    iso_path_win = (BASE_DIR / WS2022_TARGET_NAME).as_uri()
    
    # 1. Base Setup
    dc_base_script = [
        "Set-ExecutionPolicy Bypass -Scope Process -Force",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "Rename-Computer -NewName 'DC01' -Force",
        "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072",
        "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    ]

    # 2. Software (Retry Logic)
    dc_soft_script = [
        "choco install git -y --no-progress",
        "$max=3; $i=0; while($i -lt $max){ try { choco install sql-server-express -y --execution-timeout=3600; break } catch { $i++; Start-Sleep 10 } }",
        "if (-not (Get-Service 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue)) { Write-Error 'SQL Server install failed'; exit 1 }",
        "choco install xampp -y --no-progress",
        "C:\\xampp\\apache\\bin\\httpd.exe -k install",
        # Move XAMPP to 8080
        "(Get-Content 'C:\\xampp\\apache\\conf\\httpd.conf') -replace 'Listen 80', 'Listen 8080' | Set-Content 'C:\\xampp\\apache\\conf\\httpd.conf'",
        "(Get-Content 'C:\\xampp\\apache\\conf\\httpd.conf') -replace 'ServerName localhost:80', 'ServerName localhost:8080' | Set-Content 'C:\\xampp\\apache\\conf\\httpd.conf'",
        "Start-Service 'Apache2.4'"
    ]

    # 3. Domain Promo
    dc_ad_script = [
        "Install-WindowsFeature AD-Domain-Services -IncludeManagementTools",
        "Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools",
        "Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools",
        "Import-Module ADDSDeployment",
        "Install-ADDSForest -DomainName 'lab.local' -DomainNetbiosName 'LAB' -SafeModeAdministratorPassword (ConvertTo-SecureString 'Vulnerable123!' -AsPlainText -Force) -InstallDns:$true -NoRebootOnCompletion:$true -Force:$true"
    ]

    # 4. AD CS Config
    dc_adcs_script = [
        "Import-Module ActiveDirectory",
        "try { Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -CACommonName 'lab-DC01-CA' -Force } catch { Write-Host 'CA Exists' }",
        "try { Install-AdcsWebEnrollment -Force } catch { Write-Host 'Web Enrollment Exists' }",
        # IIS on Port 80
        "Get-WebBinding -Port 80 -Name 'Default Web Site' -Protocol http"
    ]

    # 5. Core Vulns
    dc_vuln_script = [
        "Install-Module -Name SqlServer -Force -AllowClobber",
        "$sqlPath = 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\*\\MSSQLServer\\SuperSocketNetLib\\Tcp\\IPAll'",
        "$tcpKey = Get-Item $sqlPath | Select-Object -First 1",
        "New-ItemProperty -Path $tcpKey.PSPath -Name 'TcpPort' -Value '1433' -PropertyType String -Force",
        "Stop-Service 'MSSQL$SQLEXPRESS' -Force; Start-Service 'MSSQL$SQLEXPRESS'",
        # Users
        "New-ADUser -Name svc_sql -SamAccountName svc_sql -AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true",
        "New-ADUser -Name svc_backup -SamAccountName svc_backup -AccountPassword (ConvertTo-SecureString 'Backup2024!' -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true",
        "New-ADUser -Name helpdesk -SamAccountName helpdesk -AccountPassword (ConvertTo-SecureString 'Help123!' -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true",
        # Vulns
        "Set-ADUser -Identity svc_backup -DoesNotRequirePreAuth $true",
        "Set-ADUser -Identity svc_sql -ServicePrincipalNames @{Add='MSSQLSvc/dc01.lab.local:1433'}",
        # DB Setup
        "Invoke-Sqlcmd -Query \"CREATE DATABASE HR_DB;\" -ServerInstance 'localhost\\SQLEXPRESS'",
        "Invoke-Sqlcmd -Query \"USE HR_DB; CREATE TABLE Employees (ID INT, Name VARCHAR(100), Salary INT, SSN VARCHAR(20)); INSERT INTO Employees VALUES (1, 'Alice Manager', 90000, '000-00-1234'), (2, 'Bob User', 50000, '000-00-5678');\" -ServerInstance 'localhost\\SQLEXPRESS'",
        "Invoke-Sqlcmd -Query \"CREATE LOGIN [LAB\\svc_sql] FROM WINDOWS; USE HR_DB; CREATE USER [LAB\\svc_sql] FOR LOGIN [LAB\\svc_sql]; ALTER ROLE [db_owner] ADD MEMBER [LAB\\svc_sql];\" -ServerInstance 'localhost\\SQLEXPRESS'",
        # PHP Portal (ODBC)
        "New-Item -Path 'C:\\xampp\\htdocs\\hr_portal' -ItemType Directory -Force",
        "(Get-Content 'C:\\xampp\\php\\php.ini') -replace ';extension=odbc', 'extension=odbc' | Set-Content 'C:\\xampp\\php\\php.ini'",
        "$php = @\"",
        "<?php",
        "  $server = 'localhost\\SQLEXPRESS';",
        "  $conn = odbc_connect(\"Driver={SQL Server};Server=$server;Database=HR_DB\", 'LAB\\svc_sql', 'Password123!');",
        "  $id = $_GET['id'];",
        "  if (!$conn) { die('Connection failed: ' . odbc_errormsg()); }",
        "  $sql = \"SELECT Name, Salary FROM Employees WHERE ID = \" . $id;",
        "  $result = odbc_exec($conn, $sql);",
        "  if(!$result) { die('Query failed'); }",
        "  while($row = odbc_fetch_array($result)) { echo 'Name: '.$row['Name'].'<br>'; }",
        "?>",
        "\"@",
        "Set-Content -Path 'C:\\xampp\\htdocs\\hr_portal\\index.php' -Value $php",
        # Fake Cloud
        "New-Item -Path 'C:\\Program Files\\Azure AD Sync' -ItemType Directory -Force",
        "$xml = @\"",
        "<AzureADSyncConfig><PasswordEncrypted>VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==</PasswordEncrypted></AzureADSyncConfig>",
        "\"@",
        "Set-Content -Path 'C:\\Program Files\\Azure AD Sync\\connection.xml' -Value $xml",
        # Firewall
        "New-NetFirewallRule -DisplayName 'Allow HTTP' -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow",
        "New-NetFirewallRule -DisplayName 'Allow HTTP 8080' -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow",
        "New-NetFirewallRule -DisplayName 'Allow MSSQL' -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow",
        "New-NetFirewallRule -DisplayName 'Allow RDP' -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow"
    ]

    # 6. Advanced Scenarios
    dc_adv_script = [
        "Write-Host '>>> DEPLOYING ADVANCED SCENARIOS...'",
        "$csc = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe'",
        # AMSI
        "New-Item -Path 'C:\\Tools\\AMSILab' -ItemType Directory -Force",
        "$amsi = @\"",
        "Add-Type -TypeDefinition @'",
        "using System; using System.Runtime.InteropServices;",
        "public class AMSITest { [DllImport(\"amsi.dll\")] public static extern int AmsiInitialize(string appName, out IntPtr ctx); }",
        "'@",
        "\"@",
        "Set-Content -Path 'C:\\Tools\\AMSILab\\vuln.ps1' -Value $amsi",
        # VEH
        "New-Item -Path 'C:\\Tools\\VEHLab' -ItemType Directory -Force",
        "$veh = @\"",
        "using System; using System.Threading;",
        "class FakeEDR { static void Main() { Console.WriteLine(\"FakeEDR Running...\"); while(true) Thread.Sleep(1000); } }",
        "\"@",
        "Set-Content -Path 'C:\\Tools\\VEHLab\\FakeEDR.cs' -Value $veh",
        "Invoke-Expression \"& $csc /out:C:\\Tools\\VEHLab\\FakeEDR.exe C:\\Tools\\VEHLab\\FakeEDR.cs\"",
        # Creds
        "New-Item -Path 'C:\\Tools\\CredLab' -ItemType Directory -Force",
        "reg save HKLM\\SAM C:\\Tools\\CredLab\\SAM.bak",
        "reg save HKLM\\SYSTEM C:\\Tools\\CredLab\\SYSTEM.bak",
        "reg save HKLM\\SECURITY C:\\Tools\\CredLab\\SECURITY.bak"
    ]

    # 7. IP Staging
    dc_ip_script = [
        "Unregister-ScheduledTask -TaskName 'SetStaticIP' -Confirm:$false -ErrorAction SilentlyContinue",
        "$lines = @(",
        "  '$ip = ''10.0.0.10''',",
        "  '$prefix = 24',",
        "  '$gw = ''''',",
        "  '$dns = ''127.0.0.1''',",
        "  '$adapter = Get-NetAdapter | Where-Object Status -eq ''Up'' | Select-Object -First 1',",
        "  'New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $ip -PrefixLength $prefix -DefaultGateway $gw -ErrorAction SilentlyContinue',",
        "  'Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dns',",
        "  'Unregister-ScheduledTask -TaskName ''SetStaticIP'' -Confirm:$false',",
        "  'Remove-Item -Path ''C:\\Set-StaticIP.ps1'' -Force'",
        ")",
        "Set-Content -Path 'C:\\Set-StaticIP.ps1' -Value $lines",
        "$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-ExecutionPolicy Bypass -File C:\\Set-StaticIP.ps1'",
        "$trigger = New-ScheduledTaskTrigger -AtStartup",
        "Register-ScheduledTask -Action $action -Trigger $trigger -TaskName 'SetStaticIP' -User 'SYSTEM' -RunLevel Highest"
    ]

    with open(BASE_DIR / "dc01.pkr.hcl", "w") as f:
        f.write(f"""
source "virtualbox-iso" "dc01" {{
  cpus                 = 2
  memory               = 6144
  disk_size            = 81920
  iso_checksum         = "none"
  headless             = false
  communicator         = "winrm"
  winrm_username       = "vagrant"
  winrm_password       = "Vagrant!123"
  winrm_timeout        = "1h"
  firmware             = "bios"
  boot_wait            = "3s"
  boot_command         = ["<enter><wait><enter><wait><enter><wait><enter>"]
  floppy_files         = ["./answer_files/Autounattend.xml"]
  shutdown_command     = "shutdown /s /t 10 /f"
  shutdown_timeout     = "60m"
  vm_name              = "Lab-DC01"
  guest_os_type        = "Windows2019_64"
  iso_url              = "{iso_path_win}"
  guest_additions_mode = "disable"
  skip_export          = true
  keep_registered      = true
}}

build {{
  sources = ["source.virtualbox-iso.dc01"]
  provisioner "powershell" {{ inline = {to_hcl(dc_base_script)} }}
  provisioner "windows-restart" {{ restart_timeout = "15m" }}
  provisioner "powershell" {{ inline = {to_hcl(dc_soft_script)} }}
  provisioner "windows-restart" {{ restart_timeout = "15m" }}
  provisioner "powershell" {{ inline = {to_hcl(dc_ad_script)} }}
  provisioner "windows-restart" {{ restart_timeout = "30m" }}
  provisioner "powershell" {{ inline = {to_hcl(dc_adcs_script)} }}
  provisioner "powershell" {{ inline = {to_hcl(dc_vuln_script)} }}
  provisioner "powershell" {{ inline = {to_hcl(dc_adv_script)} }}
  provisioner "powershell" {{ inline = {to_hcl(dc_ip_script)} }}
}}
""")

    # =========================================================================
    # GENERATE WEB01.PKR.HCL
    # =========================================================================
    iso_path_deb = (BASE_DIR / DEBIAN_TARGET_NAME).as_uri()

    web_base_script = [
        "sudo apt-get update",
        "sudo apt-get install -y curl gnupg net-tools python3-flask python3-pip gcc make libcap2-bin vim auditd audispd-plugins samba",
        # Docker
        "curl -fsSL https://get.docker.com -o get-docker.sh",
        "sudo sh get-docker.sh",
        "sudo usermod -aG docker vagrant",
        "sudo systemctl enable docker; sudo systemctl start docker",
        # K3s
        "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--disable=traefik' sh -",
        "mkdir -p /home/vagrant/.kube",
        "sudo cp /etc/rancher/k3s/k3s.yaml /home/vagrant/.kube/config",
        "sudo chown vagrant:vagrant /home/vagrant/.kube/config",
        # Samba
        "echo '[share]' | sudo tee -a /etc/samba/smb.conf",
        "echo 'path = /home/vagrant/share' | sudo tee -a /etc/samba/smb.conf",
        "echo 'read only = no' | sudo tee -a /etc/samba/smb.conf",
        "mkdir -p /home/vagrant/share && chmod 777 /home/vagrant/share",
        "sudo systemctl restart smbd"
    ]

    web_ai_script = [
        "mkdir -p /home/vagrant/ai_agent",
        r'printf "from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n@app.route(\"/\")\ndef home(): return \"Insecure AI\"\n@app.route(\"/ask\")\ndef ask():\n    q = request.args.get(\"query\", \"\")\n    try:\n        out = subprocess.check_output(q, shell=True, stderr=subprocess.STDOUT)\n        return f\"<pre>{out.decode()}</pre>\"\n    except Exception as e: return str(e)\nif __name__ == \"__main__\": app.run(host=\"0.0.0.0\", port=5000)\n" > /home/vagrant/ai_agent/app.py',
        r'printf "[Unit]\nDescription=AI\nAfter=network.target\n[Service]\nUser=root\nWorkingDirectory=/home/vagrant/ai_agent\nExecStart=/usr/bin/python3 app.py\nRestart=always\n[Install]\nWantedBy=multi-user.target\n" | sudo tee /etc/systemd/system/ai_agent.service',
        "sudo systemctl daemon-reload",
        "sudo systemctl enable ai_agent",
        "sudo systemctl start ai_agent"
    ]

    web_api_script = [
        "sudo docker run -d --restart unless-stopped -p 3000:3000 bkimminich/juice-shop",
        "sudo docker run -d --restart unless-stopped -p 5002:80 roottusk/vapi",
        "mkdir -p ~/crapi",
        "cd ~/crapi",
        "curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/v1.0.0/deploy/docker/docker-compose.yml",
        "sudo docker compose pull",
        "sudo docker compose -f docker-compose.yml up -d || echo 'Docker Compose Failed'",
        # Network
        "IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)",
        "echo \"auto $IFACE\" | sudo tee -a /etc/network/interfaces",
        "echo \"iface $IFACE inet static\" | sudo tee -a /etc/network/interfaces",
        "echo '  address 10.0.0.20/24' | sudo tee -a /etc/network/interfaces"
    ]

    web_adv_script = [
        "mkdir -p /home/vagrant/container_lab",
        r'printf "version: \"3\"\nservices:\n  vuln_priv:\n    image: ubuntu:latest\n    privileged: true\n    command: sleep infinity\n  vuln_sock:\n    image: ubuntu:latest\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    command: sleep infinity\n" > /home/vagrant/container_lab/docker-compose-vuln.yml',
        "cd /home/vagrant/container_lab && sudo docker compose -f docker-compose-vuln.yml up -d || exit 1",
        # K8s
        "echo 'Waiting for K3s...'",
        "until sudo kubectl get nodes 2>/dev/null | grep -q ' Ready'; do sleep 5; done",
        "mkdir -p /home/vagrant/k8s_lab",
        r'printf "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: vuln-sa\n  namespace: default\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: vuln-binding\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n- kind: ServiceAccount\n  name: vuln-sa\n  namespace: default\n" > /home/vagrant/k8s_lab/vuln.yaml',
        "sudo kubectl apply -f /home/vagrant/k8s_lab/vuln.yaml",
        # PrivEsc
        "echo 'vagrant ALL=(ALL) NOPASSWD: /usr/bin/vim' | sudo tee -a /etc/sudoers.d/vuln_sudo",
        "sudo cp /usr/bin/python3 /usr/local/bin/python_cap",
        "sudo setcap cap_setuid+ep /usr/local/bin/python_cap"
    ]

    with open(BASE_DIR / "web01.pkr.hcl", "w") as f:
        f.write(f"""
source "virtualbox-iso" "web01" {{
  vm_name              = "Lab-Web01"
  guest_os_type        = "Debian_64"
  iso_url              = "{iso_path_deb}"
  iso_checksum         = "none"
  cpus                 = 2
  memory               = 4096
  disk_size            = 40000
  headless             = false
  shutdown_command     = "echo 'vagrant' | sudo -S shutdown -P now"
  ssh_username         = "vagrant"
  ssh_password         = "vagrant"
  ssh_timeout          = "30m"
  ssh_pty              = true
  nic_type             = "virtio"
  firmware             = "bios"
  boot_wait            = "5s"
  boot_command = [
    "<esc><wait>",
    "auto url=http://{{{{ .HTTPIP }}}}:{{{{ .HTTPPort }}}}/preseed.cfg ",
    "<enter>"
  ]
  http_directory = "http"
  vboxmanage = [["modifyvm", "{{{{.Name}}}}", "--nat-localhostreachable1", "on"]]
  skip_export          = true
  keep_registered      = true
}}

build {{
  sources = ["source.virtualbox-iso.web01"]
  provisioner "shell" {{ inline = {to_hcl(web_base_script)} }}
  provisioner "shell" {{ inline = {to_hcl(web_ai_script)} }}
  provisioner "shell" {{ inline = {to_hcl(web_api_script)} }}
  provisioner "shell" {{ inline = {to_hcl(web_adv_script)} }}
}}
""")

# ============================================================================
# MAIN
# ============================================================================
def main():
    print_color("==================================================================", Colors.CYAN)
    print_color("        MODERN KILL LAB - MASTER BUILDER (Auto-Install)           ", Colors.CYAN)
    print_color("==================================================================", Colors.CYAN)
    
    # 1. DEPENDENCY CHECK
    dm = DependencyManager()
    print(f"Platform: {dm.os_type}")
    if not dm.check_packer(): return
    vbox = dm.check_vbox()
    if vbox is False: return

    BASE_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "answer_files").mkdir(exist_ok=True)
    (BASE_DIR / "scripts").mkdir(exist_ok=True)
    (BASE_DIR / "http").mkdir(exist_ok=True)
    os.chdir(BASE_DIR)

    # 2. ISO CHECKS
    ws2022_path = BASE_DIR / WS2022_TARGET_NAME
    if not ws2022_path.exists():
        print_color(f"\n[-] '{WS2022_TARGET_NAME}' is missing.", Colors.YELLOW)
        if input("    [?] Download Windows Server 2022? (y/n): ").lower() == 'y':
            if not download_file(WS2022_URL, ws2022_path): return
    else: print_color(f"    [CHECK] {WS2022_TARGET_NAME} found.", Colors.GREEN)

    debian_path = BASE_DIR / DEBIAN_TARGET_NAME
    if not debian_path.exists():
        download_file(DEBIAN_URL, debian_path)
    else: print_color(f"    [CHECK] {DEBIAN_TARGET_NAME} found.", Colors.GREEN)

    # 3. VM CHECKS
    nuke_vm("Lab-DC01")
    nuke_vm("Lab-Web01")
    
    # 4. BUILD
    generate_files()
    print_color("\n>>> STARTING PACKER BUILDS...", Colors.YELLOW)
    subprocess.run(["packer", "init", "."], shell=(dm.os_type=="Windows"))

    print_color("\n    [BUILD] DC01...", Colors.CYAN)
    subprocess.call(["packer", "build", "-force", "dc01.pkr.hcl"], shell=(dm.os_type=="Windows"))

    print_color("\n    [BUILD] Web01...", Colors.CYAN)
    subprocess.call(["packer", "build", "-force", "web01.pkr.hcl"], shell=(dm.os_type=="Windows"))

    # 5. NETWORKING
    vbox_cmd = "VBoxManage"
    if dm.os_type == "Windows" and not shutil.which("VBoxManage"):
        vbox_cmd = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
        
    print_color("\n>>> CONFIGURING NETWORK...", Colors.YELLOW)
    for vm in ["Lab-DC01", "Lab-Web01"]:
        subprocess.run([vbox_cmd, "modifyvm", vm, "--nic1", "intnet", "--intnet1", "psycholab"], stderr=subprocess.DEVNULL)

    # 6. SUMMARY
    print_color("\n==================================================================", Colors.CYAN)
    print_color("                  LAB ACCESS CREDENTIALS                          ", Colors.CYAN)
    print_color("==================================================================", Colors.CYAN)
    print("Lab-DC01     10.0.0.10       LAB\\vagrant        Vagrant!123")
    print("                             Legacy HR Portal   http://10.0.0.10:8080/hr_portal")
    print("                             AD CS Web          http://10.0.0.10/certsrv")
    print("")
    print("Lab-Web01    10.0.0.20       vagrant            vagrant")
    print_color("==================================================================", Colors.GREEN)

if __name__ == "__main__":
    main()
