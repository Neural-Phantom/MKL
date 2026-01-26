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
    GRAY = '\033[90m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_color(text, color=Colors.ENDC):
    print(f"{color}{text}{Colors.ENDC}")

# ============================================================================
# DEPENDENCY MANAGER
# ============================================================================
class DependencyManager:
    def __init__(self):
        self.os_type = platform.system()
        self.distro = self._get_linux_distro() if self.os_type == "Linux" else None
        self.pkg_manager = self._identify_pkg_manager()
        
    def _get_linux_distro(self):
        try:
            with open("/etc/os-release") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("ID="):
                        return line.strip().split("=")[1].strip('"')
                    if line.startswith("ID_LIKE="):
                        val = line.strip().split("=")[1].strip('"')
                        if "arch" in val: return "arch"
                        if "debian" in val or "ubuntu" in val: return "debian"
        except:
            return "unknown"
        return "unknown"

    def _identify_pkg_manager(self):
        if self.os_type == "Windows": return "winget"
        if self.os_type == "Darwin": return "brew"
        if self.os_type == "Linux":
            if self.distro in ["arch", "catchyos", "manjaro"]: return "pacman"
            if self.distro in ["debian", "ubuntu", "kali", "pop"]: return "apt"
            if self.distro in ["fedora", "centos", "rhel"]: return "dnf"
        return None

    def _run_install(self, package_map):
        mgr = self.pkg_manager
        pkg_name = package_map.get(mgr)
        if not pkg_name: return False
        
        print_color(f"    [INSTALL] Installing '{pkg_name}' via {mgr}...", Colors.CYAN)
        cmd = []
        if mgr == "winget": cmd = ["winget", "install", "-e", "--id", pkg_name]
        elif mgr == "brew": cmd = ["brew", "install", "--cask", pkg_name] if "virtualbox" in pkg_name else ["brew", "install", pkg_name]
        elif mgr == "pacman": cmd = ["sudo", "pacman", "-S", "--noconfirm", pkg_name]
        elif mgr == "apt": cmd = ["sudo", "apt-get", "install", "-y", pkg_name]
        elif mgr == "dnf": cmd = ["sudo", "dnf", "install", "-y", pkg_name]

        try:
            subprocess.run(cmd, check=True)
            print_color(f"    [SUCCESS] {pkg_name} installed.", Colors.GREEN)
            return True
        except:
            print_color(f"    [ERROR] Install failed for {pkg_name}.", Colors.FAIL)
            return False

    def check_packer(self):
        if shutil.which("packer"): return True
        print_color("\n[!] Packer is MISSING.", Colors.YELLOW)
        if self.pkg_manager and input(f"    Install Packer? (y/n): ").lower() == 'y':
            return self._run_install({"winget": "HashiCorp.Packer", "brew": "packer", "pacman": "packer", "apt": "packer", "dnf": "packer"})
        return False

    def check_vbox(self):
        if self.os_type == "Windows":
            default_path = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
            if shutil.which("VBoxManage") or default_path.exists():
                return str(default_path) if default_path.exists() else "VBoxManage"
        elif shutil.which("VBoxManage"): return "VBoxManage"

        print_color("\n[!] VirtualBox is MISSING.", Colors.YELLOW)
        if self.pkg_manager and input(f"    Install VirtualBox? (y/n): ").lower() == 'y':
            if self._run_install({"winget": "Oracle.VirtualBox", "brew": "virtualbox", "pacman": "virtualbox virtualbox-host-modules-arch", "apt": "virtualbox", "dnf": "VirtualBox"}):
                return r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" if self.os_type == "Windows" else "VBoxManage"
        return None

# ============================================================================
# UTILITIES
# ============================================================================
def nuke_vm(vm_name, vbox_cmd):
    result = subprocess.run([vbox_cmd, "list", "vms"], capture_output=True, text=True)
    if vm_name in result.stdout:
        print_color(f"    [CLEAN] Deleting {vm_name}...", Colors.FAIL)
        subprocess.run([vbox_cmd, "controlvm", vm_name, "poweroff"], stderr=subprocess.DEVNULL)
        time.sleep(2)
        subprocess.run([vbox_cmd, "unregistervm", vm_name, "--delete"], stderr=subprocess.DEVNULL)
    
    vm_folder = BASE_DIR / "output-dc01" if "DC01" in vm_name else BASE_DIR / "output-web01"
    if vm_folder.exists(): shutil.rmtree(vm_folder, ignore_errors=True)

def download_file(url, dest_path):
    print_color(f"    [DOWNLOADING] Target: {dest_path.name}...", Colors.CYAN)
    print(f"      Source: {url}")
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
            print_color("    [ERROR] File too small. Download likely failed.", Colors.FAIL)
            dest_path.unlink()
            return False

        print_color("    [SUCCESS] Download Complete.", Colors.GREEN)
        return True
    except Exception as e:
        print_color(f"\n    [ERROR] Download Failed! {e}", Colors.FAIL)
        if dest_path.exists(): dest_path.unlink()
        return False

def generate_files():
    print_color("\n>>> GENERATING CONFIGURATION FILES...", Colors.YELLOW)

    # 3A. PRESEED.CFG
    preseed_content = """d-i debian-installer/locale string en_US
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
"""
    with open(BASE_DIR / "http" / "preseed.cfg", "w") as f: f.write(preseed_content)

    # 3B. PLUGINS.PKR.HCL
    hcl_plugins = """packer {
  required_plugins {
    virtualbox = {
      version = ">= 1.0.5"
      source  = "github.com/hashicorp/virtualbox"
    }
  }
}
"""
    with open(BASE_DIR / "plugins.pkr.hcl", "w") as f: f.write(hcl_plugins)

    # 3C. AUTOUNATTEND.XML
    xml_dc = """<?xml version="1.0" encoding="utf-8"?>
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
"""
    with open(BASE_DIR / "answer_files" / "Autounattend.xml", "w") as f: f.write(xml_dc)

    # 3D. DC01.PKR.HCL
    iso_path_win = (BASE_DIR / WS2022_TARGET_NAME).as_uri()
    
    hcl_dc = f"""
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
  
  # 1. BASE SETUP
  provisioner "powershell" {{
    inline = [
      "Set-ExecutionPolicy Bypass -Scope Process -Force",
      "Set-MpPreference -DisableRealtimeMonitoring `$true",
      "Rename-Computer -NewName 'DC01' -Force",
      "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072",
      "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    ]
  }}
  provisioner "windows-restart" {{ restart_timeout = "15m" }}
  
  # 2. SOFTWARE INSTALLATION (Hardened Retry)
  provisioner "powershell" {{ 
    inline = [
      "choco install git -y --no-progress",
      "Write-Host '>>> INSTALLING SQL SERVER (Verbose/Retry)...'",
      "$max=3; $i=0; while($i -lt $max){{ try {{ choco install sql-server-express -y --execution-timeout=3600; break }} catch {{ $i++; Start-Sleep 10 }} }}",
      "if (-not (Get-Service 'MSSQL`$SQLEXPRESS' -ErrorAction SilentlyContinue)) {{ Write-Error 'SQL Server install failed'; exit 1 }}",
      # XAMPP Install & Service Config
      "choco install xampp -y --no-progress",
      "C:\\xampp\\apache\\bin\\httpd.exe -k install",
      # Move XAMPP to 8080 to avoid IIS conflict
      "(Get-Content 'C:\\xampp\\apache\\conf\\httpd.conf') -replace 'Listen 80', 'Listen 8080' | Set-Content 'C:\\xampp\\apache\\conf\\httpd.conf'",
      "(Get-Content 'C:\\xampp\\apache\\conf\\httpd.conf') -replace 'ServerName localhost:80', 'ServerName localhost:8080' | Set-Content 'C:\\xampp\\apache\\conf\\httpd.conf'",
      "Start-Service 'Apache2.4'"
    ] 
  }}
  provisioner "windows-restart" {{ restart_timeout = "15m" }}
  
  # 3. DOMAIN CONTROLLER PROMOTION & AD CS
  provisioner "powershell" {{
    inline = [
      "Install-WindowsFeature AD-Domain-Services -IncludeManagementTools",
      "Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools",
      "Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools",
      "Import-Module ADDSDeployment",
      "Install-ADDSForest -DomainName 'lab.local' -DomainNetbiosName 'LAB' -SafeModeAdministratorPassword (ConvertTo-SecureString 'Vulnerable123!' -AsPlainText -Force) -InstallDns:`$true -NoRebootOnCompletion:`$true -Force:`$true"
    ]
  }}
  provisioner "windows-restart" {{ restart_timeout = "30m" }}

  # 4. AD CS CONFIGURATION
  provisioner "powershell" {{
    inline = [
      "Import-Module ActiveDirectory",
      "try {{ Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -CACommonName 'lab-DC01-CA' -Force }} catch {{ Write-Host 'CA Exists' }}",
      "try {{ Install-AdcsWebEnrollment -Force }} catch {{ Write-Host 'Web Enrollment Exists' }}",
      # IIS stays on Port 80 for AD CS
      "Get-WebBinding -Port 80 -Name 'Default Web Site' -Protocol http" 
    ]
  }}
  
  # 5. CORE VULNERABLE CONFIGURATION
  provisioner "powershell" {{
    inline = [
      "Write-Host '>>> CONFIGURING USERS & SERVICES...'",
      # A. SQL Server Config
      "Install-Module -Name SqlServer -Force -AllowClobber",
      "`$sqlPath = 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\*\\MSSQLServer\\SuperSocketNetLib\\Tcp\\IPAll'",
      "`$tcpKey = Get-Item `$sqlPath | Select-Object -First 1",
      "New-ItemProperty -Path `$tcpKey.PSPath -Name 'TcpPort' -Value '1433' -PropertyType String -Force",
      "Stop-Service 'MSSQL`$SQLEXPRESS' -Force; Start-Service 'MSSQL`$SQLEXPRESS'",
      
      # B. Create Users
      "New-ADUser -Name svc_sql -SamAccountName svc_sql -AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Enabled `$true -PasswordNeverExpires `$true",
      "New-ADUser -Name svc_backup -SamAccountName svc_backup -AccountPassword (ConvertTo-SecureString 'Backup2024!' -AsPlainText -Force) -Enabled `$true -PasswordNeverExpires `$true",
      "New-ADUser -Name helpdesk -SamAccountName helpdesk -AccountPassword (ConvertTo-SecureString 'Help123!' -AsPlainText -Force) -Enabled `$true -PasswordNeverExpires `$true",
      "Set-ADUser -Identity svc_backup -DoesNotRequirePreAuth `$true",
      "Set-ADUser -Identity svc_sql -ServicePrincipalNames @{{Add='MSSQLSvc/dc01.lab.local:1433'}}",
      
      # C. SQL DB Setup
      "Invoke-Sqlcmd -Query \\"CREATE DATABASE HR_DB;\\" -ServerInstance 'localhost\\SQLEXPRESS'",
      "Invoke-Sqlcmd -Query \\"USE HR_DB; CREATE TABLE Employees (ID INT, Name VARCHAR(100), Salary INT, SSN VARCHAR(20)); INSERT INTO Employees VALUES (1, 'Alice Manager', 90000, '000-00-1234'), (2, 'Bob User', 50000, '000-00-5678');\\" -ServerInstance 'localhost\\SQLEXPRESS'",
      "Invoke-Sqlcmd -Query \\"CREATE LOGIN [LAB\\\\svc_sql] FROM WINDOWS; USE HR_DB; CREATE USER [LAB\\\\svc_sql] FOR LOGIN [LAB\\\\svc_sql]; ALTER ROLE [db_owner] ADD MEMBER [LAB\\\\svc_sql];\\" -ServerInstance 'localhost\\SQLEXPRESS'",
      
      # D. DEPLOY LEGACY HR PORTAL (PHP+ODBC)
      # Hardened: Using ODBC to avoid php_sqlsrv.dll missing driver issues
      "New-Item -Path 'C:\\xampp\\htdocs\\hr_portal' -ItemType Directory -Force",
      "(Get-Content 'C:\\xampp\\php\\php.ini') -replace ';extension=odbc', 'extension=odbc' | Set-Content 'C:\\xampp\\php\\php.ini'",
      "$php_code = @(",
      "  '<?php',",
      "  '$serverName = \"localhost\\SQLEXPRESS\";',",
      "  '$conn = odbc_connect(\"Driver={{SQL Server}};Server=$serverName;Database=HR_DB\", \"LAB\\\\svc_sql\", \"Password123!\");',",
      "  '$id = $_GET[\"id\"];',",
      "  'if (!$conn) {{ die(\"Connection failed: \" . odbc_errormsg()); }}',",
      "  '// VULNERABILITY: SQL Injection',",
      "  '$sql = \"SELECT Name, Salary FROM Employees WHERE ID = \" . $id;',",
      "  '$result = odbc_exec($conn, $sql);',",
      "  'if(!$result) {{ die(\"Query failed\"); }}',",
      "  'while($row = odbc_fetch_array($result)) {{ echo \"Name: \".$row[\"Name\"].\"<br>\"; }}',",
      "  '?>'",
      ")",
      "Set-Content -Path 'C:\\xampp\\htdocs\\hr_portal\\index.php' -Value $php_code",

      # E. FAKE CLOUD SYNC
      "New-Item -Path 'C:\\Program Files\\Azure AD Sync' -ItemType Directory -Force",
      "$cloud_xml = @(",
      "  '<AzureADSyncConfig>',",
      "  '  <TenantId>33e01f21-7890-4444-99a2-555555555555</TenantId>',",
      "  '  <ServiceAccount>svc_adsync@lab.local</ServiceAccount>',",
      "  '  <PasswordEncrypted>VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==</PasswordEncrypted>',",
      "  '  <Comment>Base64 Encoded (Valhalla123!) - Reversible credential storage</Comment>',",
      "  '</AzureADSyncConfig>'",
      ")",
      "Set-Content -Path 'C:\\Program Files\\Azure AD Sync\\connection.xml' -Value $cloud_xml",
      
      # F. Firewall Rules
      "New-NetFirewallRule -DisplayName 'Allow HTTP' -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow",
      "New-NetFirewallRule -DisplayName 'Allow HTTP 8080' -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow",
      "New-NetFirewallRule -DisplayName 'Allow MSSQL' -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow",
      "New-NetFirewallRule -DisplayName 'Allow RDP' -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow"
    ]
  }}

  # 6. ADVANCED OFFENSIVE LABS
  provisioner "powershell" {{
    inline = [
      "Write-Host '>>> DEPLOYING ADVANCED OFFENSIVE SCENARIOS...'",
      "`$csc = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe'",
      
      # 1. AMSI BYPASS LAB
      "New-Item -Path 'C:\\Tools\\AMSILab' -ItemType Directory -Force",
      "$amsi_vuln = @'",
      "Add-Type -TypeDefinition @\"",
      "using System;",
      "using System.Runtime.InteropServices;",
      "public class AMSITest {{",
      "    [DllImport(\"amsi.dll\")]",
      "    public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);",
      "}}",
      "\"@",
      "# Lab: Patch amsi.dll in memory",
      "'@",
      "Set-Content -Path 'C:\\Tools\\AMSILab\\vulnerable_loader.ps1' -Value $amsi_vuln",
      "$acl = Get-Acl 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers'",
      "$rule = New-Object System.Security.AccessControl.RegistryAccessRule('BUILTIN\\Users','FullControl','Allow')",
      "$acl.SetAccessRule($rule)",
      "Set-Acl 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers' $acl",
      
      # 2. VEH BYPASS LAB
      "New-Item -Path 'C:\\Tools\\VEHLab' -ItemType Directory -Force",
      "$veh_monitor = @'",
      "using System;",
      "using System.Runtime.InteropServices;",
      "class FakeEDR {{",
      "    [DllImport(\"kernel32.dll\")]",
      "    static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);",
      "    static void Main() {{",
      "        Console.WriteLine(\"[FakeEDR] Monitoring with VEH...\");",
      "        while(true) {{ System.Threading.Thread.Sleep(1000); }}",
      "    }}",
      "}}",
      "'@",
      "Set-Content -Path 'C:\\Tools\\VEHLab\\FakeEDR.cs' -Value $veh_monitor",
      "Invoke-Expression \"& $csc /out:C:\\Tools\\VEHLab\\FakeEDR.exe C:\\Tools\\VEHLab\\FakeEDR.cs\"",
      "if (-not (Test-Path 'C:\\Tools\\VEHLab\\FakeEDR.exe')) {{ Write-Warning 'FakeEDR.exe compilation failed' }}",
      
      # 3. REFLECTIVE INJECTION
      "New-Item -Path 'C:\\Tools\\ReflectiveLab' -ItemType Directory -Force",
      "icacls 'C:\\Tools\\ReflectiveLab' /grant 'BUILTIN\\Users:(OI)(CI)F'",
      "$reflect_app = @'",
      "using System;",
      "using System.Reflection;",
      "using System.IO;",
      "class VulnerableLoader {{",
      "    static void Main(string[] args) {{",
      "        if (args.Length > 0) {{",
      "            byte[] assemblyBytes = File.ReadAllBytes(args[0]);",
      "            Assembly asm = Assembly.Load(assemblyBytes);",
      "            asm.EntryPoint.Invoke(null, null);",
      "        }}",
      "    }}",
      "}}",
      "'@",
      "Set-Content -Path 'C:\\Tools\\ReflectiveLab\\VulnerableLoader.cs' -Value $reflect_app",
      
      # 4. PROCESS HOLLOWING
      "New-Item -Path 'C:\\Tools\\HollowingLab' -ItemType Directory -Force",
      "$hollow_targets = @'",
      "TARGETS:",
      "EASY: notepad.exe",
      "MEDIUM: svchost.exe",
      "HARD: werfault.exe",
      "'@",
      "Set-Content -Path 'C:\\Tools\\HollowingLab\\README.txt' -Value $hollow_targets",
      
      # 5. CREDENTIAL DUMPING (Hardened: Create Dir First)
      "cmdkey /add:fileserver.lab.local /user:LAB\\backup_admin /pass:BackupP@ss123!",
      "cmdkey /add:sqlserver.lab.local /user:sa /pass:SQLAdm1n!",
      "New-Item -Path 'C:\\Users\\vagrant\\Documents\\Passwords' -ItemType Directory -Force",
      "New-Item -Path 'C:\\Tools\\CredLab' -ItemType Directory -Force",
      "reg save HKLM\\SAM C:\\Tools\\CredLab\\SAM.bak",
      "reg save HKLM\\SYSTEM C:\\Tools\\CredLab\\SYSTEM.bak",
      "reg save HKLM\\SECURITY C:\\Tools\\CredLab\\SECURITY.bak",
      "icacls 'C:\\Tools\\CredLab' /grant 'BUILTIN\\Users:(OI)(CI)R'",
      
      # 6. LOLBINS
      "New-Item -Path 'C:\\Tools\\LOLBinLab' -ItemType Directory -Force",
      "$msbuild_proj = @'",
      "<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">",
      "  <Target Name=\"LOLBin\"> <ClassExample /> </Target>",
      "  <UsingTask TaskName=\"ClassExample\" TaskFactory=\"CodeTaskFactory\" AssemblyFile=\"C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll\">",
      "    <Task> <Code Type=\"Class\" Language=\"cs\"> <![CDATA[",
      "      using System; using Microsoft.Build.Utilities;",
      "      public class ClassExample : Task {{ public override bool Execute() {{ Console.WriteLine(\"PWNED\"); return true; }} }}",
      "    ]]> </Code> </Task>",
      "  </UsingTask>",
      "</Project>",
      "'@",
      "Set-Content -Path 'C:\\Tools\\LOLBinLab\\payload.csproj' -Value $msbuild_proj",
      
      # 7. DRIVER LAB
      "New-Item -Path 'C:\\Tools\\DriverLab' -ItemType Directory -Force",
      "Set-Content -Path 'C:\\Tools\\DriverLab\\README.md' -Value 'Download RTCore64.sys and DBUtil_2_3.sys here for testing.'",
      
      # 8. ETW/LOGGING
      "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force",
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1",
      
      # 9. PERSISTENCE (Hardened: Unregister First)
      "New-Item -Path 'C:\\Tools\\PersistenceLab' -ItemType Directory -Force",
      "Unregister-ScheduledTask -TaskName 'WindowsDefenderUpdate' -Confirm:$false -ErrorAction SilentlyContinue",
      "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -Command \"echo persistence > C:\\Windows\\Temp\\persist.txt\"'",
      "$trigger = New-ScheduledTaskTrigger -AtLogOn",
      "$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest",
      "Register-ScheduledTask -TaskName 'WindowsDefenderUpdate' -Action $action -Trigger $trigger -Principal $principal"
    ]
  }}
  
  # 7. IP STAGING
  provisioner "powershell" {{
    inline = [
      "Write-Host '>>> STAGING STATIC IP CONFIG...'",
      "Unregister-ScheduledTask -TaskName 'SetStaticIP' -Confirm:$false -ErrorAction SilentlyContinue",
      "`$lines = @(",
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
      "Set-Content -Path 'C:\\Set-StaticIP.ps1' -Value `$lines",
      "`$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-ExecutionPolicy Bypass -File C:\\Set-StaticIP.ps1'",
      "`$trigger = New-ScheduledTaskTrigger -AtStartup",
      "Register-ScheduledTask -Action `$action -Trigger `$trigger -TaskName 'SetStaticIP' -User 'SYSTEM' -RunLevel Highest"
    ]
  }}
}}
"""
    with open(BASE_DIR / "dc01.pkr.hcl", "w") as f: f.write(hcl_dc)

    # 3E. WEB01.PKR.HCL
    iso_path_deb = (BASE_DIR / DEBIAN_TARGET_NAME).as_uri()
    
    hcl_web = f"""
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
  
  # 1. INSTALL BASE, DOCKER, K3S
  provisioner "shell" {{
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y curl gnupg net-tools python3-flask python3-pip gcc make libcap2-bin vim",
      # Docker Install
      "curl -fsSL https://get.docker.com -o get-docker.sh",
      "sudo sh get-docker.sh",
      "sudo usermod -aG docker vagrant",
      "sudo systemctl enable docker; sudo systemctl start docker",
      # K3s Install (Kubernetes) - Disabled Traefik
      "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--disable=traefik' sh -",
      "mkdir -p /home/vagrant/.kube",
      "sudo cp /etc/rancher/k3s/k3s.yaml /home/vagrant/.kube/config",
      "sudo chown vagrant:vagrant /home/vagrant/.kube/config"
    ]
  }}

  # 2. VULNERABLE AI AGENT
  provisioner "shell" {{
    inline = [
      "echo '>>> DEPLOYING INSECURE AI AGENT...'",
      "mkdir -p /home/vagrant/ai_agent",
      "printf 'from flask import Flask, request\\nimport subprocess\\napp = Flask(__name__)\\n@app.route(\"/\")\\ndef home():\\n    return \"Insecure AI Agent\"\\n@app.route(\"/ask\")\\ndef ask():\\n    query = request.args.get(\"query\", \"\")\\n    try:\\n        output = subprocess.check_output(query, shell=True, stderr=subprocess.STDOUT)\\n        return f\"<pre>{{output.decode()}}</pre>\"\\n    except Exception as e:\\n        return f\"Error: {{str(e)}}\"\\nif __name__ == \"__main__\":\\n    app.run(host=\"0.0.0.0\", port=5000)\\n' > /home/vagrant/ai_agent/app.py",
      "printf '[Unit]\\nDescription=Insecure AI Agent\\nAfter=network.target\\n[Service]\\nUser=root\\nWorkingDirectory=/home/vagrant/ai_agent\\nExecStart=/usr/bin/python3 app.py\\nRestart=always\\n[Install]\\nWantedBy=multi-user.target\\n' | sudo tee /etc/systemd/system/ai_agent.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable ai_agent",
      "sudo systemctl start ai_agent"
    ]
  }}

  # 3. API SECURITY LABS
  provisioner "shell" {{
    inline = [
      "echo '>>> DEPLOYING APPS...'",
      "sudo docker run -d --restart unless-stopped -p 3000:3000 bkimminich/juice-shop",
      "sudo docker run -d --restart unless-stopped -p 5002:80 roottusk/vapi",
      "mkdir -p ~/crapi",
      "cd ~/crapi",
      # Pinned URL to avoid upstream breakage
      "curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/v1.0.0/deploy/docker/docker-compose.yml",
      "sudo docker compose pull",
      "sudo docker compose -f docker-compose.yml up -d || echo 'Docker Compose Failed'",
      # Dynamic Interface config
      "IFACE=$(ip -o link show | awk -F': ' '{{print $2}}' | grep -v lo | head -1)",
      "echo \"auto $IFACE\" | sudo tee -a /etc/network/interfaces",
      "echo \"iface $IFACE inet static\" | sudo tee -a /etc/network/interfaces",
      "echo '  address 10.0.0.20/24' | sudo tee -a /etc/network/interfaces"
    ]
  }}

  # 4. ADVANCED CONTAINER & LINUX LABS
  provisioner "shell" {{
    inline = [
      "echo '>>> DEPLOYING ADVANCED LINUX SCENARIOS...'",
      "mkdir -p /home/vagrant/container_lab",
      "printf \"version: '3'\\nservices:\\n  vuln_privileged:\\n    image: ubuntu:latest\\n    privileged: true\\n    command: sleep infinity\\n  vuln_hostsock:\\n    image: ubuntu:latest\\n    volumes:\\n      - /var/run/docker.sock:/var/run/docker.sock\\n    command: sleep infinity\\n\" > /home/vagrant/container_lab/docker-compose-vuln.yml",
      "cd /home/vagrant/container_lab && sudo docker compose -f docker-compose-vuln.yml up -d || exit 1",
      
      # Kubernetes Vulnerabilities (Hardened Wait Loop)
      "echo 'Waiting for K3s to be ready...'",
      "until sudo kubectl get nodes 2>/dev/null | grep -q ' Ready'; do sleep 5; done",
      "echo 'K3s is Ready.'",
      "mkdir -p /home/vagrant/k8s_lab",
      "printf \"apiVersion: v1\\nkind: ServiceAccount\\nmetadata:\\n  name: vuln-admin-sa\\n  namespace: default\\n---\\napiVersion: rbac.authorization.k8s.io/v1\\nkind: ClusterRoleBinding\\nmetadata:\\n  name: vuln-admin-binding\\nroleRef:\\n  apiGroup: rbac.authorization.k8s.io\\n  kind: ClusterRole\\n  name: cluster-admin\\nsubjects:\\n- kind: ServiceAccount\\n  name: vuln-admin-sa\\n  namespace: default\\n\" > /home/vagrant/k8s_lab/vuln-sa.yaml",
      "sudo kubectl apply -f /home/vagrant/k8s_lab/vuln-sa.yaml",
      
      # Linux PrivEsc (Sudo & SUID)
      "echo 'vagrant ALL=(ALL) NOPASSWD: /usr/bin/vim' | sudo tee -a /etc/sudoers.d/vuln_sudo",
      "sudo cp /usr/bin/python3 /usr/local/bin/python_cap",
      "sudo setcap cap_setuid+ep /usr/local/bin/python_cap",
      
      # Exfil Lab
      "mkdir -p /home/vagrant/exfil_lab",
      "echo 'API_KEY=sk_live_1234567890abcdef' > /home/vagrant/exfil_lab/.env",
      "echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' >> /home/vagrant/exfil_lab/.env"
    ]
  }}
}}
"""
    with open(BASE_DIR / "web01.pkr.hcl", "w") as f: f.write(hcl_web)

# ============================================================================
# MAIN
# ============================================================================
def main():
    print_color("==================================================================", Colors.CYAN)
    print_color("        MODERN KILL LAB - MASTER BUILDER (Auto-Install)           ", Colors.CYAN)
    print_color("==================================================================", Colors.CYAN)
    
    # 1. DEPENDENCY CHECK
    dm = DependencyManager()
    print(f"Platform: {dm.os_type} ({dm.distro if dm.distro else ''})")
    
    if not dm.check_packer():
        print_color("Error: Packer is required to proceed.", Colors.FAIL)
        sys.exit(1)
        
    vbox_cmd = dm.check_vbox()
    if not vbox_cmd:
        print_color("Error: VirtualBox is required to proceed.", Colors.FAIL)
        sys.exit(1)

    print(f"Base Directory: {BASE_DIR}")
    
    # Create Directories
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "answer_files").mkdir(exist_ok=True)
    (BASE_DIR / "scripts").mkdir(exist_ok=True)
    (BASE_DIR / "http").mkdir(exist_ok=True)
    os.chdir(BASE_DIR)

    # 2. ISO CHECKS & DOWNLOADS
    ws2022_path = BASE_DIR / WS2022_TARGET_NAME
    if not ws2022_path.exists():
        print_color(f"\n[-] '{WS2022_TARGET_NAME}' is missing.", Colors.YELLOW)
        if input("    [?] Download Windows Server 2022 Evaluation now? (y/n): ").lower() == 'y':
            success = download_file(WS2022_URL, ws2022_path)
            if not success:
                print_color("\n[MANUAL ACTION REQUIRED]", Colors.FAIL)
                print("The automatic download failed. You must manually download the ISO.")
                print("1. Go to: https://go.microsoft.com/fwlink/p/?LinkID=2195174")
                print(f"2. Rename the file to: {WS2022_TARGET_NAME}")
                print(f"3. Place it in: {BASE_DIR}")
                input("Press [ENTER] when the file is in place to continue...")
                if not ws2022_path.exists():
                    print_color("File still missing. Exiting.", Colors.FAIL)
                    sys.exit(1)
        else:
            print_color("You chose not to download. Exiting.", Colors.FAIL)
            sys.exit(1)
    else:
        print_color(f"    [CHECK] {WS2022_TARGET_NAME} found.", Colors.GREEN)

    debian_path = BASE_DIR / DEBIAN_TARGET_NAME
    if not debian_path.exists():
        download_file(DEBIAN_URL, debian_path)
    else:
        print_color(f"    [CHECK] {DEBIAN_TARGET_NAME} found.", Colors.GREEN)

    # 3. EXISTING VM CHECKS
    build_dc = True
    result = subprocess.run([vbox_cmd, "list", "vms"], capture_output=True, text=True)
    if "Lab-DC01" in result.stdout:
        print_color("    [!] Found existing Domain Controller: Lab-DC01", Colors.YELLOW)
        resp = input("    [?] Keep existing DC? (y/n) [Default: y]: ").lower()
        if resp != 'n':
            print_color("    [KEEP] Preserving Lab-DC01.", Colors.GREEN)
            build_dc = False
        else:
            print_color("    [NUKE] Wiping Lab-DC01.", Colors.FAIL)
            nuke_vm("Lab-DC01", vbox_cmd)
    
    nuke_vm("Lab-Web01", vbox_cmd)
    
    # Generate files
    generate_files()

    # 4. BUILD EXECUTION
    print_color("\n>>> STARTING PACKER BUILDS...", Colors.YELLOW)
    subprocess.run(["packer", "init", "."], shell=(dm.os_type=="Windows"))

    if build_dc:
        print_color("\n    [BUILD] DC01 (Windows + AD CS + Hybrid + High Gear)...", Colors.CYAN)
        ret = subprocess.call(["packer", "build", "-force", "dc01.pkr.hcl"], shell=(dm.os_type=="Windows"))
        if ret != 0:
            print_color("DC01 Build FAILED.", Colors.FAIL)
            sys.exit(1)
    else:
        print_color("\n    [SKIP] DC01 Build Skipped.", Colors.GREEN)

    print_color("\n    [BUILD] Web01 (Debian + K3s + vAPI + AI + Containers)...", Colors.CYAN)
    ret = subprocess.call(["packer", "build", "-force", "web01.pkr.hcl"], shell=(dm.os_type=="Windows"))
    if ret != 0:
        print_color("Web01 Build FAILED.", Colors.FAIL)
        sys.exit(1)

    # 5. NETWORK CONFIGURATION
    print_color("\n>>> CONFIGURING NETWORK...", Colors.YELLOW)
    vm_list = subprocess.run([vbox_cmd, "list", "vms"], capture_output=True, text=True).stdout
    
    if "Lab-DC01" in vm_list:
        subprocess.run([vbox_cmd, "modifyvm", "Lab-DC01", "--nic1", "intnet", "--intnet1", "psycholab"], stderr=subprocess.DEVNULL)
        print_color("    [OK] Lab-DC01 Network Configured", Colors.GREEN)
        
    if "Lab-Web01" in vm_list:
        subprocess.run([vbox_cmd, "modifyvm", "Lab-Web01", "--nic1", "intnet", "--intnet1", "psycholab"], stderr=subprocess.DEVNULL)
        print_color("    [OK] Lab-Web01 Network Configured", Colors.GREEN)

    # 6. DEPLOYMENT SUMMARY
    print_color("\n==================================================================", Colors.CYAN)
    print_color("                  LAB ACCESS CREDENTIALS                          ", Colors.CYAN)
    print_color("==================================================================", Colors.CYAN)
    print_color("SYSTEM       IP ADDRESS      USERNAME           PASSWORD", Colors.YELLOW)
    print_color("-----------  --------------  -----------------  ------------------", Colors.YELLOW)
    print("Lab-DC01     10.0.0.10 (*)   LAB\\vagrant        Vagrant!123")
    print("                             LAB\\Administrator  Vagrant!123")
    print("                             LAB\\svc_sql        Password123!")
    print("                             LAB\\svc_backup     Backup2024!")
    print("                             LAB\\helpdesk       Help123!")
    print("                             AD CS Web          http://10.0.0.10/certsrv")
    print("                             Legacy HR Portal   http://10.0.0.10:8080/hr_portal")
    print("")
    print("Lab-Web01    10.0.0.20       vagrant            vagrant")
    print("                             root               (sudo su)")
    print_color("==================================================================", Colors.CYAN)
    print_color("(*) Note: Windows IP is set automatically on next boot.", Colors.GRAY)
    print_color("==================================================================", Colors.GREEN)
    print_color("                   DEPLOYMENT COMPLETE! If you get stuck check the lab guide!                           ", Colors.GREEN)
    print_color("==================================================================", Colors.GREEN)

if __name__ == "__main__":
    main()
