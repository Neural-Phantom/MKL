#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
import platform
import urllib.request
import base64
import ctypes
import socket
from pathlib import Path

# --- CONFIGURATION ---
HOME_DIR = Path(os.path.expanduser("~"))
BASE_DIR = HOME_DIR / "ModernHackingLab"

# 1. ISO CONFIGURATION
WS2022_TARGET_NAME = "ws2022.iso"
WS2022_URL = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"
WS2022_CHECKSUM = "none"

DEBIAN_TARGET_NAME = "debian.iso"
DEBIAN_URL = "https://cdimage.debian.org/cdimage/archive/12.5.0/amd64/iso-cd/debian-12.5.0-amd64-netinst.iso"
DEBIAN_CHECKSUM = "none"

class Colors:
    HEADER = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def print_color(text, color=Colors.ENDC):
    print(f"{color}{text}{Colors.ENDC}")

# ============================================================================
# HELPER: PRIVILEGE CHECK
# ============================================================================
def check_privileges():
    system = platform.system()
    try:
        if system == "Windows":
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print_color("\n[CRITICAL] WINDOWS REQUIRES ADMIN", Colors.FAIL)
                print("Please right-click and 'Run as Administrator'.")
                sys.exit(1)
        else:
            if os.geteuid() == 0:
                print_color("\n[CRITICAL] DO NOT RUN AS ROOT", Colors.FAIL)
                print("VirtualBox will crash if run with sudo.")
                print("Please run as your standard user:")
                print(f"    python3 {os.path.basename(__file__)}")
                sys.exit(1)
    except Exception as e:
        pass

# ============================================================================
# HELPER: VM STATUS CHECK
# ============================================================================
def vm_exists(vm_name):
    vbox_cmd = "VBoxManage"
    if platform.system() == "Windows" and not shutil.which("VBoxManage"):
        vbox_cmd = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    
    try:
        result = subprocess.run([vbox_cmd, "list", "vms"], capture_output=True, text=True)
        if f'"{vm_name}"' in result.stdout:
            return True
    except:
        pass
    return False

# ============================================================================
# HELPER: SYSTEM RESOURCES
# ============================================================================
def get_optimal_ram_mb():
    total_ram_mb = 4096
    try:
        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            c_ulonglong = ctypes.c_ulonglong
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong), ('ullTotalPhys', c_ulonglong), ('ullAvailPhys', c_ulonglong), ('ullTotalPageFile', c_ulonglong), ('ullAvailPageFile', c_ulonglong), ('ullTotalVirtual', c_ulonglong), ('ullAvailVirtual', c_ulonglong), ('ullAvailExtendedVirtual', c_ulonglong)]
            memoryStatus = MEMORYSTATUSEX()
            memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))
            total_ram_mb = int(memoryStatus.ullTotalPhys / (1024 * 1024))
        else:
            if platform.system() == "Darwin":
                cmd = subprocess.run(['sysctl', '-n', 'hw.memsize'], capture_output=True, text=True)
                if cmd.returncode == 0:
                    total_ram_mb = int(cmd.stdout.strip()) // (1024 * 1024)
            elif platform.system() == "Linux":
                with open('/proc/meminfo', 'r') as mem:
                    for line in mem:
                        if "MemTotal" in line: 
                            total_ram_mb = int(line.split()[1]) // 1024
                            break
    except: pass
    target = int(total_ram_mb * 0.5)
    return max(4096, min(8192, target))

def encode_file_content(content):
    return base64.b64encode(content.encode('utf-8')).decode('utf-8')

def to_hcl(lines):
    sanitized = []
    for line in lines:
        clean = line.replace('\\', '\\\\').replace('"', '\\"')
        sanitized.append(f'"{clean}"')
    return "[\n    " + ",\n    ".join(sanitized) + "\n  ]"

def wait_for_service(host, port, timeout=600):
    print_color(f"    [WAIT] Waiting for {host}:{port}...", Colors.YELLOW)
    start_time = time.time()
    while time.time() - start_time < timeout:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                print_color(f"    [OK] Service {host}:{port} is UP.", Colors.GREEN)
                sock.close()
                return True
        except:
            pass
        sock.close()
        time.sleep(2)
    print_color(f"    [FAIL] Timeout waiting for {host}:{port}", Colors.FAIL)
    return False

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
            try:
                if shutil.which("pacman"): return "pacman"
                if shutil.which("apt-get"): return "apt"
                if shutil.which("dnf"): return "dnf"
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
    vbox_cmd = "VBoxManage"
    if platform.system() == "Windows" and not shutil.which("VBoxManage"):
        vbox_cmd = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    
    # 1. Power off and delete VM
    print_color(f"    [CLEAN] Unregistering VM: {vm_name}...", Colors.CYAN)
    subprocess.run([vbox_cmd, "controlvm", vm_name, "poweroff"], stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run([vbox_cmd, "unregistervm", vm_name, "--delete"], stderr=subprocess.DEVNULL)
    
    # 2. NEW: Aggressively remove zombie media (The Fix for NS_ERROR_INVALID_ARG)
    # We construct the likely path where Packer left the stuck disk
    output_dir_name = f"output-{vm_name.lower().replace('lab-', '')}"
    potential_vdi = BASE_DIR / output_dir_name / f"{vm_name}.vdi"
    
    # We attempt to close the medium by path. If it exists in registry, this kills it.
    # If it doesn't exist, it errors silently, which is fine.
    print_color(f"    [CLEAN] purging zombie media entries...", Colors.CYAN)
    subprocess.run([vbox_cmd, "closemedium", "disk", str(potential_vdi), "--delete"], stderr=subprocess.DEVNULL)
    
    # 3. Clean up VM folders
    vbox_vm_path = None
    try:
        result = subprocess.run([vbox_cmd, "list", "systemproperties"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Default machine folder:" in line:
                path_str = line.split(":", 1)[1].strip()
                vbox_vm_path = Path(path_str) / vm_name
                break
    except: pass

    if not vbox_vm_path:
        vbox_vm_path = HOME_DIR / "VirtualBox VMs" / vm_name

    if vbox_vm_path and vbox_vm_path.exists():
        try:
            shutil.rmtree(vbox_vm_path, ignore_errors=True)
        except Exception as e:
            print_color(f"    [WARN] Failed to delete {vbox_vm_path}: {e}", Colors.YELLOW)

    # 4. Clean up Packer output directory
    output_dir = BASE_DIR / output_dir_name
    if output_dir.exists():
        shutil.rmtree(output_dir, ignore_errors=True)

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

# ============================================================================
# FILE GENERATION
# ============================================================================
def generate_files():
    print_color("\n>>> GENERATING CONFIGURATION FILES...", Colors.YELLOW)
    ram_mb = get_optimal_ram_mb()
    print_color(f"    [CONFIG] Optimized RAM Allocation: {ram_mb} MB", Colors.GREEN)

    # 3A. PRESEED
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

    # 3B. PLUGINS
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

    # 3C. AUTOUNATTEND
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
    # PAYLOAD ENCODING
    # =========================================================================
    php_src = """<?php
$server = 'localhost\\SQLEXPRESS';
$conn = odbc_connect("Driver={SQL Server};Server=$server;Database=HR_DB", 'LAB\\svc_sql', 'Password123!');
$id = $_GET['id'];
if (!$conn) { die('Connection failed: ' . odbc_errormsg()); }
$sql = "SELECT Name, Salary FROM Employees WHERE ID = " . $id;
$result = odbc_exec($conn, $sql);
if(!$result) { die('Query failed'); }
while($row = odbc_fetch_array($result)) { echo 'Name: '.$row['Name'].'<br>'; }
?>"""
    php_b64 = encode_file_content(php_src)

    xml_src = """<AzureADSyncConfig><PasswordEncrypted>VABhAGwAbABoAGEAbABsAGEAMQAyADMAIQ==</PasswordEncrypted></AzureADSyncConfig>"""
    xml_b64 = encode_file_content(xml_src)

    amsi_src = """
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class AMSITest {
    [DllImport("amsi.dll")]
    public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);
}
"@
# Lab: Patch amsi.dll in memory
"""
    amsi_b64 = encode_file_content(amsi_src)

    veh_src = """using System; using System.Threading;
class FakeEDR {
    static void Main() {
        Console.WriteLine("[FakeEDR] Monitoring with VEH...");
        while(true) { Thread.Sleep(1000); }
    }
}"""
    veh_b64 = encode_file_content(veh_src)

    msbuild_src = """<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="LOLBin"> <ClassExample /> </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
    <Task> <Code Type="Class" Language="cs"> <![CDATA[
      using System; using Microsoft.Build.Utilities;
      public class ClassExample : Task { public override bool Execute() { Console.WriteLine("PWNED"); return true; } }
    ]]> </Code> </Task>
  </UsingTask>
</Project>"""
    msbuild_b64 = encode_file_content(msbuild_src)

    # =========================================================================
    # DC01 SCRIPT ARRAYS (FIXED SSL ERROR)
    # =========================================================================
    
    dc_base = [
        "Write-Host '>>> [1/5] Configuring Execution Policy...' -ForegroundColor Cyan",
        "Set-ExecutionPolicy Bypass -Scope Process -Force",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "Rename-Computer -NewName 'DC01' -Force",
        "Write-Host '>>> [2/5] Configuring Security Protocols...' -ForegroundColor Cyan",
        "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072",
        "Write-Host '>>> [3/5] Pre-authorizing NuGet (Anti-Hang)...' -ForegroundColor Cyan",
        "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force",
        "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted",
        "Write-Host '>>> [4/5] Installing Chocolatey...' -ForegroundColor Cyan",
        "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    ]

    dc_soft = [
        "Write-Host '>>> [1/7] Installing Git...' -ForegroundColor Cyan",
        "choco install git -y --no-progress",
        "Write-Host '>>> [2/7] Installing SQL Server Express (This takes time)...' -ForegroundColor Cyan",
        "$max=3; $i=0; while($i -lt $max){ try { choco install sql-server-express -y --execution-timeout=3600; break } catch { $i++; Start-Sleep 10 } }",
        "if (-not (Get-Service 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue)) { Write-Error 'SQL Server install failed'; exit 1 }",
        "Write-Host '>>> [3/7] Installing XAMPP...' -ForegroundColor Cyan",
        "choco install xampp -y --no-progress",
        "Write-Host '>>> [4/7] Installing Apache Service...' -ForegroundColor Cyan",
        "C:\\xampp\\apache\\bin\\httpd.exe -k install",
        "Write-Host '>>> [5/7] Reconfiguring Apache to Port 8080...' -ForegroundColor Cyan",
        "(Get-Content 'C:\\xampp\\apache\\conf\\httpd.conf') -replace 'Listen 80', 'Listen 8080' | Set-Content 'C:\\xampp\\apache\\conf\\httpd.conf'",
        "(Get-Content 'C:\\xampp\\apache\\conf\\httpd.conf') -replace 'ServerName localhost:80', 'ServerName localhost:8080' | Set-Content 'C:\\xampp\\apache\\conf\\httpd.conf'",
        "Write-Host '>>> [6/7] Starting Apache...' -ForegroundColor Cyan",
        "Start-Service 'Apache2.4'"
    ]

    dc_promo = [
        "Write-Host '>>> [1/2] Installing AD DS Roles...' -ForegroundColor Cyan",
        "Install-WindowsFeature AD-Domain-Services -IncludeManagementTools",
        "Import-Module ADDSDeployment",
        "Write-Host '>>> [2/2] Promoting Domain Controller...' -ForegroundColor Cyan",
        "Install-ADDSForest -DomainName 'lab.local' -DomainNetbiosName 'LAB' -SafeModeAdministratorPassword (ConvertTo-SecureString 'Vulnerable123!' -AsPlainText -Force) -InstallDns:$true -NoRebootOnCompletion:$true -Force:$true"
    ]

    dc_adcs = [
        "Write-Host '>>> [1/4] Installing Certificate Services...' -ForegroundColor Cyan",
        "Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools",
        "Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools",
        "Import-Module ActiveDirectory",
        "Write-Host '>>> [2/4] Configuring CA...' -ForegroundColor Cyan",
        "try { Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -CACommonName 'lab-DC01-CA' -Force } catch { Write-Host 'CA Exists' }",
        "Write-Host '>>> [3/4] Configuring Web Enrollment...' -ForegroundColor Cyan",
        "try { Install-AdcsWebEnrollment -Force } catch { Write-Host 'Web Enrollment Exists' }",
        "Write-Host '>>> [4/4] Verifying IIS Binding...' -ForegroundColor Cyan",
        "Get-WebBinding -Port 80 -Name 'Default Web Site' -Protocol http"
    ]

    dc_vuln = [
        "Write-Host '>>> [1/10] Installing SqlServer Module...' -ForegroundColor Cyan",
        "Install-Module -Name SqlServer -Force -AllowClobber",
        "Write-Host '>>> [2/10] Configuring SQL Network...' -ForegroundColor Cyan",
        "$sqlPath = 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\*\\MSSQLServer\\SuperSocketNetLib\\Tcp\\IPAll'",
        "$tcpKey = Get-Item $sqlPath | Select-Object -First 1",
        "New-ItemProperty -Path $tcpKey.PSPath -Name 'TcpPort' -Value '1433' -PropertyType String -Force",
        "Stop-Service 'MSSQL$SQLEXPRESS' -Force; Start-Service 'MSSQL$SQLEXPRESS'",
        "Write-Host '>>> [3/10] Creating Vulnerable Users...' -ForegroundColor Cyan",
        "New-ADUser -Name svc_sql -SamAccountName svc_sql -AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true",
        "New-ADUser -Name svc_backup -SamAccountName svc_backup -AccountPassword (ConvertTo-SecureString 'Backup2024!' -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true",
        "New-ADUser -Name helpdesk -SamAccountName helpdesk -AccountPassword (ConvertTo-SecureString 'Help123!' -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true",
        "Write-Host '>>> [4/10] Setting User Vulnerabilities...' -ForegroundColor Cyan",
        # AS-REP Roasting Vulnerability (PreAuth Not Required)
        "$u = [ADSI]'LDAP://CN=svc_backup,CN=Users,DC=lab,DC=local'",
        "$u.userAccountControl = $u.userAccountControl.Value -bor 4194304",
        "$u.SetInfo()",
        # Kerberoasting Vulnerability
        "Set-ADUser -Identity svc_sql -ServicePrincipalNames @{Add='MSSQLSvc/dc01.lab.local:1433'}",
        # Golden Ticket Vulnerability (Set KRBTGT Password)
        "Set-ADAccountPassword krbtgt -NewPassword (ConvertTo-SecureString 'GodMode123!' -AsPlainText -Force) -Reset",
        "Write-Host '>>> [5/10] Creating SQL Database...' -ForegroundColor Cyan",
        "Invoke-Sqlcmd -Query \"CREATE DATABASE HR_DB;\" -ServerInstance 'localhost\\SQLEXPRESS' -TrustServerCertificate",
        "Invoke-Sqlcmd -Query \"USE HR_DB; CREATE TABLE Employees (ID INT, Name VARCHAR(100), Salary INT, SSN VARCHAR(20)); INSERT INTO Employees VALUES (1, 'Alice Manager', 90000, '000-00-1234'), (2, 'Bob User', 50000, '000-00-5678');\" -ServerInstance 'localhost\\SQLEXPRESS' -TrustServerCertificate",
        "Write-Host '>>> [6/10] Creating SQL Login...' -ForegroundColor Cyan",
        "Invoke-Sqlcmd -Query \"CREATE LOGIN [LAB\\svc_sql] FROM WINDOWS; USE HR_DB; CREATE USER [LAB\\svc_sql] FOR LOGIN [LAB\\svc_sql]; ALTER SERVER ROLE [sysadmin] ADD MEMBER [LAB\\svc_sql];\" -ServerInstance 'localhost\\SQLEXPRESS' -TrustServerCertificate",
        "Write-Host '>>> [7/10] Deploying PHP Portal...' -ForegroundColor Cyan",
        "New-Item -Path 'C:\\xampp\\htdocs\\hr_portal' -ItemType Directory -Force",
        "(Get-Content 'C:\\xampp\\php\\php.ini') -replace ';extension=odbc', 'extension=odbc' | Set-Content 'C:\\xampp\\php\\php.ini'",
        f"$php = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{php_b64}'))",
        "Set-Content -Path 'C:\\xampp\\htdocs\\hr_portal\\index.php' -Value $php",
        "Write-Host '>>> [8/10] Planting Fake Cloud Config...' -ForegroundColor Cyan",
        "New-Item -Path 'C:\\Program Files\\Azure AD Sync' -ItemType Directory -Force",
        f"$xml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{xml_b64}'))",
        "Set-Content -Path 'C:\\Program Files\\Azure AD Sync\\connection.xml' -Value $xml",
        "Write-Host '>>> [9/10] Configuring Firewall...' -ForegroundColor Cyan",
        "New-NetFirewallRule -DisplayName 'Allow HTTP' -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow",
        "New-NetFirewallRule -DisplayName 'Allow HTTP 8080' -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow",
        "New-NetFirewallRule -DisplayName 'Allow MSSQL' -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow",
        "New-NetFirewallRule -DisplayName 'Allow RDP' -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow"
    ]

    dc_adv = [
        "Write-Host '>>> [1/7] Initializing .NET Compiler...' -ForegroundColor Cyan",
        "$csc = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe'",
        "Write-Host '>>> [2/7] Deploying AMSI Bypass Lab...' -ForegroundColor Cyan",
        "New-Item -Path 'C:\\Tools\\AMSILab' -ItemType Directory -Force",
        f"$amsi = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{amsi_b64}'))",
        "Set-Content -Path 'C:\\Tools\\AMSILab\\vuln.ps1' -Value $amsi",
        "$acl = Get-Acl 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers'",
        "$rule = New-Object System.Security.AccessControl.RegistryAccessRule('BUILTIN\\Users','FullControl','Allow')",
        "$acl.SetAccessRule($rule)",
        "Set-Acl 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers' $acl",
        "Write-Host '>>> [3/7] Compiling VEH Bypass Lab...' -ForegroundColor Cyan",
        "New-Item -Path 'C:\\Tools\\VEHLab' -ItemType Directory -Force",
        f"$veh = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{veh_b64}'))",
        "Set-Content -Path 'C:\\Tools\\VEHLab\\FakeEDR.cs' -Value $veh",
        "Invoke-Expression \"& $csc /out:C:\\Tools\\VEHLab\\FakeEDR.exe C:\\Tools\\VEHLab\\FakeEDR.cs\"",
        "Write-Host '>>> [4/7] Creating Credential Dumps...' -ForegroundColor Cyan",
        "New-Item -Path 'C:\\Tools\\CredLab' -ItemType Directory -Force",
        "cmdkey /add:fileserver.lab.local /user:LAB\\backup_admin /pass:BackupP@ss123!",
        "reg save HKLM\\SAM C:\\Tools\\CredLab\\SAM.bak",
        "reg save HKLM\\SYSTEM C:\\Tools\\CredLab\\SYSTEM.bak",
        "reg save HKLM\\SECURITY C:\\Tools\\CredLab\\SECURITY.bak",
        "Write-Host '>>> [5/7] Deploying LOLBins...' -ForegroundColor Cyan",
        "New-Item -Path 'C:\\Tools\\LOLBinLab' -ItemType Directory -Force",
        f"$proj = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{msbuild_b64}'))",
        "Set-Content -Path 'C:\\Tools\\LOLBinLab\\payload.csproj' -Value $proj",
        "Write-Host '>>> [6/7] Enabling Logging...' -ForegroundColor Cyan",
        "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force",
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1",
        "Write-Host '>>> [7/7] Configuring Persistence...' -ForegroundColor Cyan",
        "New-Item -Path 'C:\\Tools\\PersistenceLab' -ItemType Directory -Force",
        "Unregister-ScheduledTask -TaskName 'WindowsDefenderUpdate' -Confirm:$false -ErrorAction SilentlyContinue",
        "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -Command \"echo persistence > C:\\Windows\\Temp\\persist.txt\"'",
        "$trigger = New-ScheduledTaskTrigger -AtLogOn",
        "$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest",
        "Register-ScheduledTask -TaskName 'WindowsDefenderUpdate' -Action $action -Trigger $trigger -Principal $principal"
    ]

    dc_ip = [
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

    iso_path_win = (BASE_DIR / WS2022_TARGET_NAME).as_uri()
    
    with open(BASE_DIR / "dc01.pkr.hcl", "w") as f:
        f.write(f"""
source "virtualbox-iso" "dc01" {{
  cpus                 = 2
  memory               = {ram_mb}
  disk_size            = 81920
  iso_checksum         = "{WS2022_CHECKSUM}"
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
  provisioner "powershell" {{ inline = {to_hcl(dc_base)} }}
  provisioner "windows-restart" {{ restart_timeout = "15m" }}
  provisioner "powershell" {{ inline = {to_hcl(dc_soft)} }}
  provisioner "windows-restart" {{ restart_timeout = "15m" }}
  # DC PROMO FIRST (NO ADCS)
  provisioner "powershell" {{ inline = {to_hcl(dc_promo)} }}
  provisioner "windows-restart" {{ restart_timeout = "30m" }}
  # ADCS AFTER REBOOT
  provisioner "powershell" {{ inline = {to_hcl(dc_adcs)} }}
  provisioner "powershell" {{ inline = {to_hcl(dc_vuln)} }}
  provisioner "powershell" {{ inline = {to_hcl(dc_adv)} }}
  provisioner "powershell" {{ inline = {to_hcl(dc_ip)} }}
}}
""")

    # =========================================================================
    # WEB01 GENERATION (FIXED 404 & RATE LIMITS & ADDED DOMAIN JOIN)
    # =========================================================================
    iso_path_deb = (BASE_DIR / DEBIAN_TARGET_NAME).as_uri()

    web_base = [
        "export DEBIAN_FRONTEND=noninteractive",
        "sudo apt-get update",
        "sudo apt-get install -y curl gnupg net-tools python3-flask python3-pip gcc make libcap2-bin vim auditd audispd-plugins samba cifs-utils smbclient",
        "curl -fsSL https://get.docker.com -o get-docker.sh",
        "sudo sh get-docker.sh",
        "sudo usermod -aG docker vagrant",
        "sudo systemctl enable docker; sudo systemctl start docker",
        "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--disable=traefik' sh -",
        "mkdir -p /home/vagrant/.kube",
        "sudo cp /etc/rancher/k3s/k3s.yaml /home/vagrant/.kube/config",
        "sudo chown vagrant:vagrant /home/vagrant/.kube/config",
        "echo '[backup_drop]' | sudo tee -a /etc/samba/smb.conf",
        "echo 'path = /home/vagrant/share' | sudo tee -a /etc/samba/smb.conf",
        "echo 'read only = no' | sudo tee -a /etc/samba/smb.conf",
        "echo 'guest ok = yes' | sudo tee -a /etc/samba/smb.conf",
        "echo 'writable = yes' | sudo tee -a /etc/samba/smb.conf",
        "echo 'force user = root' | sudo tee -a /etc/samba/smb.conf",
        "mkdir -p /home/vagrant/share && chmod 777 /home/vagrant/share",
        "sudo systemctl restart smbd",
        # Vulnerability: Cron job executes any .sh file in share as root every minute
        "echo '* * * * * root /bin/bash -c \"for f in /home/vagrant/share/*.sh; do bash \\$f; rm \\$f; done\"' | sudo tee /etc/cron.d/smb_executor",
        "sudo chmod 644 /etc/cron.d/smb_executor"
    ]

    web_ai = [
        "mkdir -p /home/vagrant/ai_agent",
        r'printf "from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n@app.route(\"/\")\ndef home(): return \"Insecure AI\"\n@app.route(\"/ask\")\ndef ask():\n    q = request.args.get(\"query\", \"\")\n    try:\n        out = subprocess.check_output(q, shell=True, stderr=subprocess.STDOUT)\n        return f\"<pre>{out.decode()}</pre>\"\n    except Exception as e: return str(e)\nif __name__ == \"__main__\": app.run(host=\"0.0.0.0\", port=5000)\n" > /home/vagrant/ai_agent/app.py',
        r'printf "[Unit]\nDescription=AI\nAfter=network.target\n[Service]\nUser=root\nWorkingDirectory=/home/vagrant/ai_agent\nExecStart=/usr/bin/python3 app.py\nRestart=always\n[Install]\nWantedBy=multi-user.target\n" | sudo tee /etc/systemd/system/ai_agent.service',
        "sudo systemctl daemon-reload",
        "sudo systemctl enable ai_agent",
        "sudo systemctl start ai_agent"
    ]

    web_api = [
        "sudo docker run -d --restart unless-stopped -p 3000:3000 bkimminich/juice-shop",
        "sleep 10",
        "sudo docker run -d --restart unless-stopped -p 5002:80 roottusk/vapi",
        "sleep 10",
        "mkdir -p ~/crapi",
        "cd ~/crapi",
        # FIXED: URL pointing to 'main' instead of 'v1.0.0' (404 fix)
        "curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml",
        "sudo docker compose pull",
        "sudo docker compose -f docker-compose.yml up -d || echo 'Docker Compose Failed'",
    ]

    # Added: Domain Join Logic
    web_domain = [
        "echo '>>> [DOMAIN] Installing AD tools...'",
        "sudo apt-get install -y realmd sssd sssd-tools adcli krb5-user packagekit",
        "echo '>>> [DOMAIN] Configuring Network for Join...'",
        "IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -2 | tail -1)",
        "echo \"auto $IFACE\" | sudo tee -a /etc/network/interfaces",
        "echo \"iface $IFACE inet static\" | sudo tee -a /etc/network/interfaces",
        "echo '  address 10.0.0.20/24' | sudo tee -a /etc/network/interfaces",
        "sudo ip addr add 10.0.0.20/24 dev $IFACE",
        "sudo ip link set $IFACE up",
        "echo 'nameserver 10.0.0.10' | sudo tee /etc/resolv.conf",
        "echo '>>> [DOMAIN] Joining Domain lab.local...'",
        "echo 'Vagrant!123' | sudo realm join -v -U vagrant lab.local",
        "echo '>>> [DOMAIN] Configuring SSSD...'",
        "echo 'session required pam_mkhomedir.so skel=/etc/skel/ umask=0022' | sudo tee -a /etc/pam.d/common-session"
    ]

    web_adv = [
        "mkdir -p /home/vagrant/container_lab",
        r'printf "version: \"3\"\nservices:\n  vuln_priv:\n    image: ubuntu:latest\n    privileged: true\n    command: sleep infinity\n  vuln_sock:\n    image: ubuntu:latest\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    command: sleep infinity\n" > /home/vagrant/container_lab/docker-compose-vuln.yml',
        "cd /home/vagrant/container_lab && sudo docker compose -f docker-compose-vuln.yml up -d || exit 1",
        "echo 'Waiting for K3s...'",
        "until sudo kubectl get nodes 2>/dev/null | grep -q ' Ready'; do sleep 5; done",
        "mkdir -p /home/vagrant/k8s_lab",
        r'printf "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: vuln-admin-sa\n  namespace: default\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: vuln-binding\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n- kind: ServiceAccount\n  name: vuln-admin-sa\n  namespace: default\n" > /home/vagrant/k8s_lab/vuln.yaml',
        "sudo kubectl apply -f /home/vagrant/k8s_lab/vuln.yaml",
        "echo 'vagrant ALL=(ALL) NOPASSWD: /usr/bin/vim' | sudo tee -a /etc/sudoers.d/vuln_sudo",
        "sudo cp /usr/bin/python3 /usr/local/bin/python_cap",
        "sudo setcap cap_setuid+ep /usr/local/bin/python_cap",
        "mkdir -p /home/vagrant/exfil_lab",
        "echo 'API_KEY=sk_live_1234567890abcdef' > /home/vagrant/exfil_lab/.env",
        "echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' >> /home/vagrant/exfil_lab/.env"
    ]

    with open(BASE_DIR / "web01.pkr.hcl", "w") as f:
        f.write(f"""
source "virtualbox-iso" "web01" {{
  vm_name              = "Lab-Web01"
  guest_os_type        = "Debian_64"
  iso_url              = "{iso_path_deb}"
  iso_checksum         = "{DEBIAN_CHECKSUM}"
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
  # Added NIC2 (Internal) to allow communication with DC01 during build
  vboxmanage = [
    ["modifyvm", "{{{{.Name}}}}", "--nat-localhostreachable1", "on"],
    ["modifyvm", "{{{{.Name}}}}", "--nic2", "intnet", "--intnet2", "psycholab", "--promiscuous2", "allow-all"]
  ]
  skip_export          = true
  keep_registered      = true
}}

build {{
  sources = ["source.virtualbox-iso.web01"]
  provisioner "shell" {{ inline = {to_hcl(web_base)} }}
  provisioner "shell" {{ inline = {to_hcl(web_domain)} }}
  provisioner "shell" {{ inline = {to_hcl(web_ai)} }}
  provisioner "shell" {{ inline = {to_hcl(web_api)} }}
  provisioner "shell" {{ inline = {to_hcl(web_adv)} }}
}}
""")

# ============================================================================
# MAIN
# ============================================================================
def main():
    check_privileges()
    
    print_color("==================================================================", Colors.CYAN)
    print_color("        MODERN KILL LAB - MASTER BUILDER (v8.0 Gold Master)       ", Colors.CYAN)
    print_color("==================================================================", Colors.CYAN)
    
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

    # 4. BUILD LOGIC WITH "KEEP OR BLOW AWAY"
    generate_files()
    print_color("\n>>> STARTING BUILD ORCHESTRATION...", Colors.YELLOW)
    subprocess.run(["packer", "init", "."], shell=(dm.os_type=="Windows"))

    # --- DC01 LOGIC ---
    build_dc = True
    if vm_exists("Lab-DC01"):
        print_color("\n[!] Lab-DC01 already exists!", Colors.YELLOW)
        choice = input("    Keep existing VM (k) or Blow away and rebuild (b)? [k/b]: ").lower()
        if choice == 'k':
            print_color("    [SKIP] Keeping existing Lab-DC01.", Colors.GREEN)
            build_dc = False
        else:
            print_color("    [NUKE] Blowing away Lab-DC01...", Colors.FAIL)
            nuke_vm("Lab-DC01")
            build_dc = True
    
    if build_dc:
        print_color("\n    [BUILD] DC01...", Colors.CYAN)
        subprocess.call(["packer", "build", "-force", "dc01.pkr.hcl"], shell=(dm.os_type=="Windows"))

    # ========================================================================
    # NEW ORCHESTRATION LOGIC: CONFIGURE & START DC01 FOR DOMAIN JOIN
    # ========================================================================
    vbox_cmd = "VBoxManage"
    if dm.os_type == "Windows" and not shutil.which("VBoxManage"):
        vbox_cmd = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

    # Always ensure DC01 is running for Web01 to join, even if we skipped build
    print_color("\n>>> ENSURING DC01 IS RUNNING FOR DOMAIN JOIN...", Colors.YELLOW)
    
    # Check if DC01 is running
    is_running = False
    try:
        res = subprocess.run([vbox_cmd, "showvminfo", "Lab-DC01", "--machinereadable"], capture_output=True, text=True)
        if 'VMState="running"' in res.stdout:
            is_running = True
    except: pass

    if not is_running:
        print_color("    [START] Starting Lab-DC01 (Headless)...", Colors.CYAN)
        # Configure network just in case
        subprocess.run([vbox_cmd, "modifyvm", "Lab-DC01", "--nic1", "intnet", "--intnet1", "psycholab"], stderr=subprocess.DEVNULL)
        subprocess.run([vbox_cmd, "startvm", "Lab-DC01", "--type", "headless"])
        print_color("    [WAIT] Waiting for Domain Controller to initialize (approx 2-3 mins)...", Colors.YELLOW)
        time.sleep(120) # Shorter wait if we just started it, assuming it was built or exists
    else:
        print_color("    [OK] Lab-DC01 is already running.", Colors.GREEN)

    # --- WEB01 LOGIC ---
    build_web = True
    if vm_exists("Lab-Web01"):
        print_color("\n[!] Lab-Web01 already exists!", Colors.YELLOW)
        choice = input("    Keep existing VM (k) or Blow away and rebuild (b)? [k/b]: ").lower()
        if choice == 'k':
            print_color("    [SKIP] Keeping existing Lab-Web01.", Colors.GREEN)
            build_web = False
        else:
            print_color("    [NUKE] Blowing away Lab-Web01...", Colors.FAIL)
            nuke_vm("Lab-Web01")
            build_web = True

    if build_web:
        print_color("\n    [BUILD] Web01 (Joining Domain)...", Colors.CYAN)
        subprocess.call(["packer", "build", "-force", "web01.pkr.hcl"], shell=(dm.os_type=="Windows"))

    print_color("\n>>> FINAL CONFIGURATION...", Colors.YELLOW)
    # Ensure Web01 is on the right internal network for post-lab usage (redundant due to vboxmanage inside pkr, but safe)
    if vm_exists("Lab-Web01"):
         subprocess.run([vbox_cmd, "modifyvm", "Lab-Web01", "--nic1", "intnet", "--intnet1", "psycholab"], stderr=subprocess.DEVNULL)

    # Optional: Shutdown DC01 if you want to power off the whole lab after build
    # subprocess.run([vbox_cmd, "controlvm", "Lab-DC01", "poweroff"], stderr=subprocess.DEVNULL)

    print_color("\n==================================================================", Colors.CYAN)
    print_color("                  LAB ACCESS CREDENTIALS                          ", Colors.CYAN)
    print_color("==================================================================", Colors.CYAN)
    print("Lab-DC01     10.0.0.10       LAB\\vagrant        Vagrant!123")
    print("                             Legacy HR Portal   http://10.0.0.10:8080/hr_portal")
    print("                             AD CS Web          http://10.0.0.10/certsrv")
    print("")
    print("Lab-Web01    10.0.0.20       LAB\\vagrant        Vagrant!123 (Domain Joined)")
    print("                             Local User         vagrant / vagrant")
    print_color("==================================================================", Colors.GREEN)

if __name__ == "__main__":
    main()
