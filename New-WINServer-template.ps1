<#
    .SYNOPSIS
    Command reference template for installing a Windows Server on Hyper-V.
    .DESCRIPTION
    A set of command references used to go from a blank Hyper-V based VM with a single NIC to a standardised Windows Server ready for action.
    The code creates a separate administrative account $customAdminName for future use.
    The code does contain passwords in clear text and should be handled accordingly.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    .\New-WINServer-template.ps1
    .NOTES
    This script is not designed as a set-and-forget, run the sections manually one by one.
    .NOTES
    Remember to swap the # Variables to match your settings.
    .NOTES
    Assumes single Disk - C:
    (DVD driver as D:)
    Assumes single NIC - "NetConnectionID = 'Ethernet'"
#>

# Variables
$serverName = "SERVER1" # ServerName
# Set Server Name and Restart
Rename-Computer -NewName $serverName -Force
Restart-Computer -Force

# Variables
$serverName = $env:computername 
$ipaddress = "192.168.0.3" # IP Address
$ipprefix = "24" # CIDR Mask
$ipgw = "192.168.0.1" # Gateway
$ipdns = "192.168.0.1" # DNS Server
$windowsKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" # Windows Activation Key
$nicOSName = "Management" # Name for network card 
# users
$defaultAdminName = "Administrator" # Default administrator account name
$defaultAdminPsw = "P@ssWord1" # New password for default administrator account
$customAdminName = "Admin" # Custom administrator account name
$customAdminPsw = "P@ssWord2" # Password for default administrator account
$customAdminDesc = "Custom Administative Account." # Description for default administrator account

# Set Network Adapter Name Configuration
$wmi = Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetConnectionID = 'Ethernet'"
$wmi.NetConnectionID = $nicOSName
$wmi.Put()

# Set IP Information
$ipif = (Get-NetAdapter -Name $nicOSName).ifIndex 
New-NetIPAddress -IPAddress $ipaddress -PrefixLength $ipprefix -InterfaceIndex $ipif -DefaultGateway $ipgw
Set-DnsClientServerAddress -InterfaceIndex $ipif -ServerAddresses $ipdns

# Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Enable ICMPv4 Response - ping
Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -Enabled True

# Common Server Settings
Add-WindowsFeature -Name "Telnet-Client"

# Set PowerPlan to High Performance
Try {
    $HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
    $CurrPlan = $(powercfg -getactivescheme).split()[3]
    if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
    } Catch {
        Write-Warning -Message "Unable to set power plan to high performance"
    }

# Enable Windows Updates (Download updates but let me choose whether to install them)
$AUSettigns = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AUSettigns.NotificationLevel = 3
$AUSettigns.Save()

# Change DVD drive (D:) letter to Z:
$drv = Get-WmiObject win32_volume -filter 'DriveLetter = "D:"'
$drv.DriveLetter = "Z:"
$drv.Put() | out-null

# Eject DVD Drive
$Eject = New-Object -ComObject "Shell.Application"
$Eject.Namespace(17).Items() | Where-Object { $_.Type -eq "CD Drive" } | foreach { $_.InvokeVerb("Eject") }

# Enable Shadowcopies on C: drive
$diskLetter = "C:"
$diskname = "$diskLetter\"
$VolumeWmi = gwmi Win32_Volume -Namespace root/cimv2 | ?{ $_.Name -eq $diskname }
$DeviceID = $VolumeWmi.DeviceID.ToUpper().Replace("\\?\VOLUME", "").Replace("\","")
$TaskName03 = "ShadowCopyVolume - " + $DeviceID + " - 0300"
$TaskName12 = "ShadowCopyVolume - " + $DeviceID + " - 1200"
$TaskFor = "\\?\Volume" + $DeviceID + "\\"
$Task = "%systemroot%\system32\vssadmin.exe Create Shadow /AutoRetry=15 /For=$TaskFor"
vssadmin add shadowstorage /for=$diskLetter /on=$diskLetter /maxsize=10%
schtasks /create /RU SYSTEM /SC DAILY /ST 03:00 /TN $TaskName03 /TR $Task /V1
schtasks /create /RU SYSTEM /SC DAILY /ST 12:00 /TN $TaskName12 /TR $Task /V1

# Activate Windows
slmgr -upk
slmgr -ipk $windowsKey

# Local Users
# Reset Local Admin Password
Net User $defaultAdminName $defaultAdminPsw
# Set password never expires
$user = [adsi]"WinNT://$env:computername/$defaultAdminName"
$user.UserFlags.value = $user.UserFlags.value -bor 0x10000
$user.CommitChanges()

# Add custom local admin account
$localGroup = "administrators"
net user $customAdminName $customAdminPsw /add
net localgroup $localGroup $customAdminName /add
# Set account description
$user = [adsi]"WinNT://$env:computername/$customAdminName"
$user.Description=$customAdminDesc
$user.SetInfo()
# Set password never expires
$user.UserFlags.value = $user.UserFlags.value -bor 0x10000
$user.CommitChanges()

# Restart Server
Restart-Computer -Force
