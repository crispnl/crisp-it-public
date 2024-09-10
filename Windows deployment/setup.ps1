# Disabling progress bar significantly shortens Invoke-Webrequest wait
$ProgressPreference = "SilentlyContinue"

"Finishing Windows installation" | Out-Host
Start-Sleep  -s 30
$SerialNumber= (Get-WmiObject -class win32_bios).SerialNumber
Start-Transcript -Append "$($env:ProgramData)\IT\Logs\$($SerialNumber)_setup.log"

# Enable Bitlocker
$OsDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
$BitlockerVolume = Get-BitLockerVolume -Mountpoint $OsDrive
if ($BitlockerVolume.ProtectionStatus -like "Off") {
	if ((Get-TPM).TpmPresent -and (Get-TPM).TpmReady -and (Get-TPM).TpmEnabled -and (Get-TPM).TpmActivated -and (Get-TPM).TpmOwned){
		"Configuring Bitlocker" | Out-Host
		Add-BitlockerKeyProtector -MountPoint $OsDrive -TpmProtector
		Start-Sleep -s 10
		Enable-Bitlocker -MountPoint $OsDrive -EncryptionMethod XtsAes128 -UsedSpaceOnly -RecoveryPasswordProtector
	}
	else {
		Write-Error "TPM Error"
		Start-Sleep 2
		Get-tpm | Write-Host
	}
}
else {
	"Bitlocker already enabled" | Out-Host
}

# Encryption can get stuck at 98%. Pausing and resuming encryption process can solve this.
# Encryption can get stuck waiting on activation. Resuming the encryption status can solve this. 
"Checking bitlocker status" | Out-Host
if ($BitlockerVolume.ProtectionStatus -like "Off") {
	manage-bde -pause $OsDrive | Out-Null
	Start-Sleep -s 2
	manage-bde -resume $OsDrive | Out-Null
	Start-Sleep -s 30
	Resume-Bitlocker -MountPoint $OsDrive | Out-Null
}

# Install Winget
$AppFiles = 
"$($env:ProgramData)\IT\Appx\vclibs*",
"$($env:ProgramData)\IT\Appx\yaml*",
"$($env:ProgramData)\IT\Appx\winget*"

foreach ($File in $Appfiles){
    "Installing $($File)" | Out-Host
    Add-AppxPackage $File -ErrorAction SilentlyContinue
}

# Wait for network
"Checking network connection" | Out-Host
do{
    $ping = Test-NetConnection '8.8.8.8' -InformationLevel Quiet
     Start-Sleep -s 5
} while(!$ping)

# Installing PSWindowsupdate
Install-PackageProvider -Name NuGet -Confirm:$false -Force > Out-Null
Install-Module PSWindowsUpdate -Confirm:$false -Force > Out-Null
Import-Module PSWindowsUpdate > Out-Null

# Asynchronously install Windows updates
"Downloading windows updates" | Out-Host
Start-Job -ScriptBlock{
	Start-Sleep -s 5
	$Updates = Get-WindowsUpdate
	if ($Updates) {
		Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot | Select-Object KB, Result, Title, Size
	}
}

# Install Apps
# Instaling Chrome using direct download. The frequency of chrome updates can cause hash mismatches when installing via winget
"Installing apps" | Out-Host
Invoke-RestMethod -Uri "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi" -Outfile "$($env:ProgramData)\IT\Appx\googlechrome.msi"
msiexec.exe /i "$($env:ProgramData)\IT\Appx\googlechrome.msi" /qn /norestart

$Packages = 
[PSCustomObject]@{
    Name  = "Adobe Acrobat"
	Id = "Adobe.Acrobat.Reader.64-bit"
    Scope = "machine"
},
[PSCustomObject]@{
    Name  = "Slack"
	Id = "SlackTechnologies.Slack"
    Scope = "machine"
},
[PSCustomObject]@{
    Name  = "Office 365"
	Id = "Microsoft.Office"
    Scope = "machine"
}

foreach ($Package in $Packages) {
	"Installing $($Package.Name)" | Out-Host
    if ($Package.Scope) {
        winget install -e --id $Package.Id --scope $Package.Scope --silent --accept-source-agreements
    }
    else {
        winget install -e --id $Package.Id --silent --accept-source-agreements
    }
}

# Removing reinstalled bloat
winget uninstall Microsoft.Onedrive
winget uninstall Microsoft.Teams

# Setup GCPW
"Installing Google crendential provider" | Out-Host
$domainsAllowedToLogin = "crisp.nl"
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework
$gcpwFileName = 'gcpwstandaloneenterprise64.msi'
$gcpwUrlPrefix = 'https://dl.google.com/credentialprovider/'
$gcpwUri = $gcpwUrlPrefix + $gcpwFileName
Invoke-WebRequest -Uri $gcpwUri -OutFile $gcpwFileName
$arguments = "/i `"$gcpwFileName`""
$installProcess = (Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait)
if ($installProcess.ExitCode -ne 0) {
	Write-Error  "Error installing GCPW"
	return
}
$registryPath = 'HKEY_LOCAL_MACHINE\Software\Google\GCPW'
$name = 'domains_allowed_to_login'
[microsoft.win32.registry]::SetValue($registryPath, $name, $domainsAllowedToLogin)
$domains = Get-ItemPropertyValue HKLM:\Software\Google\GCPW -Name $name
if ($domains -ne $domainsAllowedToLogin) {
 	Write-Error "Error setting registry"
}

# Create keyfile
"Creating keyfile" | Out-Host
$Keyfile = "$($env:ProgramData)\IT\Logs\$($SerialNumber)_key.txt"
$Key = manage-bde $OsDrive -protectors -get -type RecoveryPassword
New-Item $Keyfile -Force| Out-Null
Set-Content $Keyfile "$($Key)"
if (!(Test-Path "D:\Keys")) {
	New-Item -Path "D:\Keys" -ItemType Directory -Force > Out-Null
}
Copy-Item $Keyfile -Destination "D:\Keys"
Start-Sleep -s 2

# Set default user settings
"Changing default user settings" | Out-Host
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
$DefaultHive = "C:\Users\Default\ntuser.dat"
REG LOAD "HKU\Default" $DefaultHive
$Settings = 
[PSCustomObject]@{
    Path  = "Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Name  = "setup_user"
	Type = "String"
    Value = "cmd /c powershell.exe -ExecutionPolicy Bypass -File $($env:ProgramData)\IT\Scripts\user.ps1"
},
[PSCustomObject]@{
    Path  = "Software\Microsoft\Windows\CurrentVersion\Search"
    Name  = "BingSearchEnabled"
	Type = "DWord"
    Value = 0
},
[PSCustomObject]@{
    Path  = "Software\Microsoft\Windows\CurrentVersion\Search"
    Name  = "SearchboxTaskbarMode"
	Type = "DWord"
    Value = 0
},
[PSCustomObject]@{
    Path  = "Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    Name  = "Enabled"
	Type = "DWord"
    Value = 0
},
[PSCustomObject]@{
    Path  = "Software\Microsoft\Windows\CurrentVersion\Privacy"
    Name  = "TailoredExperiencesWithDiagnosticDataEnabled"
	Type = "DWord"
    Value = 0
},
[PSCustomObject]@{
    Path  = "Software\Microsoft\Personalization\Settings"
    Name  = "AcceptedPrivacyPolicy"
	Type = "DWord"
    Value = 1
},
[PSCustomObject]@{
    Path  = "Software\Policies\Microsoft\Windows\Explorer"
    Name  = "NoPinningStoreToTaskbar"
	Type = "DWord"
    Value = 1
}

foreach ($Setting in $Settings) {
	$Path = "HKU:\Default\" + $Setting.Path
	if (!(Test-Path $Path)) {
		New-Item -Path $Path -Force | Out-Null
	}
    New-ItemProperty -Path $Path -Name $Setting.Name -PropertyType $Setting.Type -Value $Setting.Value -Force
}
REG UNLOAD "HKU\Default"
Remove-PSDrive -Name HKU 

# Disable autoLogon
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f

# Remove stored credentials
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f

# Removes install files and sets access rights for user script
Remove-Item -Path "$($env:ProgramData)\IT\Appx" -Recurse -Force
Get-ChildItem "$($env:ProgramData)\IT\Scripts" | ForEach-Object {
	if ($_.Name -notlike "user.ps1"){
		Remove-Item $_.FullName -Force
	}
}

# Finishing Windows update. 
"Waiting for Windows update to finish"| Out-Host
Get-Job | Wait-Job | Receive-Job | Out-Host
Write-Host -ForegroundColor Green "Setup finished `n System will restart in 5 seconds"
Stop-Transcript
Start-Sleep -s 5
Restart-Computer