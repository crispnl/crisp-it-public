# Disabling progress bar significantly shortens Invoke-Webrequest wait
$ProgressPreference = "SilentlyContinue"
"Setting up desktop. Don't close this window. The system will reboot when done" | Out-Host

# Populate registry
Start-Sleep -s 30
Start-Transcript -Append "$($env:ProgramData)\IT\Logs\$($env:UserName)_setup.log"

# Install user-only apps
"Installing apps" | Out-Host
winget install Notion.Notion --accept-source-agreements --accept-package-agreements

# Remove reinstalled bloat. Uninstalling for user scope because the script runs without admin rights
"Removing bloat" | Out-Host
winget uninstall "Microsoft-tips" --scope user
winget uninstall "Windows Web Experience Pack" --scope user

Stop-Transcript
Write-Host -ForegroundColor Green "Setup complete. `nWindows will reboot in 5 seconds."
Start-Sleep -s 5
Restart-Computer
