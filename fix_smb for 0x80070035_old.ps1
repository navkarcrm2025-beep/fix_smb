# ============================================
# FIX SMB/Network Path Issues (0x80070035)
# Allow Insecure Guest Logons + Disable SMB Signing
# Compatible with Windows 10/11 Pro (and Home)
# Run PowerShell as Administrator
# ============================================

# Function to check admin privileges
function Test-Admin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "This script must be run as Administrator."
    exit
}

Write-Host "Applying SMB configuration changes..." -ForegroundColor Cyan

# --- STEP 1: Allow Insecure Guest Logons ---
$lanmanKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if (-not (Test-Path $lanmanKey)) { New-Item -Path $lanmanKey -Force | Out-Null }
Set-ItemProperty -Path $lanmanKey -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
Write-Host "✅ Enabled insecure guest logons." -ForegroundColor Green

# --- STEP 2: Disable SMB Signing (Client side) ---
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path $lsaPath)) { New-Item -Path $lsaPath -Force | Out-Null }
Set-ItemProperty -Path $lsaPath -Name "RequireSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path $lsaPath -Name "EnableSecuritySignature" -Value 0 -Type DWord
Write-Host "✅ Disabled SMB signing for client communications." -ForegroundColor Green

# --- STEP 3: Disable SMB Signing (Server side) ---
$serverPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
Set-ItemProperty -Path $serverPath -Name "RequireSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path $serverPath -Name "EnableSecuritySignature" -Value 0 -Type DWord
Write-Host "✅ Disabled SMB signing for server communications." -ForegroundColor Green

# --- STEP 4: Apply via native commands (redundant but ensures consistency) ---
reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /f /v RequireSecuritySignature /t REG_DWORD /d 0 | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation /f /v AllowInsecureGuestAuth /t REG_DWORD /d 1 | Out-Null
reg add HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LanmanWorkstation /f /v AllowInsecureGuestAuth /t REG_DWORD /d 1 | Out-Null

Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force

# --- STEP 5: Collect Updated Configuration ---
$clientCfg = Get-SmbClientConfiguration | Select-Object EnableInsecureGuestLogons, RequireSecuritySignature
$serverCfg = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
$guestAuth = Get-ItemProperty -Path $lanmanKey | Select-Object AllowInsecureGuestAuth

# Prepare final output
$result = @"
==============================
 SMB Configuration Summary
==============================

[Client Config]
EnableInsecureGuestLogons : $($clientCfg.EnableInsecureGuestLogons)
RequireSecuritySignature   : $($clientCfg.RequireSecuritySignature)

[Server Config]
RequireSecuritySignature   : $($serverCfg.RequireSecuritySignature)

[Registry Guest Auth]
AllowInsecureGuestAuth     : $($guestAuth.AllowInsecureGuestAuth)

==============================
Please restart your computer
for changes to take full effect.
==============================
"@

# Print & copy to clipboard
Write-Host "`nAll settings applied successfully." -ForegroundColor Cyan
Write-Host "Results copied to clipboard ✅" -ForegroundColor Green
$result | Set-Clipboard
Write-Host $result

