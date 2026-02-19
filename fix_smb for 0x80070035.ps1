# ============================================================
# ULTIMATE NETWORK + SMB FIX TOOL
# Compatible: Windows 10 / 11
# ============================================================

Clear-Host
Write-Host "=== ULTIMATE NETWORK + SMB REPAIR TOOL ===" -ForegroundColor Cyan

# ============================================================
# EXECUTION POLICY CHECK
# ============================================================

if ((Get-ExecutionPolicy -Scope CurrentUser) -eq "Restricted") {
    Write-Host ""
    Write-Host "Execution Policy blocks scripts." -ForegroundColor Red
    Write-Host "Run this in a NEW PowerShell window:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Green
    Write-Host ""
    return
}

# ============================================================
# ADMIN CHECK (ISE SAFE)
# ============================================================

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "Please restart PowerShell as Administrator." -ForegroundColor Red
    return
}

Write-Host "Running as Administrator." -ForegroundColor Green

# ============================================================
# CONFIGURATION SWITCH
# ============================================================

$EnableInsecureSMB = $true   # <<< SET TO $false IF YOU WANT SECURITY SAFE MODE

# ============================================================
# NETWORK FUNCTIONS
# ============================================================

function Enable-NetworkDiscovery {
    $nd = Get-NetFirewallRule -DisplayGroup "Network Discovery"
    if ($nd.Enabled -contains "False") {
        Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True
        Write-Host "Network Discovery Enabled." -ForegroundColor Green
    }
    else { Write-Host "Network Discovery Already Enabled." -ForegroundColor Yellow }

    $fps = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing"
    if ($fps.Enabled -contains "False") {
        Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
        Write-Host "File & Printer Sharing Enabled." -ForegroundColor Green
    }
    else { Write-Host "File & Printer Sharing Already Enabled." -ForegroundColor Yellow }
}

function Reset-NetworkStack {
    Write-Host "`nResetting Network Stack..."
    ipconfig /flushdns | Out-Null
    netsh winsock reset | Out-Null
    netsh int ip reset | Out-Null
    Write-Host "Network Stack Reset Done." -ForegroundColor Green
}

function Restart-NetworkAdapterSafe {
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
    if ($adapter) {
        Restart-NetAdapter -Name $adapter.Name -Confirm:$false
        Write-Host "Adapter Restarted: $($adapter.Name)" -ForegroundColor Green
    }
}

# ============================================================
# SMB SECURITY MODIFICATION (OPTIONAL)
# ============================================================

function Configure-SMB {

    if (-not $EnableInsecureSMB) {
        Write-Host "`nSMB security downgrade skipped (Safe Mode)." -ForegroundColor Cyan
        return
    }

    Write-Host "`nApplying SMB compatibility changes..." -ForegroundColor Cyan

    # Allow Guest
    Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
        -Name AllowInsecureGuestAuth -Value 1 -Type DWord

    # Disable Signing
    Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
    Set-SmbServerConfiguration -RequireSecuritySignature $false -Force

    Write-Host "SMB Guest Logon Enabled." -ForegroundColor Yellow
    Write-Host "SMB Signing Disabled." -ForegroundColor Yellow
}

# ============================================================
# STATUS SUMMARY
# ============================================================

function Show-Summary {

    $client = Get-SmbClientConfiguration
    $server = Get-SmbServerConfiguration

    Write-Host "`n============= SUMMARY =============" -ForegroundColor Cyan
    Write-Host "Guest Logons Enabled : $($client.EnableInsecureGuestLogons)"
    Write-Host "Client Signing Req   : $($client.RequireSecuritySignature)"
    Write-Host "Server Signing Req   : $($server.RequireSecuritySignature)"
    Write-Host "===================================="
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Enable-NetworkDiscovery
Configure-SMB
Restart-NetworkAdapterSafe
Reset-NetworkStack
Show-Summary

Write-Host "`nAll operations completed." -ForegroundColor Green
Write-Host "Restart recommended." -ForegroundColor Yellow
Pause
