# ============================================================
# ULTIMATE SMB SMART REPAIR + AUDIT TOOL v2.0
# Compatible: Windows 10 / 11
# ============================================================

Clear-Host
Write-Host "=== ULTIMATE SMB SMART REPAIR + AUDIT TOOL v2.0 ===" -ForegroundColor Cyan

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
# ADMIN CHECK
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
# CONFIGURATION
# ============================================================

$EnableInsecureSMB = $false  # Default Secure Mode
$ToggleMode = $false          # Will ask user in menu
$ServerName = ""

# ============================================================
# NETWORK FUNCTIONS
# ============================================================

function Enable-NetworkDiscovery {
    $nd = Get-NetFirewallRule -DisplayGroup "Network Discovery"
    if ($nd.Enabled -contains "False") {
        Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True
        Write-Host "Network Discovery Enabled." -ForegroundColor Green
    } else { Write-Host "Network Discovery Already Enabled." -ForegroundColor Yellow }

    $fps = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing"
    if ($fps.Enabled -contains "False") {
        Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
        Write-Host "File & Printer Sharing Enabled." -ForegroundColor Green
    } else { Write-Host "File & Printer Sharing Already Enabled." -ForegroundColor Yellow }
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
# SMB CONFIGURATION FUNCTIONS
# ============================================================

function Configure-SMB {
    param([bool]$EnableInsecureSMB)

    if (-not $EnableInsecureSMB) {
        Write-Host "`nRunning in Secure Mode..." -ForegroundColor Cyan
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
        Write-Host "SMB configuration secured." -ForegroundColor Green
        return
    }

    Write-Host "`nRunning in Compatibility Mode..." -ForegroundColor Cyan

    # Enable Guest
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
# SMB AUDIT FUNCTION
# ============================================================

function Audit-SMB {
    $client = Get-SmbClientConfiguration
    $server = Get-SmbServerConfiguration
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

    $risk = "LOW"
    if ($client.EnableInsecureGuestLogons) { $risk = "HIGH" }
    if (-not $client.RequireSecuritySignature -or -not $server.RequireSecuritySignature) {
        $risk = "MEDIUM"
    }
    if ($smb1.State -eq "Enabled") { $risk = "CRITICAL" }

    Write-Host "`n============= SMB RISK REPORT =============" -ForegroundColor Cyan
    Write-Host "Guest Logons Enabled : $($client.EnableInsecureGuestLogons)"
    Write-Host "Client Signing Req   : $($client.RequireSecuritySignature)"
    Write-Host "Server Signing Req   : $($server.RequireSecuritySignature)"
    Write-Host "SMB1 Installed       : $($smb1.State -eq 'Enabled')"
    Write-Host "-------------------------------------------"
    Write-Host "OVERALL RISK LEVEL   : $risk" -ForegroundColor Red
    Write-Host "=========================================="
}

# ============================================================
# MODERATE MODE (0x80070035 Guided)
# ============================================================

function Moderate-Mode {
    Write-Host "`n=== MODERATE MODE: Guided 0x80070035 Fix ===" -ForegroundColor Cyan
    $ServerName = Read-Host "Enter the server name or IP that is not accessible (e.g., SERVER-2)"
    $resolved = $false

    # Step 1: DNS / Ping Check
    while (-not $resolved) {
        Write-Host "`nStep 1: Testing connectivity..."
        if (Test-Connection -ComputerName $ServerName -Count 2 -Quiet) {
            Write-Host "$ServerName is reachable via ping." -ForegroundColor Green
        } else {
            Write-Host "$ServerName NOT reachable via ping. Flushing DNS..." -ForegroundColor Yellow
            ipconfig /flushdns
        }

        # Ask user if accessible now
        $userInput = Read-Host "Can you access \\$ServerName now? (Y/N)"
        if ($userInput -match "^[Yy]") { $resolved = $true } else { break }
    }

    # Step 2: Network Profile
    $net = Get-NetConnectionProfile | Select-Object -First 1
    if ($net.NetworkCategory -eq "Public") {
        Write-Host "Switching network profile to Private..."
        Set-NetConnectionProfile -InterfaceIndex $net.InterfaceIndex -NetworkCategory Private
        Reset-NetworkStack
    }

    $userInput = Read-Host "Try \\$ServerName again. Accessible? (Y/N)"
    if ($userInput -match "^[Yy]") { return }

    # Step 3: Firewall / Discovery
    Enable-NetworkDiscovery
    Reset-NetworkStack
    $userInput = Read-Host "Try \\$ServerName again. Accessible? (Y/N)"
    if ($userInput -match "^[Yy]") { return }

    # Step 4: SMB Signing Relax (Temporary)
    Write-Host "Temporarily relaxing SMB signing for client..."
    Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
    Reset-NetworkStack
    $userInput = Read-Host "Try \\$ServerName again. Accessible? (Y/N)"
    if ($userInput -match "^[Yy]") { return }

    # Step 5: Guest Logon (Optional)
    $guest = Read-Host "Enable guest logon temporarily? (Y/N)"
    if ($guest -match "^[Yy]") {
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
        Reset-NetworkStack
    }

    # Step 6: SMB1 (Legacy server)
    $smb1Check = Read-Host "Is this an old legacy server requiring SMB1? (Y/N)"
    if ($smb1Check -match "^[Yy]") {
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Reset-NetworkStack
    }

    Write-Host "`nModerate Mode steps completed. Check access to \\$ServerName" -ForegroundColor Green
}

# ============================================================
# MENU
# ============================================================

function Show-Menu {
    Write-Host "`nSelect Mode:" -ForegroundColor Cyan
    Write-Host "1 - Moderate (Guided 0x80070035 Fix)"
    Write-Host "2 - Secure Mode"
    Write-Host "3 - Compatibility Mode"
    Write-Host "4 - SMB Risk Audit"
    Write-Host "5 - Exit"
    $choice = Read-Host "Enter choice [1-5]"

    switch ($choice) {
        "1" { Moderate-Mode }
        "2" { Configure-SMB -EnableInsecureSMB:$false }
        "3" { Configure-SMB -EnableInsecureSMB:$true }
        "4" { Audit-SMB }
        "5" { Write-Host "Exiting..."; exit }
        default { Write-Host "Invalid choice. Try again."; Show-Menu }
    }
}

# ============================================================
# MAIN EXECUTION
# ============================================================

while ($true) {
    Show-Menu
    Write-Host "`nOperation completed. You may run another mode or exit." -ForegroundColor Yellow
}
