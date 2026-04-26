# lab/win/promote_dc.ps1 — Stage 1: install AD-DS + DNS, promote to
# first DC in a fresh kerblab2022.local forest.
#
# Idempotent: if already a DC, exit silently. Reboot required after
# promotion; Vagrant's `reboot: true` on the provisioner handles it.
#
# Defaults match Vagrantfile.win2022 — change here AND there together.

$ErrorActionPreference = "Stop"

$DomainName  = "kerblab2022.local"
$NetbiosName = "KERBLAB22"
$AdminPass   = ConvertTo-SecureString "LabAdmin1!" -AsPlainText -Force
$DCIP        = "192.168.57.22"

# ── Already provisioned? ────────────────────────────────────────────
$role = (Get-CimInstance Win32_OperatingSystem).ProductType
# ProductType 2 = DC. ProductType 3 = member server / standalone.
if ($role -eq 2) {
    Write-Host "[promote] Already a DC — skipping promotion."
    exit 0
}

Write-Host "[promote] starting at $(Get-Date -Format o)"

# ── DNS forwarder + static IP confirmation ──────────────────────────
# Vagrant's private_network already set the IP; just point DNS at
# loopback so the DC resolves itself once promoted, plus an upstream
# fallback for outbound name resolution.
$nic = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -contains $DCIP }
if ($null -ne $nic) {
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses ("127.0.0.1","8.8.8.8")
    Write-Host "[promote] DNS set on adapter $($nic.Name)"
}

# ── Install AD-DS + DNS roles ───────────────────────────────────────
Write-Host "[promote] installing AD-DS + DNS roles..."
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools -ErrorAction Stop | Out-Null

# ── Promote to first DC of a new forest ─────────────────────────────
Write-Host "[promote] running Install-ADDSForest (~5-10 min)..."
Install-ADDSForest `
    -DomainName            $DomainName `
    -DomainNetbiosName     $NetbiosName `
    -SafeModeAdministratorPassword $AdminPass `
    -InstallDns            `
    -DomainMode            "WinThreshold" `
    -ForestMode            "WinThreshold" `
    -DatabasePath          "C:\Windows\NTDS" `
    -LogPath               "C:\Windows\NTDS" `
    -SysvolPath            "C:\Windows\SYSVOL" `
    -CreateDnsDelegation:$false `
    -NoRebootOnCompletion:$false `
    -Force:$true

Write-Host "[promote] complete; the system will reboot."
