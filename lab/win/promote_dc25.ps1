# lab/win/promote_dc25.ps1 — Stage 1: install AD-DS + DNS, promote to
# first DC in a fresh kerblab2025.local forest.
#
# Same shape as promote_dc.ps1 (Server 2022) but with the Server 2025
# realm + the WinThreshold/2025 forest mode. Idempotent: if already a
# DC, exit silently.

$ErrorActionPreference = "Stop"

$DomainName  = "kerblab2025.local"
$NetbiosName = "KERBLAB25"
$AdminPass   = ConvertTo-SecureString "LabAdmin1!" -AsPlainText -Force
$DCIP        = "192.168.57.25"

# ── Already provisioned? ────────────────────────────────────────────
$role = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($role -eq 2) {
    Write-Host "[promote-dc25] Already a DC — skipping promotion."
    exit 0
}

Write-Host "[promote-dc25] starting at $(Get-Date -Format o)"

# ── Static IP on host-only adapter ──────────────────────────────────
# Host-driven script sets this BEFORE invoking us (see the python
# uploader). Belt-and-braces: ensure DNS points at loopback so the
# DC can resolve itself once promoted.
$ifIndex = (Get-NetIPAddress -InterfaceAlias "Ethernet 2" -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceIndex
if ($ifIndex) {
    Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses ("127.0.0.1","8.8.8.8")
    Write-Host "[promote-dc25] DNS set on Ethernet 2"
}

# ── Install AD-DS + DNS roles ───────────────────────────────────────
Write-Host "[promote-dc25] installing AD-DS + DNS roles..."
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools -ErrorAction Stop | Out-Null

# ── Promote to first DC of a new forest ─────────────────────────────
# Server 2025 functional level = 10. Use WinThreshold for max compat
# while still getting the new schema (which carries dMSA / etc.
# regardless of FFL).
Write-Host "[promote-dc25] running Install-ADDSForest (~5-10 min)..."
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

Write-Host "[promote-dc25] complete; the system will reboot."
