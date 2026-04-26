# lab/win/promote_rodc.ps1 — RODC promotion of kerb-lab-rodc22.
#
# Two-stage script driven from the host over WinRM after the box is up.
# Vagrant's `vagrant up` reliably gets us a member-server-ready Windows
# install but bails before any provisioner runs (observed on every
# `gusztavvargadr/windows-server-2022-standard` box in this sprint),
# so we drive everything from outside.
#
# Stage 1: configure host-only IP + point DNS at dc22 + domain-join.
#          Reboot.
# Stage 2: install AD-DS role + Install-ADDSDomainController with
#          -ReadOnlyReplica:$true. Reboot.
# Stage 3 (optional): seed differential RODC state — set the Password
#          Replication Policy so a couple of accounts cache here.

param(
    [string]$DcIp     = "192.168.57.22",
    [string]$RodcIp   = "192.168.57.23",
    [string]$Domain   = "kerblab2022.local",
    [string]$Netbios  = "KERBLAB22",
    [string]$AdminUser = "Administrator",
    [string]$AdminPwd  = "vagrant",
    [int]   $Stage     = 1
)

$ErrorActionPreference = "Stop"

if ($Stage -eq 1) {
    Write-Host "[rodc-stage1] starting at $(Get-Date -Format o)"

    # ── Static IP on host-only adapter ───────────────────────────────
    # Vagrant's private_network sets this in vagrantfile but the box
    # often boots with link-local. Force it.
    $ifIndex = (Get-NetIPInterface -AddressFamily IPv4 |
        Where-Object { $_.ConnectionState -eq "Connected" -and $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1" } |
        Sort-Object InterfaceMetric |
        Select-Object -Last 1).InterfaceIndex
    Write-Host "[rodc-stage1] host-only InterfaceIndex: $ifIndex"
    Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $RodcIp -PrefixLength 24 -ErrorAction Stop | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses ($DcIp)
    # The new NIC was auto-classified Public — flip to Private and
    # disable the Private firewall profile so kerb-map can reach SMB.
    Set-NetConnectionProfile -InterfaceIndex $ifIndex -NetworkCategory Private -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -Profile Private -Enabled False

    # ── Domain join ───────────────────────────────────────────────────
    $secPwd = ConvertTo-SecureString $AdminPwd -AsPlainText -Force
    $cred   = New-Object System.Management.Automation.PSCredential("$Netbios\$AdminUser", $secPwd)
    Add-Computer -DomainName $Domain -Credential $cred -Force -ErrorAction Stop
    Write-Host "[rodc-stage1] domain-joined; reboot required."
    # Caller (host) handles the reboot wait.
}
elseif ($Stage -eq 2) {
    Write-Host "[rodc-stage2] starting at $(Get-Date -Format o)"

    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop | Out-Null

    $secPwd = ConvertTo-SecureString $AdminPwd -AsPlainText -Force
    $cred   = New-Object System.Management.Automation.PSCredential("$Netbios\$AdminUser", $secPwd)
    $dsrm   = ConvertTo-SecureString "LabAdmin1!" -AsPlainText -Force

    Install-ADDSDomainController `
        -DomainName $Domain `
        -InstallDns `
        -ReadOnlyReplica `
        -SiteName "Default-First-Site-Name" `
        -Credential $cred `
        -SafeModeAdministratorPassword $dsrm `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -NoGlobalCatalog:$false `
        -NoRebootOnCompletion:$false `
        -Force:$true

    Write-Host "[rodc-stage2] RODC promotion complete; rebooting."
}
else {
    throw "Unknown -Stage $Stage; valid values 1 or 2"
}
