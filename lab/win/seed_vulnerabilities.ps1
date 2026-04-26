# lab/win/seed_vulnerabilities.ps1 - Stage 2: plant the v1+v2
# attack-surface vulns parallel to lab/seed_vulnerabilities.sh
# (Samba lab). Same finding set, real Windows AD this time so we
# also catch:
#   - dMSA (msDS-DelegatedManagedServiceAccount) - Server 2025 schema
#     not present here, so BadSuccessor module will see "no dMSAs"
#     (correct empty result on Server 2022)
#   - Real ADCS templates / CA - only if AD CS is installed (this
#     script skips it; ADCS validation gets its own lab box)
#   - Real GPP cpassword XMLs in SYSVOL with Windows-side ACL caps
#
# Idempotent: every account create is `try { New-ADUser } catch {}`
# so re-runs against a seeded DC don't fail.
#
# Default credentials match Vagrantfile.win2022.

$ErrorActionPreference = "Continue"

$Realm     = "kerblab2022.local"
$BaseDN    = "DC=kerblab2022,DC=local"
$SeedPass  = ConvertTo-SecureString "Summer2024!" -AsPlainText -Force

Import-Module ActiveDirectory -ErrorAction Stop

function New-SeedUser {
    param([string]$Name, [string]$Description = "")
    try {
        New-ADUser -Name $Name -SamAccountName $Name -UserPrincipalName "$Name@$Realm" -AccountPassword $SeedPass -Enabled $true -PasswordNeverExpires $true -Description $Description -ErrorAction Stop
        Write-Host "[seed] created user $Name"
    } catch {
        if ($_.Exception.Message -match "already exists") {
            Write-Host "[seed] user $Name exists - skipping"
        } else {
            $msg = $_.Exception.Message
            Write-Host "[seed] WARN creating ${Name}: $msg"
        }
    }
}

Write-Host "[seed] starting at $(Get-Date -Format o)"

# ── v1 - SPN scanner ────────────────────────────────────────────────
# svc_sql - MSSQLSvc SPN, weak password, RC4 only
New-SeedUser -Name "svc_sql" -Description "SQL service account"
try { Set-ADUser svc_sql -ServicePrincipalNames @{Add="MSSQLSvc/sql01.$Realm:1433"} -ErrorAction Stop } catch {}
try { Set-ADUser svc_sql -KerberosEncryptionType "RC4" -ErrorAction Stop } catch {}

New-SeedUser -Name "svc_iis" -Description "IIS service account"
try { Set-ADUser svc_iis -ServicePrincipalNames @{Add="HTTP/web01.$Realm"} -ErrorAction Stop } catch {}

# ── v1 - AS-REP scanner ─────────────────────────────────────────────
# oldsvc - DONT_REQUIRE_PREAUTH (legacy NIS-style account)
New-SeedUser -Name "oldsvc" -Description "Legacy account, pre-auth disabled"
try { Set-ADAccountControl oldsvc -DoesNotRequirePreAuth $true -ErrorAction Stop } catch {}

# ── v1 - Delegation mapper ──────────────────────────────────────────
# web01$ - Unconstrained Delegation (TRUSTED_FOR_DELEGATION)
try {
    New-ADComputer -Name "WEB01" -SamAccountName "WEB01$" -Enabled $true -ErrorAction Stop
} catch { if ($_.Exception.Message -notmatch "already exists") { Write-Host "WARN: $($_.Exception.Message)" } }
try { Set-ADAccountControl WEB01$ -TrustedForDelegation $true -ErrorAction Stop } catch {}

# ── v1 - User enumerator / hygiene ──────────────────────────────────
# admin_orphan - adminCount=1 but no protected group membership
New-SeedUser -Name "admin_orphan" -Description "Orphaned admin flag"
try { Set-ADUser admin_orphan -Replace @{adminCount=1} -ErrorAction Stop } catch {}

# cred_in_desc - pw= shorthand (closes the gap-#9 regression we fixed)
New-SeedUser -Name "svc_app" -Description "SQL svc - pw=Spring2024! rotate quarterly"

# ── v1 - Encryption auditor ─────────────────────────────────────────
# des_user - USE_DES_KEY_ONLY
New-SeedUser -Name "des_user" -Description "DES-only encryption (legacy)"
try { Set-ADUser des_user -KerberosEncryptionType "DES" -ErrorAction Stop } catch {}

# ── v1 - Paging (5000 stub users) ───────────────────────────────────
# Real Windows AD; New-ADUser is faster than samba-tool but still
# ~50-100ms each → 5000 users ≈ 5-8 min. Idempotent: skip if user5000
# already exists.
$stubCount = if ($env:STUB_COUNT) { [int]$env:STUB_COUNT } else { 1500 }
$lastStub  = "user{0:D4}" -f $stubCount
$exists = Get-ADUser -Filter "SamAccountName -eq '$lastStub'" -ErrorAction SilentlyContinue
if (-not $exists) {
    Write-Host "[seed] creating $stubCount stub users (slow path)..."
    for ($i = 1; $i -le $stubCount; $i++) {
        $n = "user{0:D4}" -f $i
        try {
            New-ADUser -Name $n -SamAccountName $n -UserPrincipalName "$n@$Realm" -AccountPassword $SeedPass -Enabled $true -PasswordNeverExpires $true -Description "Stub user #$i" -ErrorAction Stop
        } catch {}
    }
    Write-Host "[seed] stub users done."
} else {
    Write-Host "[seed] stub users already present (last=$lastStub)."
}

# ── v2 - DCSync rights backdoor ─────────────────────────────────────
# svc_old_admin - granted DS-Replication-Get-Changes / Get-Changes-All
# on the domain root via DSACLS. Same effect as samba-tool dsacl set.
New-SeedUser -Name "svc_old_admin" -Description "Legacy account with DCSync grant"
# dsacls.exe wants the *display names* of the extended rights, not the
# schema CN — "DS-Replication-Get-Changes" returns "No GUID Found".
# Field bug from the v1.3 sprint Win22 validation (kerb-map silently
# reported zero DCSync rights against this lab because the seed never
# actually applied the ACE). Use the friendly display names that
# dsacls recognises.
foreach ($right in @(
    "Replicating Directory Changes",
    "Replicating Directory Changes All",
    "Replicating Directory Changes In Filtered Set"
)) {
    & dsacls.exe $BaseDN /G "$($env:USERDOMAIN)\svc_old_admin:CA;$right" 2>&1 | Out-Null
}

# ── v2 - Shadow Credentials ─────────────────────────────────────────
# bob_da - Domain Admin (so Shadow Credentials inventory flags it)
# helpdesk_op - has WriteProperty on bob_da's msDS-KeyCredentialLink
New-SeedUser -Name "bob_da" -Description "Domain admin - KCL writable by helpdesk"
try { Add-ADGroupMember -Identity "Domain Admins" -Members bob_da -ErrorAction Stop } catch {}
try { Set-ADUser bob_da -Replace @{adminCount=1} -ErrorAction Stop } catch {}

New-SeedUser -Name "helpdesk_op" -Description "Helpdesk operator with KCL write"
# Grant helpdesk_op WriteProperty on bob_da's msDS-KeyCredentialLink.
#
# Field bug from the v1.3 sprint Win22 validation: a direct ACE on
# bob_da gets wiped by AdminSDHolder/SDProp, which fires automatically
# when bob_da is added to Domain Admins (and again every 60 min). The
# real-world fix is to modify AdminSDHolder's DACL itself — SDProp
# then propagates the helpdesk_op ACE to every protected account on
# the next cycle. Setting it on the AdminSDHolder template *and* on
# bob_da gives both immediate effect and persistence.
$bobDn = (Get-ADUser bob_da).DistinguishedName
$adminSdhDn = "CN=AdminSDHolder,CN=System,$BaseDN"
foreach ($dn in @($bobDn, $adminSdhDn)) {
    & dsacls.exe $dn /G "$($env:USERDOMAIN)\helpdesk_op:WP;msDS-KeyCredentialLink" 2>&1 | Out-Null
}
# Trigger SDProp to immediately propagate (otherwise wait ≤60 min).
$rootDse = [ADSI]"LDAP://RootDSE"
$rootDse.Put("RunProtectAdminGroupsTask", 1)
$rootDse.SetInfo()

# ── v2 - Tier-0 ACL audit ───────────────────────────────────────────
# Account Operators already has WriteDACL on protected groups by
# Windows default - Tier-0 ACL audit will surface this without seeding.

# ── v1 - GPP cpassword (MS14-025) ───────────────────────────────────
# Drop a Groups.xml under the Default Domain Policy GPO with
# Password1! encrypted via the MS-published key. Same payload as
# the Samba seed.
$DefaultGpoGuid = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
$GppDir = "C:\Windows\SYSVOL\sysvol\$Realm\Policies\$DefaultGpoGuid\Machine\Preferences\Groups"
New-Item -Path $GppDir -ItemType Directory -Force | Out-Null
$xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="helpdesk_admin"
        image="2"
        changed="2014-01-01 00:00:00"
        uid="{A1B2C3D4-1234-5678-9ABC-DEF012345678}">
    <Properties action="U"
                newName=""
                fullName="Helpdesk Admin"
                description="Local admin pushed via GPP - pre-MS14-025"
                cpassword="VPe/o9YRyz2cksnYRbNeQunV3jqnKFX4lk/mmt8mza8"
                changeLogon="0"
                noChange="0"
                neverExpires="0"
                acctDisabled="0"
                subAuthority=""
                userName="helpdesk_admin"/>
  </User>
</Groups>
'@
Set-Content -Path "$GppDir\Groups.xml" -Value $xml -Encoding UTF8

Write-Host "[seed] complete at $(Get-Date -Format o)"
Write-Host "[seed] Expected kerb-map findings against $Realm :"
Write-Host "  CRITICAL  DCSync (full)                       svc_old_admin"
Write-Host "  CRITICAL  Shadow Credentials (write)          bob_da (helpdesk_op writes)"
Write-Host "  CRITICAL  GPP cpassword (MS14-025)            helpdesk_admin / Password1!"
Write-Host "  CRITICAL  Unconstrained Delegation            WEB01\$"
Write-Host "  HIGH      Kerberoast                          svc_sql / svc_iis"
Write-Host "  HIGH      AS-REP Roast                        oldsvc"
Write-Host "  HIGH      Pre-Win2k membership                Authenticated Users"
Write-Host "  MEDIUM    Credential exposure (description)   svc_app"
