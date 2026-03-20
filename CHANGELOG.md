# Changelog

All notable changes to kerb-map will be documented in this file.

## [1.1.0] — 2025

### Added
- **Hygiene Auditor** module (`--hygiene`) — 10 defensive security checks:
  - SID History abuse detection
  - LAPS deployment coverage analysis (legacy + Windows LAPS)
  - krbtgt password age assessment
  - AdminSDHolder orphan detection
  - Fine-Grained Password Policy (FGPP) audit
  - Credential exposure in description/info fields
  - PrimaryGroupId manipulation detection
  - Stale computer account identification
  - Privileged group membership breakdown
  - Service account password hygiene
- **Encryption Auditor** module (`--encryption`) — RC4/DES weakness detection on accounts and DCs
- **Trust Mapper** module (`--trusts`) — domain trust enumeration with SID filtering risk assessment
- **CVE Checks** expanded to 10:
  - noPac (CVE-2021-42278/42287)
  - ZeroLogon (CVE-2020-1472) — aggressive only
  - PrintNightmare (CVE-2021-1675) — aggressive only
  - PetitPotam (CVE-2021-36942) — aggressive only
  - AD CS ESC1-ESC8 certificate abuse
  - GPP Passwords (MS14-025)
  - Bronze Bit (CVE-2020-17049)
  - Certifried (CVE-2022-26923)
  - LDAP Signing enforcement
  - MS14-068 PAC Forgery
- `--update` flag for self-updating via git pull + pipx/pip reinstall
- BloodHound v5 JSON export with custom nodes for delegation, Kerberoast, and hygiene findings
- SQLite scan caching with `--list-scans` and `--show-scan` replay
- Stealth mode (`--stealth`) with LDAP query jitter

### Changed
- Scorer now integrates findings from all modules (encryption, trusts, hygiene)
- Reporter output expanded with remediation guidance for hygiene findings

## [1.0.0] — 2025

### Added
- Initial release
- SPN Scanner — Kerberoastable account discovery with risk scoring
- AS-REP Scanner — pre-authentication disabled accounts
- Delegation Mapper — unconstrained, constrained, and RBCD
- User Enumerator — privileged users, password policy, DnsAdmins, LAPS
- CVE Scanner framework with safe/aggressive separation
- JSON export
- Pass-the-Hash and Kerberos ccache authentication
