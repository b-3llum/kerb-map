# Extending kerb-map

> How to add new CVE checks, enumeration modules, and scoring rules.

---

## Project Entry Point Structure

Understanding how the CLI is wired is important before extending the tool:

```
kerb-map/
├── kerb-map.py          ← Direct script (python kerb-map.py ...) — kept for convenience
└── kerb_map/
    ├── main.py          ← pipx/pip entry point — delegates to cli.py
    ├── cli.py           ← Full CLI logic (argparse, run_scan, etc.)
    ├── __main__.py      ← Enables python -m kerb_map
    └── ...
```

**`kerb_map/main.py`** is the entry point registered in `pyproject.toml`:
```python
[project.scripts]
kerb-map = "kerb_map.main:main"
```

It simply delegates to `cli.py`:
```python
def main():
    from kerb_map.cli import main as _main
    _main()
```

**`kerb_map/cli.py`** contains the full CLI — `build_parser()`, `run_scan()`, `cmd_list_scans()`, `cmd_show_scan()`, and `main()`. This is where you add new flags, new module calls, and new output options.

**`kerb-map.py`** at the root is kept so users can still run `python kerb-map.py` without installing. It is identical to `cli.py`.

---

## Adding a CVE Module

All CVE modules inherit from `CVEBase` and return a `CVEResult` dataclass. Adding a new check is three steps.

### Step 1 — Create the module file

```python
# kerb_map/modules/cves/my_cve.py

from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()


class MyCVE(CVEBase):
    CVE_ID = "CVE-XXXX-XXXX"
    NAME   = "My Vulnerability Name"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID}...")

        vulnerable = self._my_detection_logic()

        return CVEResult(
            cve_id      = self.CVE_ID,
            name        = self.NAME,
            severity    = Severity.HIGH,
            vulnerable  = vulnerable,
            reason      = "Detected because..." if vulnerable else "Not vulnerable",
            evidence    = {"key": "value"},
            remediation = "Apply patch XYZ. Configure setting ABC.",
            next_step   = f"exploit_tool.py {self.domain}/user:pass@{self.dc_ip}"
                          if vulnerable else "",
            references  = ["https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX"],
        )

    def _my_detection_logic(self) -> bool:
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["someAttribute"],
        )
        if entries:
            value = entries[0]["someAttribute"].value
            return value == "vulnerable_condition"
        return False
```

### Step 2 — Register in the CVE scanner

```python
# kerb_map/modules/cve_scanner.py

from kerb_map.modules.cves.my_cve import MyCVE

class CVEScanner:
    def __init__(self, ldap_client, dc_ip, domain):
        self._safe = [
            NoPac(ldap_client, dc_ip, domain),
            ADCSAudit(ldap_client, dc_ip, domain),
            MS14068(ldap_client, dc_ip, domain),
            MyCVE(ldap_client, dc_ip, domain),   # ← safe check (LDAP only)
        ]
        self._loud = [
            ZeroLogon(ldap_client, dc_ip, domain),
            PrintNightmare(ldap_client, dc_ip, domain),
            PetitPotam(ldap_client, dc_ip, domain),
            # MyCVE here instead if it generates event log noise
        ]
```

### Step 3 — Test it

```bash
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --cves
```

---

## Adding an Enumeration Module

### Step 1 — Create the module

```python
# kerb_map/modules/my_enumerator.py

from typing import Dict, Any, List
from kerb_map.output.logger import Logger

log = Logger()


class MyEnumerator:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def enumerate(self) -> Dict[str, Any]:
        log.info("Running my custom enumeration...")
        return {
            "my_findings": self._find_things(),
        }

    def _find_things(self) -> List[Dict]:
        entries = self.ldap.query(
            search_filter="(objectClass=user)",
            attributes=["sAMAccountName", "someAttribute"],
        )
        results = []
        for e in entries:
            results.append({
                "account": str(e["sAMAccountName"]),
                "value":   str(e["someAttribute"].value or ""),
            })
        return results
```

### Step 2 — Wire into cli.py

```python
# kerb_map/cli.py

from kerb_map.modules.my_enumerator import MyEnumerator

# In run_scan():
my_data = MyEnumerator(ldap).enumerate()

# Add to full_data dict:
full_data["my_data"] = my_data
```

### Step 3 — Add to scorer (optional)

```python
# kerb_map/modules/scorer.py

# In rank():
for item in user_data.get("my_findings", []):
    if item["value"] == "high_risk_condition":
        targets.append({
            "target":   item["account"],
            "attack":   "My Custom Attack",
            "priority": 80,
            "severity": "HIGH",
            "reason":   f"Custom condition: {item['value']}",
            "next_step":"custom_exploit.py ...",
            "category": "custom",
        })
```

---

## Adding a New CLI Flag

Add flags in `cli.py` inside `build_parser()`, then handle them in `run_scan()`:

```python
# In build_parser():
p.add_argument("--my-flag", action="store_true", help="Enable my custom check")

# In run_scan():
if args.my_flag:
    my_data = MyEnumerator(ldap).enumerate()
```

---

## CVEResult Fields Reference

| Field | Type | Description |
|---|---|---|
| `cve_id` | str | CVE identifier (e.g. "CVE-2020-1472") |
| `name` | str | Human-readable name |
| `severity` | Severity enum | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `vulnerable` | bool | True = vulnerable condition detected |
| `reason` | str | Why it's vulnerable (or not) |
| `evidence` | dict | Raw data that led to the finding |
| `remediation` | str | How to fix it |
| `next_step` | str | Exact exploit command if vulnerable |
| `references` | list | CVE/advisory URLs |

## Severity Enum

```python
from kerb_map.modules.cves.cve_base import Severity

Severity.CRITICAL   # CVSS 9.0-10.0
Severity.HIGH       # CVSS 7.0-8.9
Severity.MEDIUM     # CVSS 4.0-6.9
Severity.LOW        # CVSS 0.1-3.9
Severity.INFO       # Informational
```

## LDAP Query Helper Methods

```python
# Standard query (base DN)
self.ldap.query(search_filter, attributes, size_limit=0)

# Configuration partition (AD CS, schema)
self.ldap.query_config(search_filter, attributes)

# Domain info
self.ldap.get_domain_info()

# Available attributes:
self.ldap.base_dn      # e.g. "DC=corp,DC=local"
self.ldap.domain       # e.g. "corp.local"
self.ldap.dc_ip        # e.g. "192.168.1.10"
self.ldap.username     # authenticated user
```
