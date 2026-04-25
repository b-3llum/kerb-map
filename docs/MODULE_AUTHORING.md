# Authoring a v2 plugin module

This guide walks through adding a new attack-surface module to
kerb-map. The v2 plugin contract is small — drop a Python file under
`kerb_map/modules/`, decorate the class with `@register`, and the CLI
discovers it automatically. No registration list to maintain.

## The contract

```python
from kerb_map.plugin import Module, ScanContext, ScanResult, Finding, register


@register
class YourModule(Module):
    name        = "Human-readable name (shows in scan output)"
    flag        = "your-module"          # used as `v2:your-module` in resume state
    description = "One-liner that --list-modules will print"
    category    = "attack-path"          # 'attack-path' | 'cve' | 'enumeration' | 'hygiene'
    in_default_run = True                # False = needs explicit flag

    def scan(self, ctx: ScanContext) -> ScanResult:
        ...
        return ScanResult(raw={...}, findings=[Finding(...)])
```

Required class attrs: `name`, `flag`, `description`, `category`. The
`@register` decorator adds the class to a process-wide registry that
`pkgutil.walk_packages` finds at scan time.

## What's in `ScanContext`

```python
ctx.ldap          # LDAPClient — bound, paged, transport-fallback'd
ctx.domain        # 'corp.local'
ctx.base_dn       # 'DC=corp,DC=local'
ctx.dc_ip         # '10.0.0.1'
ctx.aggressive    # True if --aggressive — gate RPC probes here
ctx.domain_info   # dict from get_domain_info(): domain_sid, FL,
                  # MAQ, lockout_threshold, dc_dns_hostname, etc.
ctx.domain_sid    # convenience — same as domain_info['domain_sid']
```

If your module needs the operator's password / hash, add it to the
`ScanContext` dataclass first — currently kerb-map runs on the
already-bound LDAP connection, so SMB / RPC plumbing needs the
extra round of work.

## Issuing LDAP queries

```python
entries = ctx.ldap.query(
    search_filter="(objectClass=user)",
    attributes=["sAMAccountName", "objectSid"],
    # Optional — only when reading nTSecurityDescriptor:
    controls=sd_control(),
)
```

Always go through `ctx.ldap.query()` — it pages results past
MaxPageSize, handles the SD control quirks, and surfaces transport
errors uniformly. Direct `ctx.ldap.conn.search()` calls bypass
the paging.

For Configuration-NC reads (KDS root keys, ADCS templates,
trustedDomain, etc.) use `ctx.ldap.query_config()` — same shape but
auto-prepends `CN=Configuration,...`.

## Walking nTSecurityDescriptor

Reading a DACL is a two-step process:

```python
from kerb_map.acl import parse_sd, walk_aces, sd_control, resolve_sids

# 1. Ask for the SD bytes via the SDFlags control:
entries = ctx.ldap.query(
    search_filter="(objectClass=user)",
    attributes=["sAMAccountName", "nTSecurityDescriptor"],
    controls=sd_control(),
)

# 2. Parse + walk:
for entry in entries:
    sd = parse_sd(attr(entry, "nTSecurityDescriptor"))
    if sd is None:
        continue
    for ace in walk_aces(sd, object_dn=attr(entry, "distinguishedName")):
        if is_well_known_privileged(ace.trustee_sid):
            continue
        if ace.has_right(ADS_RIGHT_GENERIC_ALL):
            ...

# 3. (Optional) batch-resolve writer SIDs to friendly names:
names = resolve_sids(ctx.ldap, {ace.trustee_sid for ...}, ctx.base_dn)
sam = names.get(sid, {}).get("sAMAccountName") or sid
```

`AceMatch` exposes:

| field | meaning |
|---|---|
| `object_dn` | DN you passed in (echoed back for grouping) |
| `trustee_sid` | who has the right |
| `access_mask` | raw mask bits |
| `object_type_guid` | for object-typed ACEs (extended rights, property writes) |
| `ace_type` | `0x00` allowed, `0x05` allowed-object |

And the convenience checks:

| method | when to use |
|---|---|
| `ace.has_right(ADS_RIGHT_*)` | check a specific bit |
| `ace.has_extended_right(GUID)` | DCSync, ManageCA, etc. |
| `ace.has_write_property(ATTR_GUID)` | KCL, member, SPN, UPN writes |

Real DACLs often carry an *expanded* full-control mask (`0xf01ff`)
instead of `ADS_RIGHT_GENERIC_ALL` (`0x10000000`). The expansion
includes WRITE_DAC + WRITE_OWNER, so `has_right(ADS_RIGHT_WRITE_DAC)`
catches it. The classifier convention in `tier0_acl.py` and
`user_acl.py` lists rights in priority order so the loudest one
wins.

## Emitting findings

```python
from kerb_map.plugin import Finding

findings = [
    Finding(
        target="DC01$",
        attack="DCSync (full)",
        severity="CRITICAL",      # CRITICAL | HIGH | MEDIUM | LOW | INFO
        priority=99,              # 0-100; Scorer sorts desc by this
        reason="...",
        next_step="secretsdump.py -dc-ip <DC_IP> -just-dc <DOMAIN>/<USER>:<PASS>@<DC_FQDN>",
        category="attack-path",   # mirrors Module.category by convention
        mitre="T1003.006",        # MITRE ATT&CK technique id (optional)
        data={                    # arbitrary dict — exporters / kerb-chain consume this
            "principal_sid":   sid,
            "rights_granted":  ["Get-Changes", "Get-Changes-All"],
            "domain_sid":      ctx.domain_sid,
        },
    ),
]
```

`<DC_IP>`, `<DOMAIN>`, `<DOMAIN_SID>`, `<DC_NAME>`, `<DC_FQDN>`,
`<DC_HOSTNAME>`, `<BASE>` are auto-substituted before the recipe
hits the operator's terminal — see `kerb_map/substitute.py`. Other
placeholders (`<USER>`, `<PASS>`, `<ATTACKER_IP>`, `<victim>`,
`<TPL>`, `<CA>`) stay literal because the operator picks them.

## Returning ScanResult

```python
return ScanResult(
    raw={
        "applicable": True,            # False = module had nothing to look at
        "audited":    [t["sam"] for t in targets],
        "summary":    {"audited": len(targets), "findings": len(findings)},
    },
    findings=findings,
)
```

`raw` is what lands in the JSON export and the BloodHound CE custom-
edges path. Keep the keys stable across versions so consumers don't
break.

`findings` are what land in the priority table and Scorer's ranked
output. Not every module emits findings — pure inventory modules
(e.g. trust mapping when nothing is wrong) can return `findings=[]`
with rich `raw`.

## Adding a BloodHound CE custom edge

If your finding has a clear (source, target) pair that BloodHound
operators would Cypher on, wire a custom edge in
`kerb_map/output/bloodhound_ce.py`:

```python
elif attack.startswith("Your Module:") and data.get("writer_sid"):
    self._extra_edges.append({
        "source": data["writer_sid"],
        "target": data.get("target_dn") or data.get("target_sid") or "",
        "edge":   "KerbMapYourEdge",
        "props":  {"right": data.get("right")},
    })
```

`KerbMap*` is the convention — operators can `MATCH (u)-
[:KerbMapYourEdge]->(t)` to query the graph.

## Tests

Mirror the structure under `tests/`. Mock LDAP at the client level —
**don't** spin up a real DC. The patterns:

```python
from unittest.mock import MagicMock
from kerb_map.modules.your_module import YourModule
from kerb_map.plugin import ScanContext


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.__str__ = lambda self: "" if v is None else str(v)
        m.__iter__ = lambda self: iter(v) if isinstance(v, list) else iter([v])
        return m
    e.__getitem__ = _get
    return e


def _ctx(query_responses):
    ldap = MagicMock()
    ldap.query.side_effect = lambda **_: query_responses.pop(0) if query_responses else []
    return ScanContext(
        ldap=ldap, domain="corp.local", base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1", domain_sid="S-1-5-21-1-2-3",
    )


def test_my_module_emits_critical_when_X(monkeypatch):
    # If the module walks DACLs, also patch parse_sd / walk_aces /
    # resolve_sids on the MODULE'S namespace, not on acl.py:
    monkeypatch.setattr("kerb_map.modules.your_module.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr("kerb_map.modules.your_module.walk_aces",
                        lambda sd, object_dn="": [...])
    ...
```

Coverage gate is `--cov-fail-under=65` on `kerb_map.modules`. New
modules should clear that bar individually — see the existing tests
in `tests/test_*.py` for the standard patterns.

## Field validation

Mocked tests miss real-protocol bugs. Before considering a module
"done", run it against a real DC:

```bash
python kerb-map.py -d corp.local -dc 10.10.10.10 -u <u> -p <p> --v2
```

Watch for `[!] LDAP query failed (...)` lines from `ldap_client` —
those are silent failures the unit tests didn't catch. The
`sd_control()` / `walk_aces()` field bugs surfaced exactly that way.

The lab in `lab/` (Samba 4 on Vagrant) seeds intentionally-vulnerable
objects across most attack surfaces — bring it up with `vagrant up`
and scan.
