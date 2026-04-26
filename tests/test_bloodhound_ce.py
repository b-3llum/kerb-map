"""BloodHound CE exporter — produces ingestible zip + custom edges from findings.

Doesn't actually upload to a BH instance (that's the lab acceptance test);
covers the JSON shape, edge translation from findings, and the zip
structure.
"""

import json
import zipfile
from unittest.mock import MagicMock

import pytest

from kerb_map.output.bloodhound_ce import BloodHoundCEExporter
from kerb_map.plugin import Finding


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.values = v if isinstance(v, list) else [v]
        return m
    e.__getitem__ = _get
    return e


def _ldap(query_responses):
    """Build a fake LDAP whose .query() returns these responses in order
    of call (one response per query call)."""
    ldap = MagicMock()
    queue = list(query_responses)
    ldap.query.side_effect = lambda **_: queue.pop(0) if queue else []
    return ldap


SAMPLE_USER = _entry({
    "sAMAccountName":           "jsmith",
    "objectSid":                bytes.fromhex(
        "0105000000000005150000000a000000140000001e0000005d030000"
    ),  # S-1-5-21-10-20-30-861
    "distinguishedName":        "CN=jsmith,CN=Users,DC=corp,DC=local",
    "userAccountControl":       0x10200,
    "servicePrincipalName":     ["HTTP/web01.corp.local"],
    "memberOf":                 [],
    "primaryGroupID":           513,
    "adminCount":               None,
    "pwdLastSet":               132000000000000000,
    "lastLogonTimestamp":       133500000000000000,
    "description":              None,
    "sIDHistory":               [],
    "msDS-AllowedToDelegateTo": [],
})


# ─────────────────────────────────── zip structure + meta ----


def test_export_writes_four_required_json_files(tmp_path):
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[SAMPLE_USER], [], [], []]),  # users, computers, groups, domain (last unused)
        domain="corp.local",
        domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    out = exporter.export(str(tmp_path / "scan.zip"))

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert {"users.json", "computers.json", "groups.json", "domains.json"} <= names


def test_meta_block_has_required_fields(tmp_path):
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[SAMPLE_USER], [], [], []]),
        domain="corp.local",
        domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        users = json.loads(zf.read("users.json"))
    meta = users["meta"]
    assert meta["type"] == "users"
    assert meta["count"] == 1
    assert meta["version"] >= 5  # BH CE 5.x or higher
    assert "collectorversion" in meta
    assert "collectortimestamp" in meta


# ─────────────────────────────────── user shape ----


def test_user_node_uses_full_domain_sid_format(tmp_path):
    """BH CE rejects nodes without a real S-1-5-21-... ObjectIdentifier
    — the brief's whole §1.6 problem in one assertion."""
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[SAMPLE_USER], [], [], []]),
        domain="corp.local",
        domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        users = json.loads(zf.read("users.json"))
    node = users["data"][0]
    assert node["ObjectIdentifier"].startswith("S-1-5-21-")
    # Critical SharpHound parity properties:
    assert node["Properties"]["hasspn"] is True
    assert node["Properties"]["enabled"] is True
    assert node["PrimaryGroupSID"] == "S-1-5-21-10-20-30-513"
    assert "serviceprincipalnames" in node["Properties"]
    assert node["Properties"]["serviceprincipalnames"] == ["HTTP/web01.corp.local"]


def test_user_with_account_disabled_flag_is_marked_disabled(tmp_path):
    disabled = _entry({
        "sAMAccountName":     "olduser",
        "objectSid":          bytes.fromhex(
            "0105000000000005150000000a000000140000001e0000005d040000"),
        "distinguishedName":  "CN=olduser,...",
        "userAccountControl": 0x202,  # ACCOUNTDISABLE | NORMAL_ACCOUNT
        "servicePrincipalName": [],
        "memberOf":           [],
        "primaryGroupID":     513,
        "adminCount":         None,
        "pwdLastSet":         0,
        "lastLogonTimestamp": 0,
        "description":        None,
        "sIDHistory":         [],
        "msDS-AllowedToDelegateTo": [],
    })
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[disabled], [], [], []]),
        domain="corp.local",
        domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        users = json.loads(zf.read("users.json"))
    assert users["data"][0]["Properties"]["enabled"] is False


# ─────────────────────────────────── domain node ----


def test_domain_node_present_when_sid_known(tmp_path):
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local",
        domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        doms = json.loads(zf.read("domains.json"))
    assert len(doms["data"]) == 1
    assert doms["data"][0]["ObjectIdentifier"] == "S-1-5-21-10-20-30"


def test_domain_node_absent_when_sid_unknown(tmp_path):
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local",
        domain_sid=None,  # didn't capture it for some reason
        base_dn="DC=corp,DC=local",
    )
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        doms = json.loads(zf.read("domains.json"))
    assert doms["data"] == []


# ─────────────────────────────────── custom edges from findings ----


def test_dcsync_finding_emits_kerbmap_dcsyncby_edge(tmp_path):
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local",
        domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="svc_old", attack="DCSync (full)",
        severity="CRITICAL", priority=95, reason="...",
        data={"principal_sid": "S-1-5-21-10-20-30-1234",
              "rights_granted": ["Get-Changes", "Get-Changes-All"]},
    )])
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        edges = json.loads(zf.read("_kerbmap_metadata.json"))
    assert edges["meta"]["type"] == "kerbmap_metadata"
    edge = edges["data"][0]
    assert edge["edge"]   == "KerbMapDCSyncBy"
    assert edge["source"] == "S-1-5-21-10-20-30-1234"
    assert edge["target"] == "S-1-5-21-10-20-30"
    assert "rights" in edge["props"]


def test_shadow_creds_write_finding_emits_addkeycredentiallink_edge(tmp_path):
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="bob_da", attack="Shadow Credentials (write access)",
        severity="CRITICAL", priority=92, reason="...",
        data={"writer_sid": "S-1-5-21-10-20-30-1500",
              "target_dn":  "CN=bob_da,..."},
    )])
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        edges = json.loads(zf.read("_kerbmap_metadata.json"))
    assert edges["data"][0]["edge"] == "KerbMapAddKeyCredentialLink"
    assert edges["data"][0]["source"] == "S-1-5-21-10-20-30-1500"


def test_badsuccessor_writable_ou_finding_emits_cancreatedmsa_edge(tmp_path):
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="ou_admin on OU=Lab,DC=corp,DC=local",
        attack="BadSuccessor (writable OU)",
        severity="HIGH", priority=88, reason="...",
        data={"principal_sid": "S-1-5-21-10-20-30-1500",
              "ou_dn":         "OU=Lab,DC=corp,DC=local"},
    )])
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        edges = json.loads(zf.read("_kerbmap_metadata.json"))
    assert edges["data"][0]["edge"] == "KerbMapCanCreateDMSA"


def test_no_extra_edges_means_no_kerbmap_edges_file(tmp_path):
    """Don't pollute the zip with empty edge files."""
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        assert "_kerbmap_metadata.json" not in zf.namelist()


def test_findings_without_required_data_are_skipped(tmp_path):
    """A finding with no data fields → no edge, no crash."""
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="x", attack="DCSync (full)", severity="CRITICAL",
        priority=95, reason="...", data={},  # no principal_sid
    )])
    out = exporter.export(str(tmp_path / "scan.zip"))
    with zipfile.ZipFile(out) as zf:
        assert "_kerbmap_metadata.json" not in zf.namelist()


# ─────────────────────────── new v2 modules → edges ────────────


def _exporter():
    return BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )


def _read_edges(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("_kerbmap_metadata.json"))["data"]


def test_esc9_finding_emits_kerbmap_esc9_edge(tmp_path):
    exp = _exporter()
    exp.add_findings([Finding(
        target="EnrolledUserCert",
        attack="AD CS ESC9 (no security extension)",
        severity="HIGH", priority=82, reason="...",
        data={"template_dn": "CN=EnrolledUserCert,...", "enroll_flag": "0x80"},
    )])
    out = exp.export(str(tmp_path / "esc9.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    assert edges[0]["edge"] == "KerbMapEsc9"
    assert edges[0]["source"].startswith("CN=EnrolledUserCert")
    assert edges[0]["props"]["enroll_flag"] == "0x80"


def test_esc13_finding_emits_one_edge_per_linked_group(tmp_path):
    """Operator wants to write `MATCH (t)-[:KerbMapEsc13LinkedTo]->(g)`
    so each (template, group) pair is queryable individually."""
    exp = _exporter()
    exp.add_findings([Finding(
        target="AdminCert",
        attack="AD CS ESC13 (OIDToGroupLink)",
        severity="CRITICAL", priority=92, reason="...",
        data={
            "template_dn": "CN=AdminCert,...",
            "linked_groups": [
                {"oid": "1.2.3", "group": {"name": "Domain Admins"}, "sid": "S-1-5-21-10-20-30-512"},
                {"oid": "4.5.6", "group": {"name": "Schema Admins"}, "sid": "S-1-5-21-10-20-30-518"},
            ],
        },
    )])
    out = exp.export(str(tmp_path / "esc13.zip"))
    edges = _read_edges(out)
    assert len(edges) == 2
    targets = {e["target"] for e in edges}
    assert targets == {"S-1-5-21-10-20-30-512", "S-1-5-21-10-20-30-518"}
    for e in edges:
        assert e["edge"] == "KerbMapEsc13LinkedTo"


def test_esc15_finding_emits_kerbmap_esc15_edge(tmp_path):
    exp = _exporter()
    exp.add_findings([Finding(
        target="WebServer",
        attack="AD CS ESC15 / EKUwu (CVE-2024-49019)",
        severity="HIGH", priority=80, reason="...",
        data={"template_dn": "CN=WebServer,...", "schema_version": 1},
    )])
    out = exp.export(str(tmp_path / "esc15.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    assert edges[0]["edge"] == "KerbMapEsc15"
    assert edges[0]["props"]["schema_version"] == 1


def test_prewin2k_member_emits_membership_edge(tmp_path):
    exp = _exporter()
    exp.add_findings([Finding(
        target="BUILTIN\\Pre-Windows 2000 Compatible Access",
        attack="Pre-Win2k membership: Authenticated Users",
        severity="HIGH", priority=78, reason="...",
        data={"member_sid": "S-1-5-11", "member_name": "Authenticated Users"},
    )])
    out = exp.export(str(tmp_path / "prewin2k.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    assert edges[0]["edge"] == "KerbMapPreWin2kMember"
    assert edges[0]["source"] == "S-1-5-11"
    assert edges[0]["target"] == "S-1-5-32-554"


def test_anonymous_ldap_compound_finding_emits_domain_edge(tmp_path):
    exp = _exporter()
    exp.add_findings([Finding(
        target="dsHeuristics + Pre-Win2k",
        attack="Anonymous LDAP binds enabled with permissive Pre-Win2k",
        severity="CRITICAL", priority=96, reason="...",
        data={"ds_heuristics": "0000002"},
    )])
    out = exp.export(str(tmp_path / "anon.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    assert edges[0]["edge"] == "KerbMapAnonymousLdapEnabled"


def test_kds_root_key_finding_emits_one_edge_per_reader(tmp_path):
    """Each extra reader gets its own edge so individual principals
    are queryable in BloodHound."""
    exp = _exporter()
    exp.add_findings([Finding(
        target="KDS root key key1",
        attack="Golden dMSA prerequisite (KDS root key readable)",
        severity="CRITICAL", priority=97, reason="...",
        data={
            "kds_key_cn":        "key1",
            "extra_reader_sids": ["S-1-5-21-10-20-30-1500", "S-1-5-21-10-20-30-1501"],
            "extra_reader_sams": ["alice", "bob"],
        },
    )])
    out = exp.export(str(tmp_path / "kds.zip"))
    edges = _read_edges(out)
    assert len(edges) == 2
    sources = {e["source"] for e in edges}
    assert sources == {"S-1-5-21-10-20-30-1500", "S-1-5-21-10-20-30-1501"}
    for e in edges:
        assert e["edge"] == "KerbMapKdsReadable"
        assert e["target"] == "key1"


def test_gmsa_reader_finding_emits_one_edge_per_reader(tmp_path):
    exp = _exporter()
    exp.add_findings([Finding(
        target="gmsa_app$",
        attack="gMSA password readable by non-default principal",
        severity="HIGH", priority=82, reason="...",
        data={
            "extra_reader_sids": ["S-1-5-21-10-20-30-1700"],
            "extra_reader_sams": ["appsupport"],
        },
    )])
    out = exp.export(str(tmp_path / "gmsa.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    assert edges[0]["edge"] == "KerbMapGmsaReader"
    assert edges[0]["source"] == "S-1-5-21-10-20-30-1700"
    assert edges[0]["target"] == "gmsa_app$"


# ─────────────────────── Tier-0 ACL audit findings → KerbMapWriteAcl ────


def test_tier0_acl_finding_emits_kerbmap_writeacl_edge(tmp_path):
    """Per-right edge labels so a CRTE-style 'find every writer of
    Domain Admins' query is one Cypher hop."""
    exp = _exporter()
    exp.add_findings([Finding(
        target="Domain Admins",
        attack="Tier-0 ACL: GenericAll on Privileged group",
        severity="CRITICAL", priority=95, reason="...",
        data={
            "writer_sid":  "S-1-5-21-10-20-30-1500",
            "writer_sam":  "rogue_user",
            "writer_dn":   "CN=rogue_user,...",
            "target_dn":   "CN=Domain Admins,CN=Users,DC=corp,DC=local",
            "target_sid":  "S-1-5-21-10-20-30-512",
            "target_kind": "Privileged group",
            "right":       "GenericAll",
        },
    )])
    out = exp.export(str(tmp_path / "tier0.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    edge = edges[0]
    assert edge["edge"]   == "KerbMapWriteAcl"
    assert edge["source"] == "S-1-5-21-10-20-30-1500"
    assert edge["target"] == "S-1-5-21-10-20-30-512"
    assert edge["props"]["right"]       == "GenericAll"
    assert edge["props"]["target_kind"] == "Privileged group"


def test_user_acl_finding_emits_kerbmap_writeacl_edge(tmp_path):
    """User ACL audit findings (lateral-movement edges between
    non-Tier-0 users) must reach the export — same shape as Tier-0
    ACL. Field bug from the v1.3 sprint bug-class grep: previously
    the exporter only matched ``attack.startswith("Tier-0 ACL:")``
    and silently dropped every User ACL finding from both the graph
    and the sidecar. Operators using BH CE for lateral pathfinding
    were getting the wrong picture."""
    exp = _exporter()
    exp.add_findings([Finding(
        target="bob",
        attack="User ACL: GenericAll → bob",
        severity="HIGH", priority=85, reason="...",
        data={
            "writer_sid":  "S-1-5-21-10-20-30-1500",
            "writer_sam":  "alice",
            "writer_dn":   "CN=alice,...",
            "target_sid":  "S-1-5-21-10-20-30-1600",
            "target_dn":   "CN=bob,...",
            "target_sam":  "bob",
            "right":       "GenericAll",
        },
    )])
    out = exp.export(str(tmp_path / "user_acl.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    assert edges[0]["edge"]   == "KerbMapWriteAcl"
    assert edges[0]["source"] == "S-1-5-21-10-20-30-1500"
    assert edges[0]["target"] == "S-1-5-21-10-20-30-1600"
    assert edges[0]["props"]["right"]       == "GenericAll"
    assert edges[0]["props"]["target_kind"] == "user"


def test_tier0_acl_finding_uses_target_dn_when_no_sid(tmp_path):
    """AdminSDHolder doesn't have a useful SID — the edge attaches to
    the DN instead. Operators can resolve in BH via name match."""
    exp = _exporter()
    exp.add_findings([Finding(
        target="AdminSDHolder",
        attack="Tier-0 ACL: WriteDACL on AdminSDHolder",
        severity="CRITICAL", priority=93, reason="...",
        data={
            "writer_sid":  "S-1-5-21-10-20-30-1500",
            "target_dn":   "CN=AdminSDHolder,CN=System,DC=corp,DC=local",
            "target_sid":  None,
            "target_kind": "AdminSDHolder",
            "right":       "WriteDACL",
        },
    )])
    out = exp.export(str(tmp_path / "adminsd.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    assert edges[0]["target"].startswith("CN=AdminSDHolder")


def test_tier0_acl_finding_without_writer_sid_skipped(tmp_path):
    """Defensive: a Tier-0 finding with no writer_sid (shouldn't
    happen — the module always sets it — but the BH integration
    survives the corruption gracefully)."""
    exp = _exporter()
    exp.add_findings([Finding(
        target="Domain Admins",
        attack="Tier-0 ACL: GenericAll on Privileged group",
        severity="CRITICAL", priority=95, reason="...",
        data={"target_dn": "CN=Domain Admins,...", "right": "GenericAll"},
    )])
    out = exp.export(str(tmp_path / "broken.zip"))
    with zipfile.ZipFile(out) as zf:
        # No edges file — the broken finding was skipped silently.
        assert "_kerbmap_metadata.json" not in zf.namelist()


# ───────────── OU computer-create findings → KerbMapCreateComputerOu ────


def test_ou_create_finding_emits_kerbmap_createcomputerou_edge(tmp_path):
    """Per-OU edge so a CRTE-style 'find every principal that can drop
    a machine account into an OU' query is one Cypher hop."""
    exp = _exporter()
    exp.add_findings([Finding(
        target="HelpdeskOU",
        attack="OU computer-create: CreateChild(computer)",
        severity="HIGH", priority=86, reason="...",
        data={
            "writer_sid":  "S-1-5-21-10-20-30-1900",
            "writer_sam":  "helpdesk_op",
            "target_dn":   "OU=Helpdesk,DC=corp,DC=local",
            "target_kind": "OU",
            "right":       "CreateChild(computer)",
            "maq":         0,
        },
    )])
    out = exp.export(str(tmp_path / "ou_create.zip"))
    edges = _read_edges(out)
    assert len(edges) == 1
    edge = edges[0]
    assert edge["edge"]   == "KerbMapCreateComputerOu"
    assert edge["source"] == "S-1-5-21-10-20-30-1900"
    assert edge["target"] == "OU=Helpdesk,DC=corp,DC=local"
    assert edge["props"]["right"] == "CreateChild(computer)"
    assert edge["props"]["maq"]   == 0


# ─────────────────── Aces folding (KerbMap → graph edges) ──────


def _read_meta(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("_kerbmap_metadata.json"))["meta"]


def _read_node(zip_path, file_name, sid):
    with zipfile.ZipFile(zip_path) as zf:
        data = json.loads(zf.read(file_name))["data"]
    for node in data:
        if node.get("ObjectIdentifier") == sid:
            return node
    raise AssertionError(f"node {sid} not in {file_name}")


def test_dcsync_finding_folds_two_aces_onto_domain_node(tmp_path):
    """Full DCSync needs both GetChanges + GetChangesAll on the
    domain node — emitting only one yields the partial-DCSync edge,
    which doesn't reproduce the path SharpHound would build."""
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="svc_old", attack="DCSync (full)",
        severity="CRITICAL", priority=95, reason="...",
        data={"principal_sid": "S-1-5-21-10-20-30-1234",
              "rights_granted": ["Get-Changes", "Get-Changes-All"]},
    )])
    out = exporter.export(str(tmp_path / "scan.zip"))

    domain = _read_node(out, "domains.json", "S-1-5-21-10-20-30")
    rights = sorted(a["RightName"] for a in domain["Aces"])
    assert rights == ["GetChanges", "GetChangesAll"]
    assert all(a["PrincipalSID"] == "S-1-5-21-10-20-30-1234" for a in domain["Aces"])
    # Sidecar edge marked folded so kerb-chain knows it's also in the graph.
    assert _read_meta(out)["folded"] == 1


def test_shadow_creds_folds_addkeycredentiallink_onto_target_user(tmp_path):
    """The Shadow Creds writer becomes a real ACE on the target
    user, so BH CE's normal pathfinding includes the takeover."""
    bob = _entry({
        "sAMAccountName":           "bob_da",
        "objectSid":                bytes.fromhex(
            "0105000000000005150000000a000000140000001e000000dc050000"
        ),  # S-1-5-21-10-20-30-1500
        "distinguishedName":        "CN=bob_da,CN=Users,DC=corp,DC=local",
        "userAccountControl":       0x10200,
        "servicePrincipalName":     [],
        "memberOf":                 [],
        "primaryGroupID":           513,
        "adminCount":               1,
        "pwdLastSet":               132000000000000000,
        "lastLogonTimestamp":       133500000000000000,
        "description":              None,
        "sIDHistory":               [],
        "msDS-AllowedToDelegateTo": [],
    })
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[bob], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="bob_da", attack="Shadow Credentials (write access)",
        severity="CRITICAL", priority=92, reason="...",
        data={"writer_sid": "S-1-5-21-10-20-30-1700",
              "target_dn":  "CN=bob_da,CN=Users,DC=corp,DC=local"},
    )])
    out = exporter.export(str(tmp_path / "shadow.zip"))

    target = _read_node(out, "users.json", "S-1-5-21-10-20-30-1500")
    aces = target["Aces"]
    assert len(aces) == 1
    assert aces[0]["PrincipalSID"] == "S-1-5-21-10-20-30-1700"
    assert aces[0]["RightName"]    == "AddKeyCredentialLink"
    assert aces[0]["IsInherited"]  is False
    assert _read_meta(out)["folded"] == 1


def test_tier0_acl_writeacl_folds_with_correct_sharphound_rightname(tmp_path):
    """kerb-map's internal label 'WriteDACL' must map to SharpHound's
    'WriteDacl' (case differs) — otherwise BH CE doesn't recognise it
    as the WriteDacl edge and pathfinding silently skips it."""
    da_group = _entry({
        "sAMAccountName":     "Domain Admins",
        "objectSid":          bytes.fromhex(
            "0105000000000005150000000a000000140000001e00000000020000"
        ),  # S-1-5-21-10-20-30-512
        "distinguishedName":  "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "member":             [],
        "adminCount":         1,
    })
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [da_group], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="Domain Admins",
        attack="Tier-0 ACL: WriteDACL on Privileged group",
        severity="CRITICAL", priority=93, reason="...",
        data={"writer_sid":  "S-1-5-21-10-20-30-1900",
              "target_sid":  "S-1-5-21-10-20-30-512",
              "target_kind": "Privileged group",
              "right":       "WriteDACL"},
    )])
    out = exporter.export(str(tmp_path / "tier0.zip"))

    grp = _read_node(out, "groups.json", "S-1-5-21-10-20-30-512")
    assert grp["Aces"][0]["RightName"] == "WriteDacl"
    # Principal SID isn't in any collection here, so PrincipalType
    # falls back to "Base". The principal-resolution path is covered
    # by test_principal_type_resolved_when_principal_in_collection.
    assert grp["Aces"][0]["PrincipalType"] == "Base"


def test_unfoldable_finding_marked_folded_false_in_sidecar(tmp_path):
    """ESC9 / BadSuccessor / KdsReadable target template / OU / KDS
    nodes that BH CE doesn't model — they stay in the sidecar with
    folded=false so kerb-chain still has a machine-readable view."""
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="ou_admin on OU=Lab,DC=corp,DC=local",
        attack="BadSuccessor (writable OU)",
        severity="HIGH", priority=88, reason="...",
        data={"principal_sid": "S-1-5-21-10-20-30-1500",
              "ou_dn":         "OU=Lab,DC=corp,DC=local"},
    )])
    out = exporter.export(str(tmp_path / "unfold.zip"))
    with zipfile.ZipFile(out) as zf:
        meta = json.loads(zf.read("_kerbmap_metadata.json"))
    assert meta["meta"]["folded"] == 0
    assert meta["data"][0]["folded"] is False


def test_aces_dedup_within_target(tmp_path):
    """Two findings with the same writer hitting the same target with
    the same right collapse to a single ACE — otherwise BH CE shows
    duplicate edges, which clutters the graph and breaks count-based
    Cypher queries."""
    da_group = _entry({
        "sAMAccountName":     "Domain Admins",
        "objectSid":          bytes.fromhex(
            "0105000000000005150000000a000000140000001e00000000020000"
        ),
        "distinguishedName":  "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "member":             [],
        "adminCount":         1,
    })
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[], [], [da_group], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    base = dict(target="Domain Admins",
                attack="Tier-0 ACL: GenericAll on Privileged group",
                severity="CRITICAL", priority=95, reason="...")
    exporter.add_findings([
        Finding(**base, data={"writer_sid": "S-1-5-21-10-20-30-1900",
                              "target_sid": "S-1-5-21-10-20-30-512",
                              "target_kind": "Privileged group",
                              "right": "GenericAll"}),
        Finding(**base, data={"writer_sid": "S-1-5-21-10-20-30-1900",
                              "target_sid": "S-1-5-21-10-20-30-512",
                              "target_kind": "Privileged group",
                              "right": "GenericAll"}),
    ])
    out = exporter.export(str(tmp_path / "dup.zip"))
    grp = _read_node(out, "groups.json", "S-1-5-21-10-20-30-512")
    assert len(grp["Aces"]) == 1


def test_principal_type_resolved_when_principal_in_collection(tmp_path):
    """When the writer's SID matches a collected user, PrincipalType
    must be 'User' so BH CE renders the edge from the right node
    kind in the graph."""
    helpdesk = _entry({
        "sAMAccountName":           "helpdesk_op",
        "objectSid":                bytes.fromhex(
            "0105000000000005150000000a000000140000001e0000006c070000"
        ),  # S-1-5-21-10-20-30-1900
        "distinguishedName":        "CN=helpdesk_op,CN=Users,DC=corp,DC=local",
        "userAccountControl":       0x10200,
        "servicePrincipalName":     [],
        "memberOf":                 [],
        "primaryGroupID":           513,
        "adminCount":               None,
        "pwdLastSet":               132000000000000000,
        "lastLogonTimestamp":       133500000000000000,
        "description":              None,
        "sIDHistory":               [],
        "msDS-AllowedToDelegateTo": [],
    })
    da_group = _entry({
        "sAMAccountName":     "Domain Admins",
        "objectSid":          bytes.fromhex(
            "0105000000000005150000000a000000140000001e00000000020000"
        ),
        "distinguishedName":  "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "member":             [],
        "adminCount":         1,
    })
    exporter = BloodHoundCEExporter(
        ldap=_ldap([[helpdesk], [], [da_group], []]),
        domain="corp.local", domain_sid="S-1-5-21-10-20-30",
        base_dn="DC=corp,DC=local",
    )
    exporter.add_findings([Finding(
        target="Domain Admins",
        attack="Tier-0 ACL: GenericAll on Privileged group",
        severity="CRITICAL", priority=95, reason="...",
        data={"writer_sid":  "S-1-5-21-10-20-30-1900",
              "target_sid":  "S-1-5-21-10-20-30-512",
              "target_kind": "Privileged group",
              "right":       "GenericAll"},
    )])
    out = exporter.export(str(tmp_path / "ptype.zip"))
    grp = _read_node(out, "groups.json", "S-1-5-21-10-20-30-512")
    assert grp["Aces"][0]["PrincipalType"] == "User"
