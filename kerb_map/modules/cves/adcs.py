"""
AD CS — ESC1 through ESC4 / ESC8 (passive LDAP detection).
"""


from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()

EKU_ANY_PURPOSE        = "2.5.29.37.0"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_CLIENT_AUTH        = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD_LOGON    = "1.3.6.1.4.1.311.20.2.2"


class ADCSAudit(CVEBase):
    CVE_ID = "ESC1-ESC8"
    NAME   = "AD Certificate Services Misconfigurations"

    def check(self) -> CVEResult:
        log.info(f"Checking AD CS misconfigurations ({self.CVE_ID})...")
        cas = self._find_cas()
        if not cas:
            return CVEResult(
                cve_id=self.CVE_ID, name=self.NAME, severity=Severity.INFO,
                vulnerable=False, reason="No AD CS infrastructure found",
                evidence={}, remediation="N/A", next_step="",
            )

        templates = self._get_templates()
        findings  = self._analyze(templates)
        ca_notes  = [{"template":f"[CA] {c['name']}","type":"ESC8 (manual check)",
                      "severity":"MEDIUM",
                      "detail":f"Verify EDITF_ATTRIBUTESUBJECTALTNAME2 not set on CA '{c['name']}'"}
                     for c in cas]
        all_findings = findings + ca_notes
        critical = any(f["severity"] in ("CRITICAL","HIGH") for f in all_findings)

        return CVEResult(
            cve_id=self.CVE_ID, name=self.NAME,
            severity=Severity.CRITICAL if critical else Severity.MEDIUM,
            vulnerable=bool(findings),
            reason=(f"Found {len(findings)} misconfigured template(s) across {len(cas)} CA(s)"
                    if findings else "No obvious template misconfigurations found"),
            evidence={"cas": cas, "vulnerable_templates": findings, "ca_notes": ca_notes},
            remediation=(
                "Remove ENROLLEE_SUPPLIES_SUBJECT from non-essential templates.\n"
                "Restrict enrollment permissions to authorised groups.\n"
                "Enable Manager Approval on sensitive templates.\n"
                "Apply EPA on AD CS HTTP endpoints."
            ),
            next_step=(
                f"certipy find -u {self.ldap.username}@{self.domain} -p <pass> "
                f"-dc-ip {self.dc_ip} -vulnerable\n"
                "certipy req -u user@domain -p pass -ca <CA> -template <TPL> -upn administrator@domain"
            ) if findings else "",
            references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
        )

    def _find_cas(self):
        entries = self.ldap.query_config(
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=["cn","dNSHostName","certificateTemplates"],
        )
        return [{"name":str(e["cn"]),"dns":str(e["dNSHostName"].value or ""),
                 "templates":list(e["certificateTemplates"] or [])} for e in entries]

    def _get_templates(self):
        return self.ldap.query_config(
            search_filter="(objectClass=pKICertificateTemplate)",
            attributes=["cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
                        "pKIExtendedKeyUsage","msPKI-RA-Signature"],
        )

    def _analyze(self, templates) -> list[dict]:
        findings = []
        for t in templates:
            name      = str(t["cn"])
            name_flag = int(t["msPKI-Certificate-Name-Flag"].value or 0)
            eku       = list(t["pKIExtendedKeyUsage"] or [])
            ra_sigs   = int(t["msPKI-RA-Signature"].value or 0)

            if (name_flag & 0x1) and (EKU_CLIENT_AUTH in eku or EKU_SMARTCARD_LOGON in eku or EKU_ANY_PURPOSE in eku):
                findings.append({"template":name,"type":"ESC1","severity":"CRITICAL",
                    "detail":"ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU — can request cert as any user (incl DA)"})

            if EKU_ANY_PURPOSE in eku or (len(eku) == 0 and not (name_flag & 0x1)):
                findings.append({"template":name,"type":"ESC2","severity":"HIGH",
                    "detail":"Any Purpose EKU — certificate usable for any purpose"})

            if EKU_CERT_REQUEST_AGENT in eku and ra_sigs == 0:
                findings.append({"template":name,"type":"ESC3","severity":"HIGH",
                    "detail":"Certificate Request Agent EKU — can enroll on behalf of other users"})
        return findings
