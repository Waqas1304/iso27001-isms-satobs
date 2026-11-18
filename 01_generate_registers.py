"""
01_generate_registers.py
------------------------
Builds the ISMS registers for the fictional company SatObs:
asset inventory, risk register, risk treatment plan, Statement of
Applicability (93 Annex A controls, ISO/IEC 27001:2022), exception register,
document control register, BIA, continuity test schedule, incident register,
awareness campaign log and corrective action log.

All company data is FICTIONAL / SYNTHETIC (clearly labelled).
Only the vulnerability data (CISA KEV) used in script 02 is real public data.

Run:  python scripts/01_generate_registers.py
"""
from pathlib import Path
import random
import pandas as pd

random.seed(27001)
ROOT = Path(__file__).resolve().parents[1]
REPORT_DATE = pd.Timestamp("2026-11-15")   # ISMS reporting date


def save(df, folder, name):
    out = ROOT / folder / name
    df.to_csv(out, index=False, encoding="utf-8")
    print(f"  -> {out.relative_to(ROOT)} ({len(df)} rows)")
    return df


# ---------------------------------------------------------------------------
# 1. Asset inventory (ISO 27001 A.5.9)
# ---------------------------------------------------------------------------
assets = pd.DataFrame([
    ("A01", "Raw satellite imagery (level L0)", "Information", "Ground Segment Manager", 2, 3, 3, "Cloud object storage", "-"),
    ("A02", "Processed imagery products (L1-L3)", "Information", "Production Manager", 2, 4, 3, "Cloud object storage", "-"),
    ("A03", "Customer data, contracts and personal data", "Information", "CFO / DPO", 4, 3, 2, "SaaS CRM", "-"),
    ("A04", "Processing pipeline source code", "Information", "CTO", 3, 4, 2, "GitLab", "GitLab"),
    ("A05", "Processing platform (Linux cluster)", "Infrastructure", "Infrastructure Manager", 2, 4, 4, "Sophia data centre", "Linux Kernel"),
    ("A06", "Imagery archive (object storage)", "Infrastructure", "Infrastructure Manager", 2, 4, 3, "EU cloud", "-"),
    ("A07", "Customer distribution portal", "Application", "Product Manager", 3, 4, 4, "DMZ", "Apache Tomcat / HTTP Server"),
    ("A08", "Ground station - mission centre link", "Network", "Ground Segment Manager", 3, 4, 4, "Ground station / WAN", "Cisco IOS"),
    ("A09", "Firewall and remote-access VPN", "Network", "CISO", 3, 4, 4, "Perimeter", "Fortinet FortiOS"),
    ("A10", "On-premise virtualisation", "Infrastructure", "Infrastructure Manager", 3, 4, 4, "Sophia data centre", "VMware vCenter / ESXi"),
    ("A11", "CI/CD pipeline", "Application", "CTO", 3, 4, 3, "Sophia data centre", "GitLab"),
    ("A12", "Backups", "Infrastructure", "Infrastructure Manager", 3, 4, 4, "Secondary site", "Veeam Backup & Replication"),
    ("A13", "Workstations and email", "Hardware / Software", "Internal IT Manager", 3, 3, 3, "Offices / remote work", "Microsoft Windows / Office"),
    ("A14", "Monitoring and logging", "Application", "CISO", 3, 4, 3, "Sophia data centre", "Elastic / Grafana"),
    ("A15", "Wiki and ticketing tool", "Application", "Internal IT Manager", 3, 3, 2, "Sophia data centre", "Atlassian Confluence / Jira"),
    ("A16", "Key staff (mission engineers, administrators)", "People", "HR Director", 3, 3, 4, "Sophia Antipolis", "-"),
    ("A17", "Cloud hosting provider (supplier)", "Supplier", "Procurement / CISO", 3, 4, 4, "EU", "-"),
], columns=["asset_id", "asset", "type", "owner", "confidentiality", "integrity",
            "availability", "location", "technology"])
assets["criticality"] = assets[["confidentiality", "integrity", "availability"]].max(axis=1)
assets["last_review"] = "2026-10-20"
assets["review_status"] = "Up to date"
assets.loc[assets.asset_id.isin(["A15", "A17"]), ["last_review", "review_status"]] = ["2025-09-30", "Review overdue (> 12 months)"]

# ---------------------------------------------------------------------------
# 2. Risk register (method inspired by EBIOS RM / ISO 27005)
#    Severity (S) 1-4 x Likelihood (L) 1-4 -> Level 1-16
#    Acceptable <= 4 | To treat 6-8 | Critical >= 9
# ---------------------------------------------------------------------------
def level(s, l):
    n = s * l
    return n, ("Critical" if n >= 9 else "To treat" if n >= 6 else "Acceptable")

risks_raw = [
    # id, assets, risk source, scenario, S, L, treatment, Annex A controls, owner, S_res, L_res
    ("R01", "A07", "Cybercriminal", "Exploitation of a known exploited vulnerability (KEV) in the customer portal -> leak or tampering of delivered products", 4, 3, "Reduce", "8.8; 8.9; 8.20; 8.16", "Product Manager", 4, 1),
    ("R02", "A09", "Cybercriminal / ransomware", "Compromise of an unpatched Fortinet VPN -> intrusion and encryption of the IT system", 4, 3, "Reduce", "8.8; 8.5; 8.22; 5.24", "CISO", 4, 2),
    ("R03", "A05; A10", "Ransomware", "Encryption of the processing platform and virtualisation -> production stopped", 4, 2, "Reduce", "8.7; 8.13; 5.30; 8.14", "Infrastructure Manager", 4, 1),
    ("R04", "A12", "Internal error / attacker", "Backups cannot be restored or are deleted by the attacker", 4, 2, "Reduce", "8.13; 5.30; 8.2", "Infrastructure Manager", 3, 1),
    ("R05", "A08", "Outage / state-sponsored attacker", "Interruption or interception of the ground station - mission centre link", 3, 2, "Reduce", "8.20; 8.21; 8.24; 8.14", "Ground Segment Manager", 3, 1),
    ("R06", "A03", "Malicious insider / error", "Leak of customer and personal data (GDPR)", 4, 2, "Reduce", "5.12; 5.15; 8.12; 5.34", "CFO / DPO", 4, 1),
    ("R07", "A04; A11", "Supply-chain attacker", "Compromise of the GitLab CI/CD -> malicious code injected into products", 4, 2, "Reduce", "8.25; 8.4; 8.32; 5.21", "CTO", 4, 1),
    ("R08", "A13", "Phishing", "Credential theft through phishing -> access to email and data", 3, 3, "Reduce", "6.3; 8.5; 8.7; 8.23", "Internal IT Manager", 3, 1),
    ("R09", "A17", "Supplier", "Failure or security incident at the cloud hosting provider", 4, 2, "Share", "5.19; 5.20; 5.22; 5.23", "Procurement / CISO", 4, 1),
    ("R10", "A16", "Organisational", "Key administrator leaves without knowledge transfer", 3, 2, "Reduce", "5.37; 6.5; 5.2", "HR Director", 2, 1),
    ("R11", "A02", "Internal error", "Undetected alteration of a delivered imagery product (integrity)", 4, 2, "Reduce", "8.32; 8.29; 5.37", "Production Manager", 4, 1),
    ("R12", "A14", "Attacker", "Intrusion not detected (incomplete logs)", 3, 3, "Reduce", "8.15; 8.16; 8.17", "CISO", 3, 1),
    ("R13", "A05", "Environment / climate", "Heatwave -> data centre overheating and cluster shutdown (ISO 27001 Amd 1:2024)", 3, 2, "Reduce", "7.5; 7.11; 8.14", "Infrastructure Manager", 3, 1),
    ("R14", "A15", "Cybercriminal", "Exploitation of a vulnerability in an internet-exposed Confluence", 3, 2, "Reduce", "8.8; 8.22", "Internal IT Manager", 3, 1),
    ("R15", "A01", "Error / outage", "Loss of raw imagery not yet archived", 3, 1, "Accept", "8.13", "Ground Segment Manager", 3, 1),
    ("R16", "A13", "Loss / theft", "Laptop lost while travelling", 2, 2, "Accept", "8.1; 8.24; 7.9", "Internal IT Manager", 2, 1),
]
rows = []
for r in risks_raw:
    n, cls = level(r[4], r[5])
    nr, clsr = level(r[9], r[10])
    rows.append(dict(risk_id=r[0], assets=r[1], risk_source=r[2], scenario=r[3],
                     severity=r[4], likelihood=r[5], gross_level=n, gross_class=cls,
                     treatment_option=r[6], annex_a_controls=r[7], risk_owner=r[8],
                     residual_severity=r[9], residual_likelihood=r[10],
                     residual_level=nr, residual_class=clsr,
                     last_review="2026-11-05",
                     residual_acceptance=("Accepted by management" if clsr == "Acceptable" else "To be validated")))
risks = pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# 3. Risk treatment plan (action follow-up)
# ---------------------------------------------------------------------------
actions_raw = [
    ("TA-01", "R01", "Patch KEV vulnerabilities on the portal within 15 days (internal SLA)", "Product Manager", "2026-09-30", 70),
    ("TA-02", "R02", "Upgrade the VPN to a supported FortiOS version + mandatory MFA", "CISO", "2026-10-31", 60),
    ("TA-03", "R03", "Isolate the VMware admin console on a dedicated network", "Infrastructure Manager", "2026-12-15", 40),
    ("TA-04", "R04", "Implement immutable backups (offline copy)", "Infrastructure Manager", "2026-08-31", 100),
    ("TA-05", "R04", "Quarterly restore test, documented and signed", "Infrastructure Manager", "2026-12-31", 50),
    ("TA-06", "R05", "End-to-end encryption of the ground station link", "Ground Segment Manager", "2026-07-31", 100),
    ("TA-07", "R06", "Roll out classification of customer data (labelling)", "CFO / DPO", "2026-11-30", 80),
    ("TA-08", "R07", "Protect main branches + signed commits", "CTO", "2026-09-15", 100),
    ("TA-09", "R08", "Quarterly phishing simulation campaign", "Internal IT Manager", "2026-12-31", 75),
    ("TA-10", "R09", "Add security and audit clauses to the hosting contract", "Procurement / CISO", "2026-10-15", 30),
    ("TA-11", "R10", "Write critical operating procedures (runbooks)", "HR Director", "2027-01-31", 20),
    ("TA-12", "R11", "Integrity check (SHA-256 hashes) before customer delivery", "Production Manager", "2026-06-30", 100),
    ("TA-13", "R12", "Send VPN and portal logs to the SIEM", "CISO", "2026-11-30", 60),
    ("TA-14", "R13", "Cooling capacity study + temperature alerting", "Infrastructure Manager", "2027-03-31", 10),
    ("TA-15", "R14", "Remove Confluence from internet exposure (VPN access only)", "Internal IT Manager", "2026-10-01", 100),
    ("TA-16", "R01", "Annual penetration test of the customer portal", "Product Manager", "2027-02-28", 0),
]
ta = pd.DataFrame(actions_raw, columns=["action_id", "risk_id", "action", "owner", "due_date", "progress_pct"])
ta["due_date"] = pd.to_datetime(ta["due_date"])

def status(row):
    if row.progress_pct == 100:
        return "Completed"
    if row.due_date < REPORT_DATE:
        return "Overdue"
    if row.progress_pct == 0:
        return "Not started"
    return "In progress"

ta["status"] = ta.apply(status, axis=1)
ta["days_overdue"] = ((REPORT_DATE - ta.due_date).dt.days).where(ta.status == "Overdue", 0)
ta["expected_evidence"] = ["Scan report + tickets", "Config export + MFA log", "Network diagram v3",
                           "Veeam immutability report", "Signed test report", "Certificate / IPsec config",
                           "Classification matrix", "Exported GitLab rules", "Campaign report",
                           "Signed contract amendment", "Approved runbooks", "Procedure + check log",
                           "Capacity study", "Firewall rule + external test", "Study + sensor",
                           "Pentest report"]
ta["due_date"] = ta.due_date.dt.date

# ---------------------------------------------------------------------------
# 4. Statement of Applicability (SoA) - 93 controls, ISO/IEC 27001:2022 Annex A
# ---------------------------------------------------------------------------
annex_a = {
 "Organisational": [
  "Policies for information security", "Information security roles and responsibilities", "Segregation of duties",
  "Management responsibilities", "Contact with authorities", "Contact with special interest groups", "Threat intelligence",
  "Information security in project management", "Inventory of information and other associated assets",
  "Acceptable use of information and other associated assets", "Return of assets", "Classification of information",
  "Labelling of information", "Information transfer", "Access control", "Identity management", "Authentication information",
  "Access rights", "Information security in supplier relationships", "Addressing information security within supplier agreements",
  "Managing information security in the ICT supply chain", "Monitoring, review and change management of supplier services",
  "Information security for use of cloud services", "Information security incident management planning and preparation",
  "Assessment and decision on information security events", "Response to information security incidents",
  "Learning from information security incidents", "Collection of evidence", "Information security during disruption",
  "ICT readiness for business continuity", "Legal, statutory, regulatory and contractual requirements",
  "Intellectual property rights", "Protection of records", "Privacy and protection of PII",
  "Independent review of information security", "Compliance with policies, rules and standards for information security",
  "Documented operating procedures"],
 "People": [
  "Screening", "Terms and conditions of employment", "Information security awareness, education and training",
  "Disciplinary process", "Responsibilities after termination or change of employment",
  "Confidentiality or non-disclosure agreements", "Remote working", "Information security event reporting"],
 "Physical": [
  "Physical security perimeters", "Physical entry", "Securing offices, rooms and facilities", "Physical security monitoring",
  "Protecting against physical and environmental threats", "Working in secure areas", "Clear desk and clear screen",
  "Equipment siting and protection", "Security of assets off-premises", "Storage media", "Supporting utilities",
  "Cabling security", "Equipment maintenance", "Secure disposal or re-use of equipment"],
 "Technological": [
  "User endpoint devices", "Privileged access rights", "Information access restriction", "Access to source code",
  "Secure authentication", "Capacity management", "Protection against malware", "Management of technical vulnerabilities",
  "Configuration management", "Information deletion", "Data masking", "Data leakage prevention", "Information backup",
  "Redundancy of information processing facilities", "Logging", "Monitoring activities", "Clock synchronization",
  "Use of privileged utility programs", "Installation of software on operational systems", "Networks security",
  "Security of network services", "Segregation of networks", "Web filtering", "Use of cryptography",
  "Secure development life cycle", "Application security requirements", "Secure system architecture and engineering principles",
  "Secure coding", "Security testing in development and acceptance", "Outsourced development",
  "Separation of development, test and production environments", "Change management", "Test information",
  "Protection of information systems during audit testing"]}
prefix = {"Organisational": 5, "People": 6, "Physical": 7, "Technological": 8}

ctrl_to_risks = {}
for r in risks_raw:
    for c in r[7].split(";"):
        ctrl_to_risks.setdefault(c.strip(), []).append(r[0])

legal = {"5.31", "5.32", "5.33", "5.34", "6.6", "5.5"}
not_applicable = {"8.30": "No outsourced development: all code is developed in-house (reviewed annually).",
                  "8.11": "No personal data in non-production environments; satellite imagery is not personal data."}
partial = {"5.30": "Customer portal DRP not tested for more than 12 months (see audit IA-2026-03)",
           "8.8": "15-day patching SLA not met for several KEV vulnerabilities",
           "5.22": "Annual review of the hosting provider to be formalised",
           "5.20": "Audit clauses missing from the hosting contract (TA-10)",
           "8.15": "VPN and portal logs not yet centralised (TA-13)",
           "8.16": "Partial monitoring coverage (TA-13)",
           "5.12": "Classification being rolled out (TA-07)",
           "5.37": "Critical runbooks still to be written (TA-11)",
           "7.5": "Climate / heatwave risk being treated (TA-14)",
           "6.3": "Training completion below the 95 % target"}
planned = {"8.29": "Customer portal penetration test planned for Q1 2027 (TA-16)",
           "5.7": "Threat-intelligence feed subscription to be budgeted for 2027"}

soa_rows = []
for theme, titles in annex_a.items():
    for i, title in enumerate(titles, start=1):
        cid = f"{prefix[theme]}.{i}"
        rk = ctrl_to_risks.get(cid, [])
        if cid in not_applicable:
            app, just, stat, com = "No", "Justified exclusion", "Not applicable", not_applicable[cid]
        else:
            app = "Yes"
            sources = []
            if rk: sources.append("Risk treatment (" + ", ".join(rk) + ")")
            if cid in legal: sources.append("Legal / contractual requirement")
            if not sources: sources.append("Good practice / customer requirement")
            just = " + ".join(sources)
            if cid in partial: stat, com = "Partially implemented", partial[cid]
            elif cid in planned: stat, com = "Planned", planned[cid]
            else: stat, com = "Implemented", ""
        soa_rows.append(dict(control=cid, theme=theme, control_title=title, applicable=app,
                             justification=just, related_risks=", ".join(rk), implementation_status=stat,
                             comment=com, reference_document=f"PR-SEC-{prefix[theme]}{i:02d}" if app == "Yes" else "",
                             last_updated="2026-11-10"))
soa = pd.DataFrame(soa_rows)
assert len(soa) == 93, len(soa)

# ---------------------------------------------------------------------------
# 5. Exception register
# ---------------------------------------------------------------------------
exc = pd.DataFrame([
    ("EXC-2026-01", "2026-03-02", "Windows Server 2012 R2 on the calibration bench (end of support)", "8.8; 8.19",
     "Vendor software not compatible with a recent OS", "Isolated VLAN, no internet access, enhanced monitoring",
     "Ground Segment Manager", "CISO + Management", "2027-03-31"),
    ("EXC-2026-02", "2026-05-14", "No MFA on the ground station service account", "8.5",
     "Technical limitation of the ground equipment", "IP filtering, 24-character password, 90-day rotation",
     "Ground Segment Manager", "CISO", "2026-12-31"),
    ("EXC-2026-03", "2026-08-05", "FortiOS patch (CVE-2025-68686) postponed beyond the 15-day SLA", "8.8",
     "Contractual customer maintenance window", "SSL-VPN web portal disabled, IPS monitoring",
     "CISO", "CISO", "2026-08-31"),
], columns=["exception_id", "request_date", "subject", "controls_concerned", "justification",
            "compensating_measures", "requester", "approver", "expiry_date"])
exp = pd.to_datetime(exc.expiry_date)
exc["status"] = ["Active" if e > REPORT_DATE + pd.Timedelta(days=60) else
                 ("Expires within 60 days - renew or close" if e >= REPORT_DATE else "EXPIRED - action required")
                 for e in exp]

# ---------------------------------------------------------------------------
# 6. ISMS document control register (clause 7.5)
# ---------------------------------------------------------------------------
docs = pd.DataFrame([
    ("POL-SEC-001", "Information security policy", "Policy", "3.0", "Management", "2026-01-15", 12),
    ("POL-SEC-002", "Access control policy", "Policy", "2.1", "CISO", "2025-06-10", 12),
    ("POL-SEC-003", "Information classification policy", "Policy", "1.0", "DPO", "2026-09-01", 12),
    ("PR-SEC-524", "Incident management procedure", "Procedure", "2.3", "CISO", "2026-04-02", 12),
    ("PR-SEC-808", "Vulnerability management procedure", "Procedure", "1.4", "CISO", "2025-08-28", 12),
    ("PR-SEC-813", "Backup and restore procedure", "Procedure", "2.0", "Infrastructure Manager", "2026-02-12", 12),
    ("PR-SEC-832", "Change management procedure", "Procedure", "1.6", "CTO", "2026-07-07", 12),
    ("MET-RISK-01", "Risk assessment method", "Method", "2.0", "CISO", "2026-03-20", 24),
    ("BCP-001", "Business continuity plan", "Plan", "1.2", "QHSE Manager", "2025-10-30", 12),
    ("DRP-007", "Disaster recovery plan - customer portal", "Plan", "1.1", "Product Manager", "2025-05-15", 12),
    ("SOA-001", "Statement of Applicability", "Record", "5.0", "QHSE Manager", "2026-11-10", 12),
    ("CHT-001", "IT acceptable use charter", "Charter", "2.2", "HR Director", "2026-01-20", 24),
], columns=["reference", "title", "type", "version", "owner", "last_review", "review_period_months"])
lr = pd.to_datetime(docs.last_review)
docs["next_review"] = [(d + pd.DateOffset(months=int(m))).date() for d, m in zip(lr, docs.review_period_months)]
docs["status"] = ["Review overdue" if pd.Timestamp(p) < REPORT_DATE else
                  ("Review due within 60 days" if pd.Timestamp(p) < REPORT_DATE + pd.Timedelta(days=60) else "Up to date")
                  for p in docs.next_review]

# ---------------------------------------------------------------------------
# 7. Business Impact Analysis (BIA) and BCP/DRP test schedule
# ---------------------------------------------------------------------------
bia = pd.DataFrame([
    ("P1", "Data reception from the ground station", "A08; A01; A05", 3, 4, 4, 4, 1, "Customer contracts (image freshness)"),
    ("P2", "Imagery processing (L1-L3)", "A05; A10; A06", 2, 3, 4, 12, 4, "Delivery delays, penalties"),
    ("P3", "Distribution via the customer portal", "A07; A06; A09", 3, 4, 4, 8, 4, "Reputation, 99.5 % customer SLA"),
    ("P4", "Long-term archiving", "A06; A12", 1, 2, 3, 72, 24, "Loss of historical data"),
    ("P5", "Customer support", "A13; A15", 1, 2, 3, 24, 24, "Customer satisfaction"),
    ("P6", "Invoicing", "A03; A13", 1, 1, 2, 120, 24, "Cash flow"),
], columns=["process_id", "process", "dependent_assets", "impact_4h", "impact_24h", "impact_72h",
            "RTO_hours", "RPO_hours", "main_consequence"])
bia["approved_by"] = "Operations Director"
bia["last_updated"] = "2026-06-12"

tests = pd.DataFrame([
    ("T-2026-01", "Cluster backup restore (sample)", "P2", "2026-02-15", "Done", "Compliant - restored in 5 h (RTO 12 h)", "Yes"),
    ("T-2026-02", "Failover to secondary ground station link", "P1", "2026-04-10", "Done", "Compliant - failover in 2 h 40 (RTO 4 h)", "Yes"),
    ("T-2026-03", "Cluster backup restore (sample)", "P2", "2026-05-20", "Done", "Compliant", "No (report not signed)"),
    ("T-2026-04", "Cyber crisis exercise (ransomware table-top)", "P1-P3", "2026-06-25", "Done", "3 improvement points identified", "Yes"),
    ("T-2026-05", "Cluster backup restore (sample)", "P2", "2026-08-18", "Done", "Compliant", "No (report not signed)"),
    ("T-2026-06", "Full DRP test of the customer portal", "P3", "2026-09-30", "Postponed", "Postponed twice - not performed", "-"),
    ("T-2026-07", "Cluster backup restore (sample)", "P2", "2026-11-20", "Planned", "-", "-"),
    ("T-2027-01", "Full DRP test of the customer portal (rescheduled)", "P3", "2027-01-20", "Planned", "-", "-"),
], columns=["test_id", "test", "process", "planned_date", "status", "result", "report_signed"])

# ---------------------------------------------------------------------------
# 8. Incident register (12 months, synthetic)
# ---------------------------------------------------------------------------
cats = ["Phishing", "Blocked malware", "Unauthorised access", "Lost / stolen device", "Service outage", "Data leak"]
w = [0.38, 0.2, 0.12, 0.08, 0.17, 0.05]
inc = []
months = pd.period_range("2025-12", "2026-11", freq="M")
n = 1
for m in months:
    for _ in range(random.randint(2, 6)):
        cat = random.choices(cats, w)[0]
        sev = random.choices(["Low", "Medium", "High", "Critical"],
                             [0.5, 0.32, 0.15, 0.03] if cat != "Data leak" else [0.2, 0.4, 0.3, 0.1])[0]
        d = m.start_time + pd.Timedelta(days=random.randint(0, 27))
        days = {"Low": 2, "Medium": 6, "High": 12, "Critical": 20}[sev]
        closed = d + pd.Timedelta(days=max(1, int(random.gauss(days, days / 3))))
        is_open = closed > REPORT_DATE
        inc.append(dict(incident_id=f"INC-{d.year}-{n:03d}", detection_date=d.date(), category=cat, severity=sev,
                        closure_date=None if is_open else closed.date(),
                        days_to_close=None if is_open else (closed - d).days,
                        status="Open" if is_open else "Closed",
                        lessons_learned=("Yes" if sev in ("High", "Critical") and not is_open else
                                         ("Not required" if sev in ("Low", "Medium") else "To do"))))
        n += 1
incidents = pd.DataFrame(inc)
idx = incidents[(incidents.severity == "High") & (incidents.status == "Closed")].index
if len(idx):
    incidents.loc[idx[-1], "lessons_learned"] = "Missing (follow-up gap)"

# ---------------------------------------------------------------------------
# 9. Awareness campaigns and participation
# ---------------------------------------------------------------------------
aw = pd.DataFrame([
    ("AWR-2026-01", "2026-01", "Annual security e-learning", "Training", 142, 121, None),
    ("AWR-2026-02", "2026-02", "Phishing simulation #1", "Exercise", 142, None, 17.6),
    ("AWR-2026-03", "2026-04", "Data classification workshop", "Session", 38, 33, None),
    ("AWR-2026-04", "2026-05", "Phishing simulation #2", "Exercise", 145, None, 12.4),
    ("AWR-2026-05", "2026-06", "Cyber crisis exercise (executive committee + IT)", "Exercise", 14, 12, None),
    ("AWR-2026-06", "2026-08", "Phishing simulation #3", "Exercise", 147, None, 9.5),
    ("AWR-2026-07", "2026-09", "Security onboarding for new joiners", "Training", 11, 11, None),
    ("AWR-2026-08", "2026-10", "Phishing simulation #4 (theme: fake space tender)", "Exercise", 150, None, 7.3),
    ("AWR-2026-09", "2026-10", "European Cybersecurity Month: quick-reference sheet", "Communication", 150, 150, None),
], columns=["campaign_id", "month", "action", "type", "target_population", "participants", "phishing_click_rate_pct"])
aw["participation_rate_pct"] = (aw.participants / aw.target_population * 100).round(1)

# Corrective actions from the internal audit
capa = pd.DataFrame([
    ("CA-01", "IA-2026-03 / NC-1", "8.8", "KEV vulnerabilities patched outside the SLA; exception EXC-2026-03 expired",
     "No weekly review of the KEV catalog; no expiry alert on exceptions",
     "Weekly KEV review in the IT meeting + automatic alert 30 days before any exception expires", "CISO", "2026-12-20", "In progress"),
    ("CA-02", "IA-2026-03 / NC-2", "5.30", "Customer portal DRP not tested for more than 12 months",
     "Test postponed twice for lack of a maintenance window; no escalation to management",
     "DRP test locked in the calendar (20/01/2027) + automatic escalation to the committee if postponed", "Product Manager", "2027-01-31", "Planned"),
    ("CA-03", "IA-2026-03 / OBS-1", "8.13", "2 of 3 restore test reports not signed",
     "No approval workflow defined", "Signature step added to the test report template", "Infrastructure Manager", "2026-12-15", "In progress"),
    ("CA-04", "Register review", "5.27", "Lessons learned missing for one high-severity incident",
     "No owner assigned for lessons learned at closure", "Lessons-learned field made mandatory before closure in the ticketing tool", "CISO", "2026-12-15", "Not started"),
], columns=["action_id", "origin", "control", "finding", "root_cause", "corrective_action", "owner", "due_date", "status"])

print("Generating ISMS registers (fictional data):")
save(assets, "02_assets_and_risks", "asset_inventory.csv")
save(risks, "02_assets_and_risks", "risk_register.csv")
save(ta, "02_assets_and_risks", "risk_treatment_plan.csv")
save(soa, "03_statement_of_applicability", "statement_of_applicability.csv")
save(exc, "03_statement_of_applicability", "exception_register.csv")
save(docs, "11_document_control", "document_register.csv")
save(bia, "08_business_continuity", "business_impact_analysis.csv")
save(tests, "08_business_continuity", "bcp_drp_test_schedule.csv")
save(incidents, "data/processed", "incident_register.csv")
save(aw, "10_awareness", "awareness_campaigns.csv")
save(capa, "05_internal_audit", "corrective_actions.csv")
