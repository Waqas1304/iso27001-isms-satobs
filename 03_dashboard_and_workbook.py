"""
03_dashboard_and_workbook.py
----------------------------
Consolidates the ISMS indicators (ISO 27001 clause 9.1 - monitoring, measurement,
analysis and evaluation) into:
  * 06_dashboard/isms_kpis.csv          (KPI table vs targets, RAG status)
  * 06_dashboard/isms_dashboard.png     (one-page dashboard)
  * 06_dashboard/risk_heatmap.png       (gross vs residual risk)
  * ISMS_SatObs_registers.xlsx          (all registers in one workbook)

Run after scripts 01 and 02:  python scripts/03_dashboard_and_workbook.py
"""
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "06_dashboard"
rd = lambda p: pd.read_csv(ROOT / p)

assets = rd("02_assets_and_risks/asset_inventory.csv")
risks = rd("02_assets_and_risks/risk_register.csv")
ta = rd("02_assets_and_risks/risk_treatment_plan.csv")
soa = rd("03_statement_of_applicability/statement_of_applicability.csv")
exc = rd("03_statement_of_applicability/exception_register.csv")
docs = rd("11_document_control/document_register.csv")
bia = rd("08_business_continuity/business_impact_analysis.csv")
tests = rd("08_business_continuity/bcp_drp_test_schedule.csv")
inc = rd("data/processed/incident_register.csv")
aw = rd("10_awareness/awareness_campaigns.csv")
capa = rd("05_internal_audit/corrective_actions.csv")
kev_kpi = rd("04_vulnerability_management/kev_indicators.csv")
kev_track = rd("04_vulnerability_management/kev_patch_tracking_12_months.csv")

# ---------------- KPI table ----------------
applicable = soa[soa.applicable == "Yes"]
pct_soa = (applicable.implementation_status == "Implemented").mean() * 100
open_ta = ta[ta.status != "Completed"]
pct_ta_late = (ta.status == "Overdue").sum() / len(open_ta) * 100
kev_sla = float(kev_kpi.loc[kev_kpi.indicator.str.startswith("KPI"), "value"].iloc[0])
training = aw[aw.action.str.contains("e-learning")].participation_rate_pct.iloc[0]
last_click = aw.dropna(subset=["phishing_click_rate_pct"]).phishing_click_rate_pct.iloc[-1]
high = inc[inc.severity.isin(["High", "Critical"])]
ll_rate = (high.lessons_learned == "Yes").sum() / len(high[high.status == "Closed"]) * 100
mttc_high = high.days_to_close.mean()
docs_ok = (docs.status != "Review overdue").mean() * 100
done_tests = tests[tests.status == "Done"]
signed = (done_tests.report_signed == "Yes").mean() * 100
not_acc = (risks.residual_class != "Acceptable").sum()
expired = int(exc.status.str.startswith("EXPIRED").sum())

def rag(val, target, higher_better=True, tol=0.2):
    ok = val >= target if higher_better else val <= target
    near = val >= target * (1 - tol) if higher_better else val <= target * (1 + tol)
    return "Green" if ok else ("Amber" if near else "Red")

kpis = pd.DataFrame([
    ("KPI-01", "Applicable Annex A controls implemented (%)", round(pct_soa, 1), 95, rag(pct_soa, 95), "SoA", "6.1.3 / 8.1"),
    ("KPI-02", "Overdue risk treatment actions (% of open actions)", round(pct_ta_late, 1), 10, rag(pct_ta_late, 10, False), "Risk treatment plan", "6.1.3 / 8.3"),
    ("KPI-03", "KEV vulnerabilities patched within 15-day SLA (%)", kev_sla, 90, rag(kev_sla, 90), "CISA KEV + internal tracking", "A.8.8"),
    ("KPI-04", "Annual security training completion (%)", training, 95, rag(training, 95), "Awareness campaigns", "A.6.3"),
    ("KPI-05", "Click rate, latest phishing simulation (%)", last_click, 5, rag(last_click, 5, False), "Awareness campaigns", "A.6.3"),
    ("KPI-06", "High/critical incidents with lessons learned (%)", round(ll_rate, 1), 100, rag(ll_rate, 100), "Incident register", "A.5.27"),
    ("KPI-07", "Mean time to close high/critical incidents (days)", round(mttc_high, 1), 15, rag(mttc_high, 15, False), "Incident register", "A.5.26"),
    ("KPI-08", "ISMS documents reviewed on time (%)", round(docs_ok, 1), 100, rag(docs_ok, 100), "Document register", "7.5"),
    ("KPI-09", "BCP/DRP tests done with signed report (%)", round(signed, 1), 100, rag(signed, 100), "Test schedule", "A.5.30 / A.8.13"),
    ("KPI-10", "Expired exceptions not handled (count)", expired, 0, "Red" if expired else "Green", "Exception register", "A.5.36"),
    ("KPI-11", "Residual risks not acceptable (count)", int(not_acc), 0, "Green" if not_acc == 0 else "Amber", "Risk register", "6.1.3 / 8.3"),
], columns=["id", "indicator", "value", "target", "rag_status", "source", "iso27001_requirement"])
kpis.to_csv(OUT / "isms_kpis.csv", index=False)
print(kpis[["id", "value", "target", "rag_status"]].to_string(index=False))

# ---------------- Dashboard ----------------
C = {"Green": "#3A7D44", "Amber": "#E0A33A", "Red": "#C8553D", "blue": "#2E5C8A", "grey": "#8C8C8C"}
fig = plt.figure(figsize=(16, 10))
fig.suptitle("SatObs - ISO 27001 ISMS dashboard  |  Reporting date 15 Nov 2026  (fictional data, except CISA KEV)",
             fontsize=14, fontweight="bold", x=0.01, ha="left")
gs = fig.add_gridspec(2, 3, hspace=0.45, wspace=0.35)

ax = fig.add_subplot(gs[0, 0]); ax.axis("off"); ax.set_title("Key indicators vs targets", loc="left", fontweight="bold")
for i, r in kpis.iterrows():
    y = 1 - i * 0.088
    ax.add_patch(plt.Rectangle((0, y - 0.06), 0.04, 0.06, color=C[r.rag_status], transform=ax.transAxes))
    label = r.indicator if len(r.indicator) < 50 else r.indicator[:48] + "…"
    ax.text(0.06, y - 0.045, label, fontsize=7.5, transform=ax.transAxes)
    ax.text(1.0, y - 0.045, f"{r.value:g} / {r.target:g}", fontsize=7.5, ha="right", transform=ax.transAxes, fontweight="bold")

ax = fig.add_subplot(gs[0, 1])
order = ["Completed", "In progress", "Not started", "Overdue"]
v = ta.status.value_counts().reindex(order).fillna(0)
ax.bar(order, v.values, color=[C["Green"], C["blue"], C["grey"], C["Red"]])
for i, x in enumerate(v.values): ax.text(i, x + 0.1, int(x), ha="center")
ax.set_title("Risk treatment plan (16 actions)", loc="left", fontweight="bold")
ax.spines[["top", "right"]].set_visible(False)

ax = fig.add_subplot(gs[0, 2])
s = soa.groupby(["theme", "implementation_status"]).size().unstack(fill_value=0)
cols = [c for c in ["Implemented", "Partially implemented", "Planned", "Not applicable"] if c in s.columns]
s = s[cols].reindex(["Organisational", "People", "Physical", "Technological"])
left = np.zeros(len(s))
for c, col in zip(cols, [C["Green"], C["Amber"], C["blue"], C["grey"]]):
    ax.barh(s.index, s[c], left=left, color=col, label=c); left += s[c].values
ax.legend(fontsize=7, frameon=False, loc="upper center", bbox_to_anchor=(0.45, -0.08), ncol=2)
ax.set_title("SoA - 93 Annex A controls", loc="left", fontweight="bold")
ax.spines[["top", "right"]].set_visible(False)

ax = fig.add_subplot(gs[1, 0])
inc["month"] = pd.to_datetime(inc.detection_date).dt.to_period("M").astype(str)
t = inc.groupby(["month", "severity"]).size().unstack(fill_value=0).reindex(columns=["Low", "Medium", "High", "Critical"], fill_value=0)
bottom = np.zeros(len(t))
for g, col in zip(t.columns, ["#B9CFE4", C["blue"], C["Amber"], C["Red"]]):
    ax.bar(t.index.str[2:], t[g], bottom=bottom, color=col, label=g); bottom += t[g].values
ax.tick_params(axis="x", rotation=60, labelsize=7); ax.legend(fontsize=7, frameon=False, ncol=2)
ax.set_title("Security incidents per month by severity", loc="left", fontweight="bold")
ax.spines[["top", "right"]].set_visible(False)

ax = fig.add_subplot(gs[1, 1])
ph = aw.dropna(subset=["phishing_click_rate_pct"])
ax.plot(ph.month, ph.phishing_click_rate_pct, marker="o", color=C["blue"], lw=2)
ax.axhline(5, ls="--", color=C["Green"]); ax.text(0, 5.4, "target 5 %", color=C["Green"], fontsize=8)
for x, y in zip(ph.month, ph.phishing_click_rate_pct): ax.text(x, y + 0.6, f"{y} %", ha="center", fontsize=8)
ax.set_ylim(0, 21); ax.set_title("Phishing simulation click rate", loc="left", fontweight="bold")
ax.spines[["top", "right"]].set_visible(False)

ax = fig.add_subplot(gs[1, 2])
order = ["Patched within SLA", "Patched outside SLA", "Open - within SLA", "Open - outside SLA"]
cnt = kev_track.sla_status.value_counts().reindex(order).fillna(0)
ax.barh(order[::-1], cnt.values[::-1], color=[C["Red"], "#8DA9C4", C["Amber"], C["Green"]])
for i, n in enumerate(cnt.values[::-1]): ax.text(n + 0.3, i, int(n), va="center")
ax.tick_params(axis="y", labelsize=8); ax.spines[["top", "right"]].set_visible(False)
ax.set_title(f"KEV patching (12 months): {kev_sla:.0f} % within SLA\n(target 90 %)", loc="left", fontweight="bold")
fig.text(0.01, 0.01, "Vulnerabilities: real CISA KEV catalog (1,782 entries on 17 Nov 2026). All other data: simulated for demonstration.", fontsize=8, color="grey")
plt.savefig(OUT / "isms_dashboard.png", dpi=140, bbox_inches="tight")

# ---------------- Risk heat map ----------------
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
for ax, (g, v, title) in zip(axes, [("severity", "likelihood", "Gross risks"),
                                   ("residual_severity", "residual_likelihood", "Residual risks (after treatment)")]):
    grid = np.array([[gg * vv for vv in range(1, 5)] for gg in range(1, 5)])
    ax.imshow(grid, cmap="RdYlGn_r", origin="lower", extent=(0.5, 4.5, 0.5, 4.5), alpha=0.55, vmin=1, vmax=16)
    cell = {}
    for _, r in risks.iterrows():
        cell.setdefault((r[v], r[g]), []).append(r.risk_id)
    for (x, y), ids in cell.items():
        ax.text(x, y, "\n".join([", ".join(ids[i:i + 3]) for i in range(0, len(ids), 3)]), ha="center", va="center", fontsize=8, fontweight="bold")
    ax.set_xticks(range(1, 5)); ax.set_yticks(range(1, 5))
    ax.set_xlabel("Likelihood (1 minimal - 4 almost certain)"); ax.set_ylabel("Severity (1 minor - 4 critical)")
    ax.set_title(title, fontweight="bold")
plt.suptitle("SatObs - Risk map (method inspired by EBIOS RM / ISO 27005)", fontweight="bold")
plt.tight_layout(); plt.savefig(OUT / "risk_heatmap.png", dpi=140)

# ---------------- Excel workbook ----------------
sheets = [("Read me", None), ("KPIs", kpis), ("Assets", assets), ("Risks", risks), ("Treatment_plan", ta),
          ("SoA_93_controls", soa), ("Exceptions", exc), ("KEV_12_months", kev_track), ("Incidents", inc.drop(columns="month")),
          ("BIA", bia), ("BCP_DRP_tests", tests), ("Awareness", aw), ("Corrective_actions", capa), ("Documents", docs)]
xlsx = ROOT / "ISMS_SatObs_registers.xlsx"
readme = pd.DataFrame({"SatObs ISMS - ISO/IEC 27001:2022 registers": [
    "Portfolio project: operational management of an ISMS for SatObs, a FICTIONAL Earth-observation company.",
    "All data is fictional / simulated, EXCEPT the CISA KEV catalog (actively exploited vulnerabilities, real public data).",
    "Reporting date: 15 Nov 2026. Risk method: Severity (1-4) x Likelihood (1-4), inspired by EBIOS RM / ISO 27005.",
    "Sheets: KPIs, assets, risks, treatment plan, SoA (93 controls), exceptions, vulnerabilities, incidents, BIA, tests, awareness, corrective actions, documents.",
    "Code and documents: see the GitHub repository (scripts/ folder)."]})
red_values = ("Overdue", "Review overdue", "EXPIRED - action required", "Open - outside SLA", "Patched outside SLA", "Missing (follow-up gap)")
with pd.ExcelWriter(xlsx, engine="openpyxl") as xw:
    for name, df in sheets:
        (readme if df is None else df).to_excel(xw, sheet_name=name, index=False)
    fill = PatternFill("solid", fgColor="1F3A5F")
    rag_fill = {"Green": "C6E0B4", "Amber": "FFE699", "Red": "F4B6B6"}
    for ws in xw.book.worksheets:
        for c in ws[1]:
            c.font = Font(bold=True, color="FFFFFF"); c.fill = fill
            c.alignment = Alignment(wrap_text=True, vertical="center")
        ws.freeze_panes = "A2"
        for i, col in enumerate(ws.columns, start=1):
            width = max(len(str(c.value)) if c.value is not None else 0 for c in col)
            ws.column_dimensions[get_column_letter(i)].width = min(max(10, width + 2), 60 if ws.title != "Read me" else 140)
        ws.auto_filter.ref = ws.dimensions
        for row in ws.iter_rows(min_row=2):
            for c in row:
                if isinstance(c.value, str):
                    if c.value in rag_fill: c.fill = PatternFill("solid", fgColor=rag_fill[c.value])
                    if c.value in red_values: c.fill = PatternFill("solid", fgColor="F4B6B6")
print(f"Workbook -> {xlsx.name}")
