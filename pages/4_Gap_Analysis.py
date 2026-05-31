"""Step 4 — Gap analysis with severity breakdown and readiness score."""
from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st

from lib.ranger_parser import is_not_translatable
from lib.state import gaps, init_state, render_sidebar_summary, require_policies, stats

init_state()
render_sidebar_summary()
require_policies()

SEVERITY_ICONS = {"critical": "🛑", "warning": "⚠️", "info": "ℹ️"}
SEVERITY_LABELS = {"critical": "Critical", "warning": "Warning", "info": "Info"}

parsed = st.session_state.parsed_data
items = st.session_state.policy_items
catalog = st.session_state.catalog_name
all_gaps = gaps()
s = stats()

critical_count = sum(1 for g in all_gaps if g["severity"] == "critical")
warning_count = sum(1 for g in all_gaps if g["severity"] == "warning")
info_count = sum(1 for g in all_gaps if g["severity"] == "info")
total_issues = sum(g["count"] for g in all_gaps)

# Readiness score — exclude items that cannot produce executable SQL
total = s["total"]
not_translatable = s.get("notTranslatable", s["denies"])
translatable     = total - not_translatable
readiness_base   = (translatable / total * 100) if total > 0 else 0
critical_penalty = critical_count * 10
warning_penalty  = warning_count * 3
readiness        = max(0, round(readiness_base - critical_penalty - warning_penalty))

# Per-type breakdown of non-translatable items
nt_deny  = sum(1 for p in items if p.get("type") == "deny")
nt_tag   = sum(1 for p in items if p.get("type") == "tag_placeholder")
nt_hbase = sum(1 for p in items if is_not_translatable(p) and p.get("type") == "hbase_grant")

# ── Header ────────────────────────────────────────────────────────────
left, right = st.columns([3, 2])
with left:
    st.title("⚠️ Gap Analysis")
    st.caption(f"{len(all_gaps)} categories · {total_issues} total items requiring attention")

# ── Readiness + severity ──────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Migration Readiness", f"{readiness}%",
              delta=("Ready" if readiness >= 70 else
                     "Needs attention" if readiness >= 40 else
                     "Significant gaps"),
              delta_color="normal" if readiness >= 70 else "inverse")
c2.metric("🛑 Critical", critical_count,
          f"{sum(g['count'] for g in all_gaps if g['severity'] == 'critical')} items")
c3.metric("⚠️ Warning", warning_count,
          f"{sum(g['count'] for g in all_gaps if g['severity'] == 'warning')} items")
c4.metric("ℹ️ Info", info_count,
          f"{sum(g['count'] for g in all_gaps if g['severity'] == 'info')} items")

st.progress(readiness / 100)

# ── Readiness score breakdown ─────────────────────────────────────────
if total > 0:
    rows = []
    rows.append({
        "Factor": f"✅ Auto-translatable items ({translatable} of {total})",
        "Impact": f"+{round(readiness_base)}%",
        "Detail": "Grants, row filters, masks, HDFS, HBase (non-wildcard), UDF, tag grants",
    })
    if not_translatable:
        parts = []
        if nt_deny:  parts.append(f"deny ×{nt_deny}")
        if nt_tag:   parts.append(f"tag placeholder ×{nt_tag}")
        if nt_hbase: parts.append(f"HBase wildcard ×{nt_hbase}")
        rows.append({
            "Factor": f"⛔ Non-translatable items ({not_translatable} of {total})",
            "Impact": f"−{round(not_translatable / total * 100)}%",
            "Detail": ", ".join(parts) + " — advisory comment only; no executable SQL",
        })
    if critical_penalty:
        rows.append({
            "Factor": f"🛑 Critical gap penalty ({critical_count} issue{'s' if critical_count != 1 else ''})",
            "Impact": f"−{critical_penalty} pts",
            "Detail": f"{critical_count} × 10 pts — review critical gaps below",
        })
    if warning_penalty:
        rows.append({
            "Factor": f"⚠️ Warning penalty ({warning_count} warning{'s' if warning_count != 1 else ''})",
            "Impact": f"−{warning_penalty} pts",
            "Detail": f"{warning_count} × 3 pts — review warnings below",
        })
    rows.append({
        "Factor": "📊 Final Migration Readiness",
        "Impact": f"{readiness}%",
        "Detail": "Resolve non-translatable items and gaps above to improve this score",
    })
    with st.expander("📊 How is this score calculated?", expanded=(not_translatable > 0 or critical_count > 0)):
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ── Export report ─────────────────────────────────────────────────────
def _build_report() -> str:
    lines: list[str] = []
    lines.append("╔═══════════════════════════════════════════════════════════════╗")
    lines.append("║  Ranger → Unity Catalog: Gap Analysis Report                ║")
    lines.append(f"║  Generated: {datetime.utcnow().isoformat()}Z                ║")
    lines.append(f"║  Source: {parsed['serviceName']}")
    lines.append(f"║  Target Catalog: {catalog}")
    lines.append("╚═══════════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append("═══ EXECUTIVE SUMMARY ═══════════════════════════════════════════")
    lines.append("")
    lines.append(f"Total Ranger Policies:      {parsed['totalRangerPolicies']}")
    lines.append(f"Parsed Policy Items:        {s['total']}")
    lines.append(f"  Auto-translatable:        {translatable}")
    lines.append(f"  Non-translatable:         {not_translatable}"
                 + (f"  (deny={nt_deny}, tag_placeholder={nt_tag}, hbase_wildcard={nt_hbase})" if not_translatable else ""))
    lines.append(f"Migration Readiness:        {readiness}%")
    lines.append(f"  Base (translatable only): {round(readiness_base)}%")
    if critical_penalty: lines.append(f"  Critical gap penalty:     -{critical_penalty} pts ({critical_count} issues × 10)")
    if warning_penalty:  lines.append(f"  Warning penalty:          -{warning_penalty} pts ({warning_count} warnings × 3)")
    lines.append(f"Critical Issues:            {critical_count}")
    lines.append(f"Warnings:                   {warning_count}")
    lines.append(f"Total Items Requiring Attention: {total_issues}")
    lines.append("")
    for g in all_gaps:
        lines.append(f"═══ {g['category'].upper()} ({g['severity'].upper()}) ═══════════════")
        lines.append(f"Count: {g['count']}")
        lines.append(f"Description: {g['description']}")
        lines.append(f"Remediation: {g['remediation']}")
        lines.append("")
        for item in g["items"]:
            lines.append(f"  • Resource: {item['resource']}")
            lines.append(f"    Principal: {item['principal']}")
            lines.append(f"    Detail: {item['detail']}")
            lines.append("")
    return "\n".join(lines)

with right:
    st.download_button(
        "⬇ Export report",
        data=_build_report(),
        file_name=f"gap_analysis_{catalog}_{datetime.utcnow().date().isoformat()}.txt",
        mime="text/plain",
        use_container_width=True,
    )
    if st.button("Deploy Guide →", type="primary", use_container_width=True):
        st.switch_page("pages/5_Deploy.py")

st.divider()

# ── Gap categories ────────────────────────────────────────────────────
if not all_gaps:
    st.success("✅ No gaps detected — all policies translate cleanly to Unity Catalog.")
else:
    for gap in all_gaps:
        icon = SEVERITY_ICONS[gap["severity"]]
        label = SEVERITY_LABELS[gap["severity"]]
        with st.expander(
            f"{icon} **{gap['category']}** — {label} · {gap['count']} items",
            expanded=(gap["severity"] == "critical"),
        ):
            st.markdown(f"_{gap['description']}_")
            st.info(f"**Recommended remediation:** {gap['remediation']}")
            if gap["items"]:
                df = pd.DataFrame(gap["items"])
                st.dataframe(df, use_container_width=True, hide_index=True)

st.divider()

# ── Migration risk summary ────────────────────────────────────────────
with st.container(border=True):
    st.markdown("##### 📄 Migration Risk Summary")
    cols = st.columns(2)
    cols[0].markdown(f"**Source Cluster:** `{parsed['clusterName']}`")
    cols[1].markdown(f"**Source Service:** `{parsed['serviceName']}`")
    cols[0].markdown(f"**Total Ranger Policies:** `{parsed['totalRangerPolicies']}`")
    cols[1].markdown(f"**Target Catalog:** `{catalog}`")
    cols[0].markdown(f"**Schemas Affected:** `{s['schemaCount']}`")
    cols[1].markdown(f"**Principals:** `{s['principalCount']}`")

    if critical_count > 2:
        effort = "**High** — 4–6 weeks including governance redesign"
    elif critical_count > 0:
        effort = "**Medium** — 2–4 weeks with targeted remediation"
    else:
        effort = "**Low** — 1–2 weeks, mostly testing and validation"
    st.markdown(f"**Estimated Effort:** {effort}")

st.page_link("pages/5_Deploy.py", label="Continue → Deploy", icon="➡️")
