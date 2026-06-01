"""Step 5 — 5-phase deployment checklist."""
from __future__ import annotations

import streamlit as st

from lib.state import gaps, init_state, render_sidebar_summary, require_policies, stats

init_state()
render_sidebar_summary()
require_policies()

DEPLOY_PHASES = [
    {
        "id": "pre-reqs",
        "title": "Pre-requisites & Setup",
        "icon": "🗄",
        "steps": [
            {
                "label": "Unity Catalog metastore configured",
                "detail": "Ensure a Unity Catalog metastore is created and attached to your "
                          "Databricks workspace. Metastore admin role is required.",
                "doc_link": "https://docs.databricks.com/en/data-governance/unity-catalog/get-started.html",
            },
            {
                "label": "Target catalog exists",
                "detail": "Create the target catalog if it doesn't exist.",
                "sql": "CREATE CATALOG IF NOT EXISTS {catalog};",
            },
            {
                "label": "All referenced schemas exist",
                "detail": "Create schemas for each database referenced in your Ranger policies.",
                "sql": "-- Run for each schema:\nCREATE SCHEMA IF NOT EXISTS {catalog}.<schema_name>;",
            },
            {
                "label": "Storage credentials configured",
                "detail": "If migrating external tables, create storage credentials and external "
                          "locations pointing to your cloud storage (S3/ADLS/GCS).",
            },
            {
                "label": "Tables migrated or created",
                "detail": "Ensure all tables referenced in the migration script exist in Unity Catalog. "
                          "Use the Databricks migration wizard or manual DDL.",
            },
        ],
    },
    {
        "id": "identity",
        "title": "Identity Provider Sync",
        "icon": "👥",
        "steps": [
            {
                "label": "IdP integration configured (Okta/Entra ID/Ping)",
                "detail": "Configure SCIM provisioning from your Identity Provider to sync "
                          "users and groups to Databricks account.",
                "doc_link": "https://docs.databricks.com/en/admin/users-groups/scim/index.html",
            },
            {
                "label": "All Ranger groups synced to Databricks",
                "detail": "Verify every group referenced in your migration script exists in the "
                          "Databricks account. Check Account Console → Groups.",
            },
            {
                "label": "Service principals created",
                "detail": "For each Kerberos service account / keytab-based identity, create a "
                          "Databricks service principal and generate OAuth M2M tokens.",
            },
            {
                "label": "Identity mapping verified",
                "detail": "Confirm the Ranger → Databricks identity mapping matches your SCIM sync. "
                          "Check for name mismatches, removed users, and merged groups.",
            },
        ],
    },
    {
        "id": "dry-run",
        "title": "Dry Run in Test Catalog",
        "icon": "🧪",
        "steps": [
            {
                "label": "Create test catalog",
                "detail": "Clone your production catalog or create a test catalog with the same "
                          "schema/table structure.",
                "sql": "CREATE CATALOG IF NOT EXISTS {catalog}_test;\n-- Mirror schemas from {catalog}",
            },
            {
                "label": "Execute migration script against test catalog",
                "detail": "Run the generated SQL script replacing the target catalog with your "
                          "test catalog. Note any errors.",
            },
            {
                "label": "Validate permissions with sample queries",
                "detail": "For each principal, run SHOW GRANTS and execute sample SELECT/MODIFY "
                          "queries to verify access matches Ranger behavior.",
                "sql": "SHOW GRANTS ON SCHEMA {catalog}_test.<schema>;\n"
                       "SHOW GRANTS `<principal>` ON CATALOG {catalog}_test;",
            },
            {
                "label": "Test row filters and column masks",
                "detail": "Query tables with row filters as different users to verify filter "
                          "expressions work correctly. Check masked column output.",
            },
            {
                "label": "Document any discrepancies",
                "detail": "Compare Ranger audit logs with UC test results. Document any access "
                          "differences for compliance review.",
            },
        ],
    },
    {
        "id": "production",
        "title": "Production Deployment",
        "icon": "🚀",
        "steps": [
            {
                "label": "Get compliance/CISO sign-off",
                "detail": "Present the gap analysis report and dry-run results to your compliance "
                          "team. Get formal approval for the governance cutover.",
            },
            {
                "label": "Schedule maintenance window",
                "detail": "Coordinate with data platform and application teams. Plan a window "
                          "where no ETL jobs or user queries are running.",
            },
            {
                "label": "Execute migration script in production",
                "detail": "Run the SQL script against your production catalog. Monitor for errors "
                          "and keep a rollback plan.",
            },
            {
                "label": "Enable Unity Catalog audit logging",
                "detail": "Verify that system.access.audit is capturing all access events. This "
                          "replaces Ranger audit logs.",
                "sql": "SELECT * FROM system.access.audit\n"
                       "WHERE event_date = current_date()\n"
                       "ORDER BY event_time DESC\n"
                       "LIMIT 100;",
            },
            {
                "label": "Disable Ranger policies (don't delete)",
                "detail": "Disable Ranger policies after verifying UC grants work correctly. "
                          "Keep them disabled (not deleted) for 30–90 days as rollback safety net.",
            },
        ],
    },
    {
        "id": "validation",
        "title": "Post-Migration Validation",
        "icon": "📋",
        "steps": [
            {
                "label": "Run access validation suite",
                "detail": "Execute a comprehensive test for each principal: verify SELECT works "
                          "on allowed tables, verify denied access is actually blocked.",
            },
            {
                "label": "Compare Ranger audit vs UC audit",
                "detail": "Pull last 7 days of Ranger audit logs and compare access patterns with "
                          "UC audit logs. Flag any new DENIED events that shouldn't be denied.",
            },
            {
                "label": "Monitor for 1–2 weeks",
                "detail": "Keep Ranger policies disabled (not deleted) during the monitoring period. "
                          "Watch UC audit logs for unexpected DENIED events.",
            },
            {
                "label": "Archive Ranger audit logs",
                "detail": "Export and archive Ranger audit logs for compliance retention. Map old "
                          "audit entries to new UC object paths for continuity.",
            },
            {
                "label": "Decommission Ranger policies",
                "detail": "After successful monitoring period, delete Ranger policies. Document "
                          "the migration in your change management system.",
            },
        ],
    },
]


if "checked_steps" not in st.session_state or not isinstance(st.session_state.checked_steps, set):
    st.session_state.checked_steps = set()

parsed = st.session_state.parsed_data
catalog = st.session_state.catalog_name
s = stats()
all_gaps = gaps()
critical_gaps = [g for g in all_gaps if g["severity"] == "critical"]

# ── Header ────────────────────────────────────────────────────────────
st.title("🚀 Deployment Guide")
st.caption("5-phase deployment checklist for your Ranger → Unity Catalog migration")

# ── Progress ──────────────────────────────────────────────────────────
total_steps = sum(len(p["steps"]) for p in DEPLOY_PHASES)
done_steps = len(st.session_state.checked_steps)
progress_pct = (done_steps / total_steps) if total_steps else 0

with st.container(border=True):
    pc1, pc2 = st.columns([3, 1])
    pc1.markdown("**Deployment Progress**")
    pc2.markdown(f"<div style='text-align:right;font-family:monospace;font-weight:bold;color:#7c3aed;'>"
                 f"{done_steps}/{total_steps}</div>", unsafe_allow_html=True)
    st.progress(progress_pct)
    bottom_l, bottom_r = st.columns(2)
    bottom_l.caption(f"{int(progress_pct * 100)}% complete")
    if critical_gaps:
        bottom_r.markdown(
            f"<div style='text-align:right;color:#dc2626;font-size:13px;'>"
            f"⚠️ {len(critical_gaps)} critical gaps to resolve first</div>",
            unsafe_allow_html=True,
        )

# ── Migration context ────────────────────────────────────────────────
ctx = st.columns(4)
ctx[0].metric("Source", parsed.get("serviceName", "unknown"), parsed.get("serviceType", "hive"))
ctx[1].metric("Target", catalog, "Unity Catalog")
ctx[2].metric("Policies", s["total"], f"{s['approved']} approved")
ctx[3].metric("Schemas", s["schemaCount"], f"{s['principalCount']} principals")

st.divider()

# ── Phases ────────────────────────────────────────────────────────────
for idx, phase in enumerate(DEPLOY_PHASES, start=1):
    phase_steps = phase["steps"]
    phase_done = sum(
        1 for i in range(len(phase_steps))
        if f"{phase['id']}-{i}" in st.session_state.checked_steps
    )
    phase_complete = phase_done == len(phase_steps)
    header_icon = "✅" if phase_complete else phase["icon"]
    header = f"{header_icon} **{idx:02d} · {phase['title']}**  · {phase_done}/{len(phase_steps)} steps"

    with st.expander(header, expanded=(idx == 1)):
        for step_idx, step in enumerate(phase_steps):
            key = f"{phase['id']}-{step_idx}"
            checked = st.checkbox(
                f"**{step['label']}**",
                value=key in st.session_state.checked_steps,
                key=f"chk-{key}",
            )
            if checked:
                st.session_state.checked_steps.add(key)
            else:
                st.session_state.checked_steps.discard(key)

            st.caption(step["detail"])

            if "sql" in step:
                sql_rendered = step["sql"].replace("{catalog}", catalog)
                st.code(sql_rendered, language="sql")

            if "doc_link" in step:
                st.markdown(f"[📘 Databricks Documentation]({step['doc_link']})")
            st.markdown("")

st.divider()

# ── Rollback strategy ─────────────────────────────────────────────────
with st.container(border=True):
    st.markdown("##### 🛡 Rollback Strategy")
    st.write(
        "Keep Ranger policies **disabled (not deleted)** for 30–90 days after production "
        "cutover. If issues arise, re-enable the Ranger policies and revoke UC grants. "
        "Unity Catalog grants are additive and can be cleanly removed with `REVOKE` statements."
    )
