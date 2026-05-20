"""Step 2 — Review parsed policies, approve/reject, preview SQL."""
from __future__ import annotations

import streamlit as st

from lib.ranger_parser import generate_uc_sql
from lib.state import (
    bulk_set_status,
    init_state,
    render_sidebar_summary,
    require_policies,
    stats,
    update_policy_status,
)

init_state()
render_sidebar_summary()
require_policies()

TYPE_LABELS = {
    "grant": "GRANT",
    "deny": "DENY",
    "row_filter": "ROW FILTER",
    "column_mask": "COL MASK",
    "tag_set": "SET TAGS",
    "tag_grant": "TAG GRANT",
    "tag_placeholder": "TAG (no map)",
    "hdfs_grant": "HDFS GRANT",
    "hbase_grant": "HBASE GRANT",
}
STATUS_LABELS = {
    "pending": "Pending",
    "approved": "Approved",
    "needs_review": "Needs Review",
    "rejected": "Skipped",
}

parsed = st.session_state.parsed_data
items = st.session_state.policy_items
warnings = st.session_state.warnings
s = stats()

# ── Header ────────────────────────────────────────────────────────────
left, right = st.columns([3, 2])
with left:
    st.title("🛡 Review Policies")
    st.caption(f"{s['total']} rules parsed from {parsed['totalRangerPolicies']} Ranger policies")
with right:
    btn_cols = st.columns(2)
    if btn_cols[0].button("✅ Approve all valid", use_container_width=True):
        bulk_set_status(
            lambda p: p["type"] != "deny" and p.get("enabled", True) and p.get("status") != "rejected",
            "approved",
        )
        st.rerun()
    if btn_cols[1].button("Generate SQL →", type="primary", use_container_width=True):
        st.switch_page("pages/3_Generate_SQL.py")

# ── Stat chips ────────────────────────────────────────────────────────
chip_cols = st.columns(8)
chip_data = [
    ("Grants", s["grants"]), ("Denies", s["denies"]),
    ("Row Filters", s["rowFilters"]), ("Col Masks", s["masks"]),
    ("Tag Sets", s.get("tagSets", 0) + s.get("tagGrants", 0) + s.get("tagPlaceholders", 0)),
    ("Approved", s["approved"]), ("Needs Review", s["needsReview"]), ("Pending", s["pending"]),
]
for col, (label, val) in zip(chip_cols, chip_data):
    col.metric(label, val)

# ── Warnings ──────────────────────────────────────────────────────────
if warnings:
    with st.expander(f"⚠️ {len(warnings)} Warning(s)", expanded=False):
        for w in warnings:
            st.write(f"- {w['message']}")
            if w.get("recommendation"):
                st.caption(f"  ↳ {w['recommendation']}")

# ── Filters ───────────────────────────────────────────────────────────
f1, f2, f3 = st.columns([3, 1, 1])
search = f1.text_input("Search policies, schemas, principals", label_visibility="collapsed",
                      placeholder="Search policies, schemas, principals…")
type_filter = f2.selectbox(
    "Type",
    ["All", "grant", "deny", "row_filter", "column_mask",
     "tag_set", "tag_grant", "tag_placeholder", "hdfs_grant", "hbase_grant"],
    label_visibility="collapsed",
)
status_filter = f3.selectbox("Status", ["All", "pending", "approved", "needs_review", "rejected"],
                             label_visibility="collapsed")

def _matches(p: dict) -> bool:
    if type_filter != "All" and p["type"] != type_filter:
        return False
    if status_filter != "All" and p["status"] != status_filter:
        return False
    if search:
        term = search.lower()
        haystack = " ".join(str(x or "") for x in [
            p.get("rangerPolicyName"), p.get("schema"), p.get("table"),
            (p.get("principal") or {}).get("name"),
        ]).lower()
        if term not in haystack:
            return False
    return True

filtered = [p for p in items if _matches(p)]
st.caption(f"Showing {len(filtered)} of {len(items)} policy items")

# ── Policy list ───────────────────────────────────────────────────────
catalog = st.session_state.catalog_name
identity_map = st.session_state.identity_map

if not filtered:
    st.info("No policies match your filters.")
else:
    for item in filtered:
        itype = item.get("type", "grant")
        principal_name = (item.get("principal") or {}).get("name", "")
        schema = item.get("schema") or ""
        table = item.get("table")
        if itype == "tag_set":
            col = item.get("column")
            resource = f"`{catalog}.{schema}.{table}{'.' + col if col else ''}`"
        elif itype == "tag_placeholder":
            tags = ", ".join(item.get("tag_names") or [])
            resource = f"tags: `{tags}`"
        elif itype in ("hdfs_grant",):
            resource = f"`{item.get('path', '/')}`"
        elif schema:
            resource = f"`{catalog}.{schema}{('.' + table) if table else '.*'}`"
        else:
            resource = f"`{catalog}.*`"
        privs = ", ".join(item.get("privileges") or [])
        type_label = TYPE_LABELS.get(itype, itype.upper())
        header = (
            f"**[{type_label}]** {resource}"
            + (f" → `{principal_name}`" if principal_name else "")
            + (f" · [{privs}]" if privs else "")
            + (" · _disabled_" if not item.get("enabled", True) else "")
            + f" · _{STATUS_LABELS[item['status']]}_"
        )

        with st.expander(header, expanded=False):
            d1, d2 = st.columns([3, 2])
            with d1:
                st.markdown(f"**Ranger Policy:** {item['rangerPolicyName']} _(ID {item.get('rangerPolicyId', '—')})_")
                if item.get("rangerPolicyDesc"):
                    st.caption(item["rangerPolicyDesc"])
                st.markdown(
                    f"**Resource:** `{catalog}.{item['schema']}"
                    f"{('.' + item['table']) if item.get('table') else '.*'}`"
                )
                if item.get("columns"):
                    st.markdown(f"**Columns:** `{', '.join(item['columns'])}`")
                st.markdown(
                    f"**Principal:** {item['principal']['type']} → `{principal_name}`"
                )
                if item.get("filterExpr"):
                    st.markdown("**Row Filter:**")
                    st.code(item["filterExpr"], language="sql")
                if item.get("maskType"):
                    st.markdown(f"**Mask Type:** `{item['maskType']}`")

                action_cols = st.columns(3)
                if action_cols[0].button("✅ Approve", key=f"approve-{item['id']}", use_container_width=True):
                    update_policy_status(item["id"], "approved")
                    st.rerun()
                if action_cols[1].button("⚠️ Needs Review", key=f"review-{item['id']}", use_container_width=True):
                    update_policy_status(item["id"], "needs_review")
                    st.rerun()
                if action_cols[2].button("❌ Skip", key=f"skip-{item['id']}", use_container_width=True):
                    update_policy_status(item["id"], "rejected")
                    st.rerun()

            with d2:
                st.markdown("**Preview SQL**")
                st.code(
                    generate_uc_sql(item, identity_map, catalog) or "-- no SQL emitted",
                    language="sql",
                )

st.divider()
st.page_link("pages/3_Generate_SQL.py", label="Continue → Generate SQL", icon="➡️")
