"""Step 3 — Generate the full Unity Catalog migration script."""
from __future__ import annotations

from datetime import date

import streamlit as st

from lib.ranger_parser import generate_full_script
from lib.state import init_state, render_sidebar_summary, require_policies, stats

st.set_page_config(page_title="Generate SQL", page_icon="💻", layout="wide")
init_state()
render_sidebar_summary()
require_policies()

parsed = st.session_state.parsed_data
items = st.session_state.policy_items
catalog = st.session_state.catalog_name
identity_map = st.session_state.identity_map

eligible = [p for p in items if p["status"] in ("approved", "needs_review")]
grants = [p for p in eligible if p["type"] == "grant"]
denies = [p for p in eligible if p["type"] == "deny"]
filters = [p for p in eligible if p["type"] == "row_filter"]
masks = [p for p in eligible if p["type"] == "column_mask"]

# ── Header ────────────────────────────────────────────────────────────
left, right = st.columns([3, 1])
with left:
    st.title("💻 Generate Unity Catalog SQL")
    st.caption(f"{len(eligible)} eligible policies will be converted to SQL statements")
with right:
    if st.button("Gap Analysis →", type="primary", use_container_width=True):
        st.switch_page("pages/4_Gap_Analysis.py")

# ── Summary cards ─────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("GRANT Statements", len(grants))
c2.metric("DENY Advisories", len(denies))
c3.metric("Row Filter Functions", len(filters))
c4.metric("Column Mask Functions", len(masks))

st.divider()

# ── Generate ──────────────────────────────────────────────────────────
gen_col, _ = st.columns([1, 3])
if gen_col.button(f"🚀 Generate migration script ({len(eligible)} policies)",
                  type="primary", use_container_width=True):
    st.session_state.generated_sql = generate_full_script(
        items,
        identity_map,
        catalog,
        parsed.get("serviceName", "unknown"),
        date.today().isoformat(),
    )

sql_text = st.session_state.get("generated_sql") or ""
if sql_text:
    lines = sql_text.count("\n") + 1
    st.success(f"SQL generated · {lines} lines")

    st.download_button(
        label="⬇ Download .sql",
        data=sql_text,
        file_name=f"uc_migration_{catalog}_{date.today().isoformat()}.sql",
        mime="text/sql",
        use_container_width=False,
    )

    st.markdown(f"**`uc_migration_{catalog}.sql`**")
    st.code(sql_text, language="sql")

    with st.container(border=True):
        st.markdown("##### ⚠️ Execution Notes")
        st.markdown(
            f"""
1. Run this script with a metastore admin or catalog owner role in Databricks SQL or a notebook.
2. Ensure all referenced schemas exist in catalog `{catalog}` before executing grants.
3. DENY policy advisories are commented out — they require manual restructuring before migration.
4. Row filter and column mask functions should be tested against sample data before production deployment.
5. Groups referenced in GRANT statements must be synced to Databricks via SCIM before execution.
            """
        )
else:
    st.info("Click **Generate migration script** above to build the SQL.")

st.divider()
st.page_link("pages/4_Gap_Analysis.py", label="Continue → Gap Analysis", icon="➡️")
