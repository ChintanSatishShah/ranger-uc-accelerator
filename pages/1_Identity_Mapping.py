"""Step 1 — Map Ranger identities to Databricks principals."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from lib.state import init_state, render_sidebar_summary, require_policies

st.set_page_config(page_title="Identity Mapping", page_icon="👥", layout="wide")
init_state()
render_sidebar_summary()
require_policies()

parsed = st.session_state.parsed_data
identities = parsed["identities"]
kerberos_issues = parsed["kerberosIssues"]
groups = [i for i in identities if i["type"] == "group"]
users = [i for i in identities if i["type"] == "user"]

st.title("👥 Identity Mapping")
st.caption(
    f"Map {len(groups)} groups and {len(users)} users from Ranger to Databricks principals"
)

# ── Catalog name ──────────────────────────────────────────────────────
with st.container(border=True):
    st.markdown("**Target Unity Catalog**")
    st.session_state.catalog_name = st.text_input(
        "Catalog name",
        value=st.session_state.catalog_name,
        label_visibility="collapsed",
    )
    st.caption("All generated SQL will use this as the top-level catalog.")

# ── Kerberos warnings ─────────────────────────────────────────────────
if kerberos_issues:
    with st.container(border=True):
        st.markdown(f"#### 🔑 {len(kerberos_issues)} Kerberos / Service Account Issue(s)")
        for issue in kerberos_issues:
            st.warning(
                f"**`{issue['principal']}`** — {issue['recommendation']}",
                icon="⚠️",
            )

# ── Search & filter ───────────────────────────────────────────────────
c1, c2 = st.columns([3, 1])
search_term = c1.text_input("Search identities", placeholder="e.g. finance, svc", label_visibility="collapsed")
filter_type = c2.selectbox("Type", ["All", "Group", "User"], label_visibility="collapsed")

kerb_set = {k["principal"] for k in kerberos_issues}

def _matches(idn: dict) -> bool:
    if filter_type == "Group" and idn["type"] != "group":
        return False
    if filter_type == "User" and idn["type"] != "user":
        return False
    if search_term and search_term.lower() not in idn["name"].lower():
        return False
    return True

filtered = [i for i in identities if _matches(i)]

# ── Editable mapping table ────────────────────────────────────────────
st.markdown("##### Mapping (edit the Databricks principal column)")
rows = []
for idn in filtered:
    rows.append({
        "Type": idn["type"],
        "Ranger Identity": idn["name"],
        "Kerberos": "🔑" if idn["name"] in kerb_set else "",
        "Databricks Principal": st.session_state.identity_map.get(idn["name"], idn["name"]),
    })
df = pd.DataFrame(rows)

edited = st.data_editor(
    df,
    use_container_width=True,
    hide_index=True,
    column_config={
        "Type": st.column_config.TextColumn(disabled=True, width="small"),
        "Ranger Identity": st.column_config.TextColumn(disabled=True),
        "Kerberos": st.column_config.TextColumn(disabled=True, width="small"),
        "Databricks Principal": st.column_config.TextColumn(required=True),
    },
    key="identity_editor",
)

# Persist edits back into identity_map
for _, row in edited.iterrows():
    st.session_state.identity_map[row["Ranger Identity"]] = row["Databricks Principal"]

st.caption(
    f"{len(identities)} identities found across {parsed['totalRangerPolicies']} Ranger policies "
    f"from cluster `{parsed['clusterName']}`"
)

st.divider()
st.page_link("pages/2_Review_Policies.py", label="Continue → Review Policies", icon="➡️")
