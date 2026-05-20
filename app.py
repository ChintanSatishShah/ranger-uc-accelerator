"""Ranger → Unity Catalog Migration Accelerator — Streamlit entrypoint.

Run with: streamlit run app.py
"""
from __future__ import annotations

import json

import streamlit as st

from lib.sample_data import SAMPLE_RANGER_EXPORT
from lib.state import init_state, load_policies, render_sidebar_summary

st.set_page_config(
    page_title="Ranger → Unity Catalog Migrator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_state()
render_sidebar_summary()

# ── Header ────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="display:inline-block;padding:4px 10px;border-radius:999px;
                background:rgba(124,58,237,0.08);border:1px solid rgba(124,58,237,0.2);
                color:#7c3aed;font-size:11px;font-family:monospace;letter-spacing:1px;
                margin-bottom:12px;">
      🛡 GOVERNANCE MIGRATION
    </div>
    """,
    unsafe_allow_html=True,
)
st.title("Apache Ranger → Unity Catalog")
st.write(
    "Upload your Ranger policy export from Cloudera CDP, HDP, or any Hadoop distribution. "
    "The tool parses all policy types — grants, denies, row filters, and column masks — "
    "and generates equivalent Unity Catalog SQL."
)

# ── Upload + Sample ───────────────────────────────────────────────────
col_upload, col_sample = st.columns(2, gap="medium")

with col_upload:
    st.subheader("📂 Upload Ranger JSON")
    uploaded = st.file_uploader(
        "Ranger policy export (.json)",
        type=["json"],
        label_visibility="collapsed",
    )
    if uploaded is not None:
        try:
            data = json.loads(uploaded.read())
            load_policies(data)
            st.success(f"Loaded {len(data.get('policies', []))} policies from {uploaded.name}")
            st.page_link("pages/1_Identity_Mapping.py", label="Continue → Identity Mapping", icon="➡️")
        except json.JSONDecodeError:
            st.error("Invalid JSON file. Please upload a Ranger policy export.")

with col_sample:
    st.subheader("🗄 Load Sample Policies")
    st.caption("15 policies · Cloudera CDP 7.1 export")
    sample_tags = "  ".join(f"`{t}`" for t in ("Grants", "Denies", "Filters", "Masks"))
    st.markdown(sample_tags)
    if st.button("Load 15-policy sample", type="primary", use_container_width=True):
        load_policies(SAMPLE_RANGER_EXPORT)
        st.success("Sample policies loaded — head to Identity Mapping next.")
        st.page_link("pages/1_Identity_Mapping.py", label="Continue → Identity Mapping", icon="➡️")

st.divider()

# ── Export command snippet ────────────────────────────────────────────
st.markdown("##### 💻 Export from Ranger Admin")
st.code(
    'curl -u admin:password \\\n'
    '  "https://<ranger-host>:6080/service/plugins/policies/exportJson'
    '?serviceName=<hive-service>" \\\n'
    '  -o ranger_policies.json',
    language="bash",
)
st.caption("Works with Cloudera CDP 7.x, HDP 2.x/3.x, and standalone Apache Ranger 2.x")

# ── Feature cards ─────────────────────────────────────────────────────
st.markdown("##### What this tool does")
f1, f2, f3, f4 = st.columns(4)
with f1:
    st.markdown("**📄 Policy Parsing**")
    st.caption("All Ranger policy types")
with f2:
    st.markdown("**👥 Identity Mapping**")
    st.caption("Kerberos → IdP / SCIM")
with f3:
    st.markdown("**👁 Gap Analysis**")
    st.caption("Deny, Kerberos, audit")
with f4:
    st.markdown("**🛡 SQL Generation**")
    st.caption("GRANT, filters, masks")

# ── Workflow steps ────────────────────────────────────────────────────
if st.session_state.get("parsed_data"):
    st.divider()
    st.markdown("##### Next steps")
    st.page_link("pages/1_Identity_Mapping.py", label="1 · Identity Mapping", icon="👥")
    st.page_link("pages/2_Review_Policies.py", label="2 · Review Policies", icon="🛡")
    st.page_link("pages/3_Generate_SQL.py", label="3 · Generate SQL", icon="💻")
    st.page_link("pages/4_Gap_Analysis.py", label="4 · Gap Analysis", icon="⚠️")
    st.page_link("pages/5_Deploy.py", label="5 · Deploy", icon="🚀")
