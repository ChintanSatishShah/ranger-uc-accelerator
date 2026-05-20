"""Ranger → Unity Catalog Migration Accelerator — Streamlit entrypoint.

Run with: streamlit run app.py
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

import streamlit as st

from lib.sample_data import SAMPLE_FILES, load_sample
from lib.state import init_state, load_policies, render_sidebar_summary

INPUT_DIR = Path(__file__).parent / "data" / "input"


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "_", name.lower())[:40]


def _save_to_input(data: dict, filename: str) -> str:
    """Persist raw JSON to data/input/ with user_ prefix. Returns saved filename."""
    safe = f"user_{filename}" if not filename.startswith("user_") else filename
    (INPUT_DIR / safe).write_text(json.dumps(data, indent=2))
    return safe

st.set_page_config(
    page_title="Ranger → UC Migration Accelerator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _home_page() -> None:
    init_state()
    render_sidebar_summary()

    # ── Header ────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="display:inline-block;padding:4px 10px;border-radius:999px;
                    background:rgba(124,58,237,0.08);border:1px solid rgba(124,58,237,0.2);
                    color:#7c3aed;font-size:11px;font-family:monospace;letter-spacing:1px;
                    margin-bottom:12px;">
          🛡 GOVERNANCE POLICY MIGRATION
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.title("Apache Ranger → Unity Catalog Migrator")
    st.write(
        "The tool parses all the policy types supported by Unity Catalog — grants, row filters, "
        "and column masks — and generates equivalent Unity Catalog SQL."
    )

    # ── Input: Upload / Paste / Sample ───────────────────────────────
    tab_upload, tab_paste, tab_sample = st.tabs(["📂 Upload File", "✏️ Paste JSON", "🗄 Load Sample"])

    def _on_loaded(data: dict, source: str) -> None:
        load_policies(data)
        count = len(data.get("policies", []))
        st.success(f"Loaded {count} policies from {source}.")
        st.page_link("pages/1_Identity_Mapping.py", label="Continue → Identity Mapping", icon="➡️")

    # ── Tab 1: Upload file or pick from input/ folder ─────────────────
    with tab_upload:
        uploaded = st.file_uploader(
            "Ranger policy export (.json)",
            type=["json"],
            label_visibility="collapsed",
        )
        if uploaded is not None:
            try:
                data = json.loads(uploaded.read())
                saved_name = _save_to_input(data, uploaded.name)
                st.caption(f"Saved to `data/input/{saved_name}`")
                _on_loaded(data, uploaded.name)
            except json.JSONDecodeError:
                st.error("Invalid JSON — please upload a Ranger policy export.")

        # Show all JSON files; separate samples (no user_ prefix) from user uploads
        all_input = sorted(INPUT_DIR.glob("*.json"))
        sample_files = [f for f in all_input if not f.name.startswith("user_")]
        user_files = [f for f in all_input if f.name.startswith("user_")]
        if sample_files or user_files:
            groups: list[str] = []
            if sample_files:
                groups.append("── Samples ──")
                groups.extend(f.name for f in sample_files)
            if user_files:
                groups.append("── My uploads ──")
                groups.extend(f.name for f in user_files)
            st.markdown("**Or pick from `input/` folder:**")
            chosen = st.selectbox("input/ files", groups, label_visibility="collapsed")
            is_header = chosen.startswith("──")
            if st.button("Load selected file", use_container_width=True, disabled=is_header):
                try:
                    data = json.loads((INPUT_DIR / chosen).read_text())
                    _on_loaded(data, chosen)
                except (json.JSONDecodeError, OSError) as e:
                    st.error(f"Could not read file: {e}")
        else:
            st.caption("Drop `.json` files into the `input/` folder to make them available here.")

    # ── Tab 2: Paste raw JSON ─────────────────────────────────────────
    with tab_paste:
        raw = st.text_area(
            "Paste Ranger policy JSON here",
            height=260,
            placeholder='{\n  "serviceName": "...",\n  "policies": [ ... ]\n}',
            label_visibility="collapsed",
        )
        if st.button("Parse pasted JSON", type="primary", use_container_width=True):
            if not raw.strip():
                st.warning("Paste some JSON first.")
            else:
                try:
                    data = json.loads(raw)
                    service = data.get("serviceName", "pasted")
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    fname = f"user_pasted_{_slugify(service)}_{ts}.json"
                    _save_to_input(data, fname)
                    st.caption(f"Saved to `data/input/{fname}`")
                    _on_loaded(data, fname)
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON: {e}")

    # ── Tab 3: Built-in samples ───────────────────────────────────────
    with tab_sample:
        _options: list[str] = []
        _label_to_file: dict[str, str] = {}
        _current_category = None
        for _s in SAMPLE_FILES:
            if _s["category"] != _current_category:
                _options.append(f"── {_s['category']} ──")
                _current_category = _s["category"]
            _label = _s["display_name"]
            _options.append(_label)
            _label_to_file[_label] = _s["filename"]

        _selected = st.selectbox(
            "Choose a sample",
            _options,
            index=1,
            label_visibility="collapsed",
        )
        _is_header = _selected and _selected.startswith("──")
        _meta = next((s for s in SAMPLE_FILES if s["display_name"] == _selected), None)
        if _meta:
            tags_md = "  ".join(f"`{t}`" for t in _meta["tags"])
            st.caption(f"{_meta['policy_count']} policies · {_meta['service_type'].upper()} · {tags_md}")
            st.caption(_meta["description"])

        if st.button(
            "Load sample",
            type="primary",
            use_container_width=True,
            disabled=_is_header or _meta is None,
        ):
            try:
                data = load_sample(_label_to_file[_selected])
                _on_loaded(data, _selected)
            except FileNotFoundError:
                st.error("Sample file not found. Check that the samples/ folder is present.")

    st.divider()

    # ── Export command snippet ────────────────────────────────────────
    st.markdown("##### 💻 Export from Ranger Admin")
    st.code(
        'curl -u admin:password \\\n'
        '  "https://<ranger-host>:6080/service/plugins/policies/exportJson'
        '?serviceName=<hive-service>" \\\n'
        '  -o ranger_policies.json',
        language="bash",
    )
    st.caption("Works with Cloudera CDP 7.x, HDP 2.x/3.x, and standalone Apache Ranger 2.x")

    # ── Feature cards ────────────────────────────────────────────────
    st.markdown("##### What this tool does")
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        st.markdown("**📄 Policy Parsing**")
        st.caption("All Ranger policy types")
    with f2:
        st.markdown("**👥 Identity Mapping**")
        st.caption("Kerberos → IdP / SCIM")
    with f3:
        st.markdown("**⚠️ Gap Analysis**")
        st.caption("Kerberos, audit, readiness")
    with f4:
        st.markdown("**🛡 SQL Generation**")
        st.caption("GRANT, filters, masks")

    # ── Workflow steps ────────────────────────────────────────────────
    if st.session_state.get("parsed_data"):
        st.divider()
        st.markdown("##### Next steps")
        st.page_link("pages/1_Identity_Mapping.py", label="1 · Identity Mapping", icon="👥")
        st.page_link("pages/2_Review_Policies.py", label="2 · Review Policies", icon="🛡")
        st.page_link("pages/3_Generate_SQL.py", label="3 · Generate SQL", icon="💻")
        st.page_link("pages/4_Gap_Analysis.py", label="4 · Gap Analysis", icon="⚠️")
        st.page_link("pages/5_Deploy.py", label="5 · Deploy", icon="🚀")


# ── Navigation ────────────────────────────────────────────────────────
pg = st.navigation(
    {
        "Migration Steps": [
            st.Page(_home_page, title="Policy Import", icon="📂", default=True),
            st.Page("pages/1_Identity_Mapping.py", title="Identity Mapping", icon="👥"),
            st.Page("pages/2_Review_Policies.py", title="Review Policies", icon="🛡️"),
            st.Page("pages/3_Generate_SQL.py", title="Generate SQL", icon="💻"),
            st.Page("pages/4_Gap_Analysis.py", title="Gap Analysis", icon="⚠️"),
            st.Page("pages/5_Deploy.py", title="Deploy", icon="🚀"),
        ],
        "History": [
            st.Page("pages/6_History.py", title="Session Archive", icon="📋"),
        ],
        "References": [
            st.Page("pages/7_Migration_Mappings.py", title="Migration Mappings", icon="📖"),
            st.Page("pages/8_Cautions_Constraints.py", title="Cautions & Constraints", icon="⚠️"),
        ],
    }
)
pg.run()
