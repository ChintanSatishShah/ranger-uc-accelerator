"""Session-state helpers — Streamlit's analog of the React MigrationContext."""
from __future__ import annotations

from typing import Any

import streamlit as st

from .history import save_session as _save_session
from .ranger_parser import (
    calculate_stats,
    generate_gap_analysis,
    parse_ranger_policies,
)


def init_state() -> None:
    defaults = {
        "raw_json": None,
        "parsed_data": None,
        "policy_items": [],
        "warnings": [],
        "identity_map": {},
        "catalog_name": "main",
        "generated_sql": "",
        "checked_steps": set(),
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def load_policies(json_data: dict[str, Any] | list[Any]) -> None:
    parsed = parse_ranger_policies(json_data)
    st.session_state.raw_json = json_data
    st.session_state.parsed_data = parsed
    st.session_state.policy_items = parsed["results"]
    st.session_state.warnings = parsed["warnings"]
    st.session_state.identity_map = {idn["name"]: idn["name"] for idn in parsed["identities"]}
    st.session_state.generated_sql = ""


def reset() -> None:
    for k in (
        "raw_json", "parsed_data", "policy_items", "warnings",
        "identity_map", "generated_sql", "checked_steps",
    ):
        if k in st.session_state:
            del st.session_state[k]
    init_state()


def update_policy_status(policy_id: str, status: str) -> None:
    for p in st.session_state.policy_items:
        if p["id"] == policy_id:
            p["status"] = status
            break


def bulk_set_status(predicate, status: str) -> None:
    for p in st.session_state.policy_items:
        if predicate(p):
            p["status"] = status


def stats() -> dict[str, Any]:
    return calculate_stats(st.session_state.policy_items)


def gaps() -> list[dict[str, Any]]:
    if not st.session_state.parsed_data:
        return []
    return generate_gap_analysis(
        st.session_state.parsed_data,
        st.session_state.identity_map,
        st.session_state.catalog_name,
    )


def require_policies() -> bool:
    """Show a stop screen if no policies are loaded. Returns True if loaded."""
    if not st.session_state.get("parsed_data"):
        st.warning("Upload Ranger policies on the home page before continuing.")
        st.page_link("app.py", label="← Go to Upload", icon="📂")
        st.stop()
    return True


def render_sidebar_summary() -> None:
    """Render the migration summary in the Streamlit sidebar."""
    parsed = st.session_state.get("parsed_data")
    with st.sidebar:
        if parsed:
            s = stats()
            st.markdown("**Migration Summary**")
            c1, c2 = st.columns(2)
            c1.metric("Policies", s["total"])
            c2.metric("Schemas", s["schemaCount"])
            c1.metric("Approved", s["approved"])
            c2.metric("Review", s["needsReview"])
            st.caption(f"Source: `{parsed['serviceName']}`")
            st.caption(f"Cluster: `{parsed['clusterName']}`")
            st.divider()
            if st.button("Reset session", use_container_width=True):
                reset()
                st.rerun()
        else:
            st.caption("No policies loaded yet.")


def save_current_session(notes: str = "", source_file: str = "") -> str:
    """Archive the current session. Returns filename (prefixed with user_)."""
    service = (st.session_state.parsed_data or {}).get("serviceName", "session")
    import re as _re
    safe = _re.sub(r"[^a-z0-9_-]", "_", service.lower())[:40]
    return _save_session(
        parsed_data=st.session_state.parsed_data,
        policy_items=st.session_state.policy_items,
        identity_map=st.session_state.identity_map,
        catalog_name=st.session_state.catalog_name,
        generated_sql=st.session_state.generated_sql,
        notes=notes,
        label=f"user_{safe}",
        add_timestamp=True,
        source_file=source_file,
    )


def restore_session(archive: dict[str, Any]) -> None:
    """Restore a session from an archive."""
    st.session_state.parsed_data = archive["parsed_data"]
    st.session_state.policy_items = archive["policy_items"]
    st.session_state.identity_map = archive["identity_map"]
    st.session_state.catalog_name = archive["metadata"].get("catalog_name", "main")
    st.session_state.generated_sql = archive.get("generated_sql", "")
