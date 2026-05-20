"""Step 6 — Session history and archive management."""
from __future__ import annotations

import streamlit as st

from lib.history import (
    delete_archive,
    export_session_as_zip,
    list_archives,
    load_session,
)
from lib.state import (
    init_state,
    render_sidebar_summary,
    restore_session,
    save_current_session,
)

st.set_page_config(page_title="History", page_icon="📋", layout="wide")
init_state()
render_sidebar_summary()

st.title("📋 Session History & Archives")
st.caption("Save, manage, and restore migration sessions")

# ── Save Current Session ──────────────────────────────────────────────
parsed = st.session_state.get("parsed_data")
if parsed:
    st.subheader("💾 Archive Current Session")
    col1, col2 = st.columns([3, 1])
    with col1:
        notes = st.text_input("Session notes (optional)", placeholder="e.g., Production migration attempt 1")
    with col2:
        st.write("")
        if st.button("Save & Archive", type="primary", use_container_width=True):
            try:
                filename = save_current_session(notes=notes)
                st.success(f"Session archived: `{filename}`")
            except Exception as e:
                st.error(f"Failed to save session: {e}")
    st.divider()
else:
    st.info("Load policies on the Migrator page before archiving.")
    st.divider()

# ── List Archives ────────────────────────────────────────────────────
st.subheader("📁 Archived Sessions")
archives = list_archives()

if not archives:
    st.info("No archived sessions yet. Load policies and click 'Save & Archive' to get started.")
else:
    # Display as expandable list
    for i, archive in enumerate(archives):
        meta = archive["metadata"]
        timestamp = meta.get("timestamp", "unknown")
        service = meta.get("service_name", "Unknown")
        catalog = meta.get("catalog_name", "main")
        notes = meta.get("notes", "")
        
        with st.expander(f"📦 {service} · {timestamp[:10]} · {archive['size_kb']:.1f} KB"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**Cluster:** `{meta.get('cluster_name', 'unknown')}`")
                st.markdown(f"**Catalog:** `{catalog}`")
                st.markdown(f"**Timestamp:** {timestamp}")
                if notes:
                    st.markdown(f"**Notes:** {notes}")
                st.caption(f"File: `{archive['filename']}`")
            
            with col2:
                # Load button
                if st.button("🔄 Load", key=f"load_{i}", use_container_width=True):
                    try:
                        loaded_archive = load_session(archive["filename"])
                        restore_session(loaded_archive)
                        st.success("Session restored!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to load: {e}")
                
                # Export button
                if st.button("📥 Export", key=f"export_{i}", use_container_width=True):
                    try:
                        zip_data = export_session_as_zip(archive["filename"])
                        st.download_button(
                            label="Download ZIP",
                            data=zip_data,
                            file_name=f"{service}_{timestamp[:10]}.zip",
                            mime="application/zip",
                            key=f"download_{i}",
                        )
                    except Exception as e:
                        st.error(f"Failed to export: {e}")
                
                # Delete button
                if st.button("🗑️ Delete", key=f"delete_{i}", use_container_width=True):
                    delete_archive(archive["filename"])
                    st.success("Deleted!")
                    st.rerun()

st.divider()
st.markdown("### Archive Contents")
st.caption("Each archive contains:")
st.markdown("""
- **METADATA.json** — timestamp, source, catalog, notes
- **ranger_export.json** — original Ranger policy export
- **policy_items.json** — parsed policy rules
- **identity_map.json** — user/group mappings
- **generated_migration.sql** — generated UC SQL script
""")
