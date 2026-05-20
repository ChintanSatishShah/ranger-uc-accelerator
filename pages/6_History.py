"""Session Archive — save, preview, and restore migration sessions."""
from __future__ import annotations

import re
from collections import Counter

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

init_state()
render_sidebar_summary()

st.title("📋 Session Archive")
st.caption("Save, preview, and restore migration sessions")

# ── Save Current Session ──────────────────────────────────────────────
parsed = st.session_state.get("parsed_data")
if parsed:
    st.subheader("💾 Archive Current Session")
    col1, col2 = st.columns([3, 1])
    with col1:
        notes = st.text_input(
            "Session notes (optional)",
            placeholder="e.g., Production migration attempt 1",
        )
    with col2:
        st.write("")
        if st.button("Save & Archive", type="primary", use_container_width=True):
            try:
                filename = save_current_session(notes=notes)
                st.success(f"Session archived: `{filename}`")
            except Exception as e:
                st.error(f"Failed to save session: {e}")
else:
    st.info("Load policies on the Policy Import page before archiving.")

st.divider()

# ── Archived Sessions ─────────────────────────────────────────────────
st.subheader("📁 Archived Sessions")

archives = list_archives()

if not archives:
    st.info("No archived sessions yet. Load policies and click **Save & Archive** to get started.")
else:
    # ── Replay guide ──────────────────────────────────────────────────
    with st.expander("ℹ️ How to replay a session", expanded=False):
        st.markdown(
            """
**Replaying restores your full session state** — the original Ranger export, all
approve / reject decisions, identity mappings, and the generated SQL — exactly as
they were when you archived.

**Steps:**

1. Find the session below and click **🔄 Restore Session** inside its row.
2. The app reloads with that session active (you'll see the sidebar summary update).
3. Navigate to any step using the left sidebar:

   | Step | What you can do |
   |---|---|
   | **👥 Identity Mapping** | Review or edit Kerberos → Databricks principal mappings |
   | **🛡️ Review Policies** | Check, change, or bulk-update approve / reject decisions |
   | **💻 Generate SQL** | Re-generate or copy the Unity Catalog migration script |
   | **⚠️ Gap Analysis** | Re-examine migration gaps, deny policies, and Kerberos issues |
   | **🚀 Deploy** | Work through the deployment checklist |

4. Archive again at any point to save a new checkpoint with your updates.

> **Tip:** Use the **📊 Summary**, **💻 SQL Script**, and **👥 Identity Map** tabs inside
> each session row to preview the content *before* restoring, so you can confirm
> you're loading the right checkpoint.
            """
        )

    def _badge(text: str, bg: str, fg: str) -> str:
        return (
            f'<span style="background:{bg};color:{fg};padding:2px 10px;'
            f'border-radius:999px;font-size:12px;font-weight:500;'
            f'margin-right:4px;display:inline-block;">{text}</span>'
        )

    # ── Session rows ──────────────────────────────────────────────────
    for i, archive in enumerate(archives):
        meta = archive["metadata"]
        timestamp = meta.get("timestamp", "unknown")
        service = meta.get("service_name", "Unknown")
        catalog = meta.get("catalog_name", "main")
        notes_text = meta.get("notes", "")
        policy_items = archive["policy_items"]
        identity_map = archive["identity_map"]
        generated_sql = archive["generated_sql"]

        type_counts = Counter(p.get("type") for p in policy_items)
        status_counts = Counter(p.get("status") for p in policy_items)
        total = len(policy_items)

        # Derive source name by stripping the _YYYYMMDD_HHMMSS timestamp from the filename
        source_name = re.sub(r"_\d{8}_\d{6}$", "", archive["filename"].removesuffix(".json"))
        expander_label = f"📦  {source_name}"
        if notes_text:
            expander_label += f'  —  "{notes_text}"'

        with st.expander(expander_label):
            # ── Metadata + action buttons ─────────────────────────────
            meta_col, btn_col = st.columns([3, 1])

            with meta_col:
                # Colored metadata badges
                badges = (
                    _badge(timestamp[:10], "#dbeafe", "#1e40af")
                    + _badge(f"{total} items", "#dcfce7", "#166534")
                    + _badge(f"{archive['size_kb']:.1f} KB", "#fef3c7", "#92400e")
                    + _badge(service, "#ede9fe", "#5b21b6")
                )
                st.markdown(badges, unsafe_allow_html=True)
                st.caption(f"📁 {archive['filename']}")
                st.markdown(
                    f"Catalog: `{catalog}` · Cluster: `{meta.get('cluster_name', 'unknown')}` "
                    f"· Archived: {timestamp.replace('T', ' ')[:19]} UTC"
                )
                if notes_text:
                    st.caption(f"Notes: {notes_text}")

            with btn_col:
                if st.button("🔄 Restore Session", key=f"load_{i}", use_container_width=True,
                             type="primary"):
                    try:
                        loaded = load_session(archive["filename"])
                        restore_session(loaded)
                        st.success("Session restored — use the sidebar to navigate.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to restore: {e}")

                try:
                    zip_data = export_session_as_zip(archive["filename"])
                    st.download_button(
                        label="📥 Download ZIP",
                        data=zip_data,
                        file_name=f"{service}_{timestamp[:10]}.zip",
                        mime="application/zip",
                        key=f"download_{i}",
                        use_container_width=True,
                    )
                except Exception:
                    pass

                if st.button("🗑️ Delete", key=f"delete_{i}", use_container_width=True):
                    delete_archive(archive["filename"])
                    st.rerun()

            st.divider()

            # ── Preview tabs ──────────────────────────────────────────
            tab_summary, tab_sql, tab_identity = st.tabs(
                ["📊 Summary", "💻 SQL Script", "👥 Identity Map"]
            )

            with tab_summary:
                if not policy_items:
                    st.caption("No policy items recorded in this archive.")
                else:
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("**By type**")
                        for type_key, label_text in [
                            ("grant",        "Hive grants"),
                            ("hdfs_grant",   "HDFS grants"),
                            ("hbase_grant",  "HBase grants"),
                            ("deny",         "Deny policies"),
                            ("row_filter",   "Row filters"),
                            ("column_mask",  "Column masks"),
                        ]:
                            n = type_counts.get(type_key, 0)
                            if n:
                                st.markdown(f"- {label_text}: **{n}**")
                    with c2:
                        st.markdown("**By status**")
                        for status_key, label_text in [
                            ("approved",     "✅ Approved"),
                            ("needs_review", "⚠️ Needs review"),
                            ("pending",      "🕐 Pending"),
                            ("rejected",     "❌ Rejected"),
                        ]:
                            n = status_counts.get(status_key, 0)
                            if n:
                                st.markdown(f"- {label_text}: **{n}**")

            with tab_sql:
                if not generated_sql or not generated_sql.strip():
                    st.info(
                        "No SQL was generated in this session. "
                        "After restoring, go to **💻 Generate SQL** to create the migration script."
                    )
                else:
                    line_count = generated_sql.count("\n") + 1
                    st.caption(f"{line_count} lines")
                    st.code(generated_sql, language="sql")

            with tab_identity:
                if not identity_map:
                    st.info(
                        "No identity mappings recorded. "
                        "After restoring, go to **👥 Identity Mapping** to configure them."
                    )
                else:
                    custom = {k: v for k, v in identity_map.items() if k != v}
                    unchanged = {k: v for k, v in identity_map.items() if k == v}
                    st.caption(
                        f"{len(identity_map)} principals — "
                        f"{len(custom)} custom mappings, {len(unchanged)} unchanged"
                    )
                    if custom:
                        st.markdown("**Custom mappings**")
                        st.table(
                            {"Ranger principal": list(custom.keys()),
                             "Databricks principal": list(custom.values())}
                        )
                    if unchanged:
                        with st.expander(f"Unchanged principals ({len(unchanged)})"):
                            st.table({"Principal": list(unchanged.keys())})
