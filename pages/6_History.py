"""Session Archive — save, preview, and restore migration sessions."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import streamlit as st

_INPUT_DIR = Path(__file__).parent.parent / "data" / "input"

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
                source = st.session_state.get("_last_source_file", "")
                filename = save_current_session(notes=notes, source_file=source)
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
    with st.expander("ℹ️ How to replay a session", expanded=False):
        st.markdown(
            """
**Replaying restores your full session state** — the original Ranger export, all
approve / reject decisions, identity mappings, and the generated SQL.

1. Find the session below and click **🔄 Restore Session**.
2. The sidebar summary updates to confirm the restore.
3. Navigate to any step using the left sidebar to continue or review.
4. Archive again at any point to save a new checkpoint.
            """
        )

    def _badge(text: str, bg: str, fg: str) -> str:
        return (
            f'<span style="background:{bg};color:{fg};padding:2px 10px;'
            f'border-radius:999px;font-size:12px;font-weight:500;'
            f'margin-right:4px;display:inline-block;">{text}</span>'
        )

    TYPE_LABELS = {
        "grant": "Hive grants", "deny": "Deny policies",
        "row_filter": "Row filters", "column_mask": "Column masks",
        "tag_set": "Tag SET TAGS", "tag_grant": "Tag grants",
        "tag_placeholder": "Tag (no map)",
        "hdfs_grant": "HDFS grants", "hbase_grant": "HBase grants",
    }

    for i, archive in enumerate(archives):
        meta = archive["metadata"]
        timestamp = meta.get("timestamp", "unknown")
        service = meta.get("service_name", "Unknown")
        catalog = meta.get("catalog_name", "main")
        notes_text = meta.get("notes", "")
        source_file = meta.get("source_file", "")
        policy_items = archive["policy_items"]
        identity_map = archive["identity_map"]
        generated_sql = archive["generated_sql"]
        parsed_data = archive.get("parsed_data") or {}

        type_counts = Counter(p.get("type") for p in policy_items)
        status_counts = Counter(p.get("status") for p in policy_items)
        total = len(policy_items)

        source_name = re.sub(r"_\d{8}_\d{6}$", "", archive["filename"].removesuffix(".json"))
        expander_label = f"📦  {source_name}  ·  {timestamp[:10]}  ·  {total} items  ·  {service}"
        if notes_text:
            expander_label += f'  —  "{notes_text}"'

        with st.expander(expander_label):

            # ── Metadata badges + action buttons ─────────────────────────
            badge_col, btn_col = st.columns([3, 1])
            with badge_col:
                badges = (
                    _badge(timestamp[:10], "#dbeafe", "#1e40af")
                    + _badge(f"{total} items", "#dcfce7", "#166534")
                    + _badge(f"{archive['size_kb']:.1f} KB", "#fef3c7", "#92400e")
                    + _badge(service, "#ede9fe", "#5b21b6")
                )
                st.markdown(badges, unsafe_allow_html=True)
                st.caption(f"📁 {archive['filename']}"
                           + (f"  ·  source: {source_file}" if source_file and source_file != source_name else ""))

            with btn_col:
                if st.button("🔄 Restore Session", key=f"load_{i}", use_container_width=True, type="primary"):
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
                        file_name=f"{source_name}.zip",
                        mime="application/zip",
                        key=f"dl_{i}",
                        use_container_width=True,
                    )
                except Exception:
                    pass
                if st.button("🗑️ Delete", key=f"del_{i}", use_container_width=True):
                    delete_archive(archive["filename"])
                    st.rerun()

            st.divider()

            # ── Side-by-side: INPUT (left) | OUTPUT (right) ───────────────
            left, right = st.columns([4, 6])

            # ─ LEFT: Input attributes ────────────────────────────────────
            with left:
                st.markdown("#### 📂 Input")

                # Service metadata
                svc_type = parsed_data.get("serviceType") or "hive"
                cluster = parsed_data.get("clusterName") or meta.get("cluster_name", "unknown")
                total_ranger = parsed_data.get("totalRangerPolicies", "—")
                st.markdown(
                    f"**Service:** `{service}`  \n"
                    f"**Type:** `{svc_type}`  \n"
                    f"**Cluster:** `{cluster}`  \n"
                    f"**Catalog:** `{catalog}`  \n"
                    f"**Ranger Policies:** {total_ranger}"
                )

                # Policy type breakdown
                if policy_items:
                    st.markdown("**Items by type:**")
                    for type_key, label_text in TYPE_LABELS.items():
                        n = type_counts.get(type_key, 0)
                        if n:
                            st.markdown(f"- {label_text}: **{n}**")

                # Schemas
                schemas = sorted({p.get("schema") for p in policy_items if p.get("schema")})
                if schemas:
                    st.markdown(f"**Schemas ({len(schemas)}):**")
                    st.caption(", ".join(f"`{s}`" for s in schemas[:15])
                               + (" …" if len(schemas) > 15 else ""))

                # Principals
                principals = sorted({
                    (p.get("principal") or {}).get("name", "")
                    for p in policy_items
                    if (p.get("principal") or {}).get("name")
                })
                if principals:
                    st.markdown(f"**Principals ({len(principals)}):**")
                    st.caption(", ".join(f"`{p}`" for p in principals[:10])
                               + (" …" if len(principals) > 10 else ""))

                # Warnings / kerberos
                kerberos = parsed_data.get("kerberosIssues") or []
                if kerberos:
                    st.warning(f"{len(kerberos)} Kerberos / service-account principal(s) detected", icon="⚠️")

                # Load and display the original input JSON from data/input/
                with st.expander("📄 View input JSON"):
                    src = meta.get("source_file", "")
                    input_path = _INPUT_DIR / src if src else None
                    if input_path and input_path.exists():
                        try:
                            raw = json.loads(input_path.read_text())
                            st.json(raw, expanded=False)
                        except Exception:
                            st.caption(f"Could not load `{src}`")
                    else:
                        st.caption("Source file not found in `data/input/`.")

            # ─ RIGHT: Output attributes ───────────────────────────────────
            with right:
                st.markdown("#### 🎯 Output")

                # Status breakdown
                if policy_items:
                    status_display = []
                    for sk, sl in [("approved","✅ Approved"), ("needs_review","⚠️ Needs review"),
                                   ("pending","🕐 Pending"), ("rejected","❌ Skipped")]:
                        n = status_counts.get(sk, 0)
                        if n:
                            status_display.append(f"{sl}: **{n}**")
                    if status_display:
                        st.markdown("  ·  ".join(status_display))

                # Identity map
                if identity_map:
                    custom = {k: v for k, v in identity_map.items() if k != v}
                    unchanged = len(identity_map) - len(custom)
                    st.markdown(
                        f"**Identity Map:** {len(identity_map)} principals — "
                        f"{len(custom)} remapped, {unchanged} unchanged"
                    )
                    if custom:
                        with st.expander(f"Custom mappings ({len(custom)})"):
                            st.table({
                                "Ranger principal": list(custom.keys()),
                                "Databricks principal": list(custom.values()),
                            })
                else:
                    st.caption("No identity mappings recorded.")

                # Generated SQL
                st.markdown("**💻 Generated SQL:**")
                if not generated_sql or not generated_sql.strip():
                    st.info(
                        "No SQL was generated in this session. "
                        "Restore and go to **Generate SQL** to create the migration script."
                    )
                else:
                    line_count = generated_sql.count("\n") + 1
                    st.caption(f"{line_count} lines")
                    st.code(generated_sql, language="sql")
