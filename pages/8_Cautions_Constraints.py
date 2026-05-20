"""Reference: Cautions, Constraints & Unsupported Services."""
from __future__ import annotations

import streamlit as st

st.markdown(
    """
    <div style="display:inline-block;padding:4px 10px;border-radius:999px;
                background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.2);
                color:#dc2626;font-size:11px;font-family:monospace;letter-spacing:1px;
                margin-bottom:12px;">
      ⚠ CAUTIONS & CONSTRAINTS
    </div>
    """,
    unsafe_allow_html=True,
)
st.title("Cautions, Constraints & Unsupported Services")
st.caption(
    "Read this page before executing generated SQL in your Databricks environment. "
    "Items marked 🔴 require manual intervention; 🟡 require review."
)

# ── Supported input formats ───────────────────────────────────────────
st.header("Supported Input Formats")
st.markdown(
    "The tool accepts two Ranger JSON structures:"
)
st.dataframe(
    {
        "Format": ["Standard Ranger export", "ACL provider / policy engine test file"],
        "Top-level key": ["`serviceName` + `policies`", "`testCases[].servicePolicies`"],
        "How to obtain": [
            "Ranger Admin UI → Export or `curl .../exportJson?serviceName=...`",
            "Apache Ranger source: `agents-common/src/test/resources/policyengine/test_*.json`",
        ],
        "Notes": [
            "Primary format for production migrations",
            "Wrapper unwrapped automatically; only first testCase is used",
        ],
    },
    use_container_width=True,
    hide_index=True,
)

# ── Critical gaps ─────────────────────────────────────────────────────
st.header("Critical Gaps")

with st.expander("🔴 Deny Policies — No equivalent in Unity Catalog", expanded=True):
    st.markdown(
        """
Unity Catalog uses an **additive (allowlist) model**. There is no `DENY` statement.

**What this tool does:** emits comment-only blocks explaining the deny; does not generate executable SQL.

**What you must do manually:**
- Restructure data into separate schemas where the principal should not have access
- Remove the principal from over-privileged groups
- Use row filters or column masks as fine-grained alternatives
- If the deny was a safety net, ensure the broad grant that triggered it is never issued in UC

The Gap Analysis page lists all deny policies found in your export.
        """
    )

with st.expander("🔴 Kerberos Principals and Service Accounts", expanded=True):
    st.markdown(
        """
Ranger stores Kerberos principals (`user@REALM.COM`, `svc/host@REALM.COM`) and service accounts
(`svc_spark`, `hive_svc`) directly as policy subjects. These do not exist in Databricks.

**What this tool does:** detects these automatically (by `@`, `/`, `_svc`, `svc_` prefix, `_service_account` suffix)
and flags them in the Gap Analysis.

**What you must do manually:**
- Create a Databricks **service principal** for each service account
- Configure **OAuth M2M** token authentication instead of Kerberos keytabs
- Sync human users via **SCIM** from your IdP (Okta, Azure AD, etc.), removing the realm suffix
- Use the Identity Mapping page to define the old → new principal mapping before generating SQL
        """
    )

# ── Functional Limitations ────────────────────────────────────────────
st.header("Functional Limitations")

with st.expander("🟡 Row Filter Expressions — manual review required"):
    st.markdown(
        """
Ranger row filter expressions (`filterExpr`) are copied verbatim into the generated UC function body.
This works when:
- The expression uses standard SQL comparisons (`region = 'WEST'`, `dept_id IN (1,2,3)`)
- Column names are the same in the migrated table

**This does not work when:**
- The expression calls Ranger/Hive UDFs that do not exist in Databricks
- Column names changed during migration
- The expression references `req.user`, `req.groups`, or other Ranger request-context attributes
  (Unity Catalog uses `current_user()` and `IS_ACCOUNT_GROUP_MEMBER()` instead)
- The expression contains Hive-specific syntax (`UNIX_TIMESTAMP`, `DECODE`, etc.)

**Action required:** test every generated row filter function against a sample query before applying.
        """
    )

with st.expander("🟡 Column Mask Types — partial coverage"):
    st.markdown(
        """
Not all Ranger mask types have a direct UC equivalent. The current mapping:

| Ranger type | Status | Notes |
|---|---|---|
| MASK | ✅ Supported | Full redact → `'***REDACTED***'` |
| MASK_SHOW_LAST_4 | ✅ Supported | `CONCAT('***-**-', RIGHT(val, 4))` |
| MASK_HASH | ✅ Supported | `SHA2(val, 256)` |
| MASK_NULL | ✅ Supported | Returns `NULL` |
| MASK_NONE | ✅ Supported | Comment only — no masking applied |
| MASK_SHOW_FIRST_4 | ⚠ Falls back to REDACT | Implement manually if needed |
| MASK_DATE_SHOW_YEAR | ⚠ Falls back to REDACT | Use `MAKE_DATE(YEAR(val), 1, 1)` as custom expr |

Custom mask expressions (`valueExpr` in the export) are not yet handled — they fall back to full redaction.
        """
    )

with st.expander("🟡 delegateAdmin — no direct equivalent"):
    st.markdown(
        """
Ranger `delegateAdmin: true` lets a principal manage access policies for the resources they own.
Unity Catalog does not have a delegated-admin concept at the policy level.

**What this tool does:** appends a SQL comment suggesting `GRANT MANAGE` as the closest equivalent.

**Considerations:**
- `MANAGE` on a table allows the grantee to grant/revoke on that table — similar but not identical
- For broader admin delegation, consider assigning the principal as a catalog or schema owner
- Do not blindly grant `MANAGE` — review each delegateAdmin case individually
        """
    )

with st.expander("🟡 Wildcard Table Policies — scope expansion"):
    st.markdown(
        """
Ranger policies targeting `table: *` (all tables in a database) translate to **schema-level grants**
in Unity Catalog. This means:
- The grant applies to **all current and future tables** in the schema, not just tables that existed at migration time
- Ranger wildcard grants were historically scoped to existing tables; UC schema grants are forward-looking

**Action required:** review wildcard grants in the Review Policies page and consider replacing with
explicit per-table grants for sensitive schemas.
        """
    )

with st.expander("🟡 Disabled Policies — skipped silently"):
    st.markdown(
        """
Policies with `isEnabled: false` in the Ranger export are parsed and displayed, but are given
`status: pending` and will not appear in the generated SQL unless manually approved in the
Review Policies page.

Review disabled policies before migration — some may have been disabled temporarily and should
be re-enabled, while others may be obsolete and should be excluded entirely.
        """
    )

# ── Unsupported Services ──────────────────────────────────────────────
st.header("Supported Non-Hive Services (with Limitations)")
st.markdown(
    "Beyond Hive, this tool also translates **HDFS** and **HBase** policies. "
    "Both have limitations you should review before executing the generated SQL."
)

with st.expander("🟡 HDFS Policies → UC External Location grants", expanded=True):
    st.markdown(
        """
HDFS path policies (`resources.path`) are translated to UC **External Location** grants:
- `read` → `GRANT READ FILES ON EXTERNAL LOCATION ...`
- `write` → `GRANT WRITE FILES ON EXTERNAL LOCATION ...`
- `execute` → treated as `READ FILES` (closest equivalent)

**Limitation:** The tool does not know your External Location names — it generates a placeholder
`<ext_loc_<path>>` that you must replace with the actual name.

**Before executing:**
1. Create External Locations in UC Admin Console for all HDFS paths in the export
2. Replace each `<ext_loc_...>` placeholder in the generated SQL with the real location name
3. `isDenyAllElse` and `allowExceptions` in HDFS policies are not translated — review manually
        """
    )

with st.expander("🟡 HBase Policies → UC table/schema grants", expanded=True):
    st.markdown(
        """
HBase table policies are translated to UC table or schema grants, assuming HBase data has been
(or will be) migrated to Delta tables:
- HBase namespace (`namespace:table`) → UC `catalog.namespace.table`
- Wildcard (`namespace:*`) → schema-level grant on `catalog.namespace`
- Full wildcard (`*`) → cannot be translated automatically (emits a comment)
- `read` → `SELECT`, `write` → `MODIFY`, `create` → `CREATE`, `admin` → `ALL PRIVILEGES`

**Limitation:** HBase **column families** have no direct UC equivalent. The tool notes them in a
SQL comment and falls back to a table-level grant. If column-family isolation is critical,
consider restructuring into separate Delta tables per family.
        """
    )

st.header("Unsupported / Out-of-Scope Services")
st.markdown(
    "The following Ranger service types produce no meaningful UC SQL and are out of scope:"
)
st.dataframe(
    {
        "Ranger service": ["Kafka", "YARN", "Storm", "Knox"],
        "Why not supported": [
            "Kafka ACLs are managed outside UC",
            "YARN resource queues have no UC equivalent",
            "Storm topologies have no UC equivalent",
            "Knox gateway policies have no UC equivalent",
        ],
        "Path forward": [
            "Use Kafka-native ACLs or Lakehouse Federation",
            "Out of scope for this tool",
            "Out of scope for this tool",
            "Out of scope for this tool",
        ],
    },
    use_container_width=True,
    hide_index=True,
)
st.info(
    "**Atlas tag-based policies** are supported with limitations — see the "
    "Tag-Based Policies section below for details.",
    icon="ℹ️",
)

# ── Tag-Based Policies ────────────────────────────────────────────────
st.header("Tag-Based Policies — Supported with Limitations")
st.markdown(
    """
Tag-based policies are translated in two parts:

**Part 1 — `ALTER TABLE SET TAGS`** (always generated when `resourceTags` is present):
- Each resource path in `resourceTags` generates a `SET TAGS` or `ALTER COLUMN SET TAGS` statement
- Tag attributes from `tagDefinitions.attributeDefs` are included as additional tag key-value pairs
- This part works fully when `resourceTags` is included in the export

**Part 2 — GRANT statements** (tag access policies):
- When `resourceTags` is present: grants are resolved to the specific tagged tables/columns ✅
- When `resourceTags` is absent: placeholder comment emitted — table names unknown ⚠️

**Row filters and column masks on tag policies** are resolved using the same `resourceTags` mapping.

**Limitations:**
- `allowExceptions` on tag policies are not translated
- Request-context conditions (`ip-range`, `user-zone`) in tag policy `conditions[]` are noted in a comment but not translated — UC has no equivalent condition matching
- Atlas-native tag inheritance (child resources inheriting parent tags) is not resolved — only explicit `resourceTags` entries are used
- If your Ranger admin did not export `resourceTags`, add it manually or re-export using Atlas REST API
"""
)

# ── SQL Execution Reminders ───────────────────────────────────────────
st.header("Before Executing Generated SQL")
st.markdown(
    """
1. **Schemas and catalogs must exist** — the generated script does not create them.
2. **Test row filters and masks** against sample queries before applying to production tables.
3. **Verify principal names** exist in your Databricks account (SCIM sync complete, service principals created).
4. **Review deny comment blocks** — these require architectural decisions before the gap can be closed.
5. **Check for UDF dependencies** in row filter expressions — migrate any Hive UDFs to Databricks first.
6. **Apply in a dev/staging environment** first; the Deploy page provides an execution checklist.
"""
)
