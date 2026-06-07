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

st.info(
    "**Non-translatable policies** — Deny policies, tag policies without `resourceTags`, and HBase `*` wildcard "
    "grants cannot produce executable SQL. They generate advisory comment blocks only, "
    "are excluded from the **Approve all valid** bulk action, and are not counted in the "
    "**Migration Readiness** score on the Gap Analysis page.",
    icon="ℹ️",
)

with st.expander("🔴 Deny Policies — No equivalent in Unity Catalog", expanded=True):
    st.markdown(
        """
Unity Catalog uses an **additive (allowlist) model**. There is no `DENY` statement.

**What this tool does:** emits advisory comment blocks explaining the deny; does not generate executable SQL.
Deny items cannot be bulk-approved and do not count toward the readiness score.

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

with st.expander("🟡 Column Mask Types — full coverage with review required"):
    st.markdown(
        """
All Ranger mask types are translated. The current mapping:

| Ranger type | Status | UC function body |
|---|---|---|
| MASK | ✅ Supported | `'***REDACTED***'` |
| MASK_SHOW_LAST_4 | ✅ Supported | `CONCAT('***-**-', RIGHT(val, 4))` |
| MASK_SHOW_FIRST_4 | ✅ Supported | `CONCAT(LEFT(val, 4), '***')` |
| MASK_HASH | ✅ Supported | `SHA2(val, 256)` |
| MASK_NULL | ✅ Supported | Returns `NULL` |
| MASK_NONE | ✅ Supported | `val` — no masking for that principal |
| MASK_DATE_SHOW_YEAR | ✅ Supported | `CAST(MAKE_DATE(YEAR(TRY_CAST(val AS DATE)), 1, 1) AS STRING)` |
| Custom `valueExpr` | ✅ Auto-adapted — **review before executing** | See below |

**Custom `valueExpr` auto-adaptation:**
The tool attempts two automatic fixes before using the expression:
1. `CAST('<non-numeric-literal>' AS DECIMAL/INT/…)` → `NULL` (invalid literal would fail at parse time)
2. Bare column reference matching the masked column → `val` (the function parameter)

If the expression references **other columns** (cross-column references), UC mask functions cannot resolve
them (each function only receives `val` — the current column's value). Those branches are replaced with
`'***REDACTED***'` and marked `⛔ BRANCH OMITTED` with an ACTION REQUIRED advisory. Rewrite them
manually using UC-native expressions (`IS_ACCOUNT_GROUP_MEMBER()`, `current_user()`, etc.).

**Action required:** test every generated mask function against sample data before applying to production.
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

with st.expander("🟡 Wildcard Table Policies — SELECT/MODIFY via scripted loop"):
    st.markdown(
        """
Ranger policies targeting `table: *` (all tables in a database) must be handled carefully in UC:

- **Schema-level privileges** (CREATE TABLE, DROP, ALL PRIVILEGES, USE SCHEMA, etc.) are granted directly on the schema ✅
- **`SELECT` and `MODIFY`** cannot be granted at schema level in UC — they are table-level only.
  The tool generates a `BEGIN...END FOR` loop over `information_schema.tables`:

```sql
BEGIN
  FOR tbl AS (
    SELECT table_name FROM `main`.information_schema.tables
    WHERE table_schema = 'sales'
      AND table_type IN ('BASE TABLE', 'EXTERNAL', 'MANAGED')
  ) DO
    EXECUTE IMMEDIATE 'GRANT SELECT ON TABLE `main`.`sales`.`' || tbl.table_name || '` TO `analyst_group`';
  END FOR;
END;
```

**Requirements:**
- Databricks Runtime **14.0+** or a SQL Warehouse with scripting enabled
- The principal executing this script must have USAGE on the catalog and schema

**Important limitation:**
Tables created **after** this script runs are NOT automatically covered.
Re-run the loop section or add explicit per-table grants for new tables.

**Action required:** review wildcard grants in the Review Policies page and consider replacing with
explicit per-table grants for sensitive schemas where forward-scope expansion is a concern.
        """
    )

with st.expander("🟡 ALTER Privilege — mapped to ALL PRIVILEGES"):
    st.markdown(
        """
Ranger's `alter` access type (used for DDL operations: ADD COLUMN, RENAME, etc.) has **no direct
equivalent in Unity Catalog**. UC structural changes require **object ownership**, not a specific
GRANT statement.

**What this tool does:** maps `alter` → `ALL PRIVILEGES` with an advisory comment:
```sql
-- ⚠ ALTER privilege has no direct equivalent in Unity Catalog.
-- Converted to ALL PRIVILEGES (closest available substitute for DDL access).
-- In UC, table/schema structural changes (ADD COLUMN, RENAME, etc.) require ownership.
-- Review: consider assigning object ownership instead of granting ALL PRIVILEGES.
GRANT ALL PRIVILEGES ON TABLE `main`.`hr`.`employees` TO `schema_admin_group`;
```

**Action required:** for each generated `ALL PRIVILEGES` grant that originated from an `alter` mapping,
evaluate whether granting ownership (`ALTER TABLE ... SET OWNER TO …`) is more appropriate than
granting `ALL PRIVILEGES` to a group.
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

with st.expander("🔴 isDenyAllElse — no UC equivalent"):
    st.markdown(
        """
Ranger policies with `isDenyAllElse: true` implicitly deny all access not covered by an explicit allow
in that policy. Unity Catalog's additive model has no equivalent mechanism.

**What this tool does:** detects `isDenyAllElse: true` and flags it as a critical warning in the Gap Analysis.

**What you must do manually:**
- Ensure that no other policy grants access to the resource for principals not listed in this policy
- Consider restricting the resource to a dedicated schema with tightly controlled membership
- Do not assume the UC migration will preserve the "deny everything else" behaviour automatically
        """
    )

with st.expander("🟡 validitySchedules — no time-scoped grants in UC"):
    st.markdown(
        """
Ranger supports `validitySchedules` on policies — time windows during which a policy is active
(e.g., grant access only during business hours). Unity Catalog grants are permanent; there is
no built-in time-scoping mechanism.

**What this tool does:** detects `validitySchedules` and flags them as warnings in the Gap Analysis.

**What you must do manually:**
- If time-scoped access is required, implement it via scheduled Databricks jobs that grant/revoke
  at the appropriate times
- Consider whether permanent access is acceptable for the principal in question
        """
    )

with st.expander("🟡 Policy conditions — request-context matching not supported"):
    st.markdown(
        """
Ranger `conditions[]` on policy items allow access decisions based on request-context attributes
such as IP ranges (`ip-range`), user zones, or time of day. Unity Catalog has no equivalent
request-context condition matching.

**What this tool does:** detects conditions on any policy item and flags them as warnings in the Gap Analysis.

**What you must do manually:**
- Evaluate whether the condition was a security control or an operational convenience
- For IP-based restrictions, consider Databricks network policies or private connectivity instead
- For user-zone conditions, restructure into separate groups with distinct grants
        """
    )

# ── Unsupported Services ──────────────────────────────────────────────
st.header("Supported Non-Hive Services (with Limitations)")
st.markdown(
    "Beyond Hive, this tool also translates **HDFS**, **HBase**, Hive **URL**, and Hive **UDF** policies. "
    "All have limitations you should review before executing the generated SQL."
)

with st.expander("🟡 HDFS Policies → UC External Location grants", expanded=True):
    st.markdown(
        """
HDFS path policies (`resources.path`) are translated to UC **External Location** grants:
- `read` → `GRANT READ FILES ON EXTERNAL LOCATION ...`
- `write` → `GRANT WRITE FILES ON EXTERNAL LOCATION ...`
- `execute` → treated as `READ FILES` (closest equivalent)

**External Location naming:** The tool derives the location name directly from the Ranger HDFS path
(e.g. `/data/finance` → `ext_loc_data_finance`). The same name is used in both the GRANT statements
and in `_bootstrap_prerequisites.sql` STEP 5, so no manual substitution is needed.

**Before executing:**
1. Create External Locations in UC Admin Console using the names and URL hints in `_bootstrap_prerequisites.sql` STEP 5
2. `isDenyAllElse` and `allowExceptions` in HDFS policies are not translated — review manually
        """
    )

with st.expander("🟡 Hive URL Policies → UC External Location grants"):
    st.markdown(
        """
Hive policies with a `url` resource (S3, ADLS, or GCS paths referenced directly in Hive storage
policies) are translated to UC **External Location** grants using the same access map as HDFS.

- `read` → `GRANT READ FILES ON EXTERNAL LOCATION ...`
- `write` → `GRANT WRITE FILES ON EXTERNAL LOCATION ...`
- `execute` → treated as `READ FILES`

**External Location naming:** Same convention as HDFS — location names are derived from the URL path
(e.g. `s3a://my-bucket/data/finance` → `ext_loc_s3a___my_bucket_data_finance`). Names are consistent
between the GRANT statements and `_bootstrap_prerequisites.sql` STEP 5.
        """
    )

with st.expander("🟡 Hive UDF Policies → GRANT EXECUTE ON FUNCTION"):
    st.markdown(
        """
Hive policies with a `udf` resource generate `GRANT EXECUTE ON FUNCTION` statements in UC.

**Limitation:** The tool does not verify that the UDF exists in UC. Hive UDFs must be:
1. Rewritten as Databricks Unity Catalog functions (Python or SQL UDFs)
2. Registered in the correct catalog and schema in UC
3. Tested before granting access to other principals

**Before executing:**
- Confirm every UDF name in the generated SQL is registered in UC
- Hive UDFs that use Java/JAR implementations need a full reimplementation as UC functions
- `GRANT EXECUTE ON FUNCTION` will fail with a "function not found" error if the UDF does not exist
        """
    )

with st.expander("🟡 HBase Policies → UC table/schema grants", expanded=True):
    st.markdown(
        """
HBase table policies are translated to UC table or schema grants, assuming HBase data has been
(or will be) migrated to Delta tables:
- HBase namespace (`namespace:table`) → UC `catalog.namespace.table`
- Wildcard (`namespace:*`) → schema-level grant on `catalog.namespace`
- Full wildcard (`*`) → **non-translatable** — advisory comment only; stays at Needs Review, cannot be bulk-approved, excluded from readiness score
- `read` → `SELECT`, `write` → `MODIFY`, `create` → `CREATE`, `admin` → `ALL PRIVILEGES`

**What you must do manually for `*` wildcards:**
- Identify all namespaces/schemas that the principal needs access to
- Grant each schema explicitly in UC after migration

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
- When `resourceTags` is absent: `tag_placeholder` items are emitted — advisory comment only ⚠️

**Row filters and column masks on tag policies** are resolved using the same `resourceTags` mapping.

**Limitations:**
- `tag_placeholder` items (no `resourceTags`) are **non-translatable** — they stay at Needs Review, cannot be bulk-approved, and are excluded from the readiness score. Re-export with `resourceTags` to resolve them.
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
4. **Review advisory comment blocks** — deny policies, tag placeholders, and HBase `*` wildcards generate comment-only advisories that require manual remediation before the gap can be closed.
5. **Register UDFs in UC** before executing `GRANT EXECUTE ON FUNCTION` statements — the grant will fail if the function does not exist.
6. **Create External Locations** listed in `_bootstrap_prerequisites.sql` STEP 5 — names are pre-derived from Ranger paths and match the GRANT statements exactly.
7. **Check for UDF dependencies** in row filter expressions — migrate any Hive UDFs to Databricks first.
8. **Review Gap Analysis warnings** for `isDenyAllElse`, `validitySchedules`, and `conditions` — these require manual remediation.
9. **`BEGIN...END FOR` loop sections** require Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled. These sections appear when Ranger had `table: *` (all-tables wildcard) and `SELECT` or `MODIFY` were among the privileges. Run them from a Databricks notebook or SQL Warehouse — the Databricks CLI's `sql execute` command also works.
10. **Re-run wildcard table loops** after adding new tables to a schema — the loop only grants to tables present at execution time.
11. **Review `⛔ BRANCH OMITTED` advisories** in custom column mask functions — these mark cross-column expressions that could not be auto-adapted. The branch uses `'***REDACTED***'` as a conservative fallback until you rewrite it.
12. **Apply in a dev/staging environment** first; the Deploy page provides an execution checklist.
"""
)
