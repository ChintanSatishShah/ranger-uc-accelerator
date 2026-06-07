"""Reference: Migration Mappings — how Ranger constructs translate to Unity Catalog SQL."""
from __future__ import annotations

import streamlit as st

st.markdown(
    """
    <div style="display:inline-block;padding:4px 10px;border-radius:999px;
                background:rgba(124,58,237,0.08);border:1px solid rgba(124,58,237,0.2);
                color:#7c3aed;font-size:11px;font-family:monospace;letter-spacing:1px;
                margin-bottom:12px;">
      📖 REFERENCE
    </div>
    """,
    unsafe_allow_html=True,
)
st.title("Migration Mappings")
st.caption(
    "How each Ranger policy construct maps to Unity Catalog SQL. "
    "All mappings reflect exactly what this tool generates."
)

# ── Policy Types ──────────────────────────────────────────────────────
st.header("1. Policy Types")
st.markdown(
    "Ranger exports carry a `policyType` field that controls how items are parsed:"
)
st.dataframe(
    {
        "policyType": ["0 (access)", "1 (dataMask)", "2 (rowFilter)"],
        "Ranger field used": [
            "policyItems / denyPolicyItems",
            "dataMaskPolicyItems",
            "rowFilterPolicyItems",
        ],
        "UC output": ["GRANT statement", "CREATE FUNCTION + ALTER COLUMN SET MASK", "CREATE FUNCTION + ALTER TABLE SET ROW FILTER"],
    },
    use_container_width=True,
    hide_index=True,
)

# ── Privilege Mapping ─────────────────────────────────────────────────
st.header("2. Privilege Mapping (Access Policies)")
st.markdown(
    "Ranger `accesses[].type` values are mapped via the parser's `ACCESS_MAP`. "
    "Only accesses where `isAllowed: true` are included."
)
st.dataframe(
    {
        "Ranger access type": [
            "select", "read", "update", "write",
            "create", "create", "drop", "alter", "all",
            "index", "lock", "execute",
        ],
        "Target": [
            "TABLE / SCHEMA", "TABLE / SCHEMA", "TABLE / SCHEMA", "TABLE / SCHEMA",
            "SCHEMA", "TABLE",
            "TABLE / SCHEMA", "TABLE / SCHEMA", "TABLE / SCHEMA",
            "TABLE / SCHEMA", "TABLE / SCHEMA", "FUNCTION",
        ],
        "UC privilege": [
            "SELECT", "SELECT", "MODIFY", "MODIFY",
            "CREATE TABLE", "⚠ No equivalent — advisory comment",
            "DROP", "ALL PRIVILEGES ⚠", "ALL PRIVILEGES",
            "SELECT", "SELECT", "EXECUTE",
        ],
        "Notes": [
            "", "", "", "",
            "Ranger 'create' at schema scope = ability to create tables in that schema",
            "No CREATE privilege on a UC TABLE — grant MODIFY or ALL PRIVILEGES instead",
            "", "ALTER has no UC equivalent — mapped to ALL PRIVILEGES; advisory comment recommends reviewing ownership", "",
            "Treated as read-equivalent", "Treated as read-equivalent", "",
        ],
    },
    use_container_width=True,
    hide_index=True,
)

# ── Resource Mapping ──────────────────────────────────────────────────
st.header("3. Resource Mapping")
st.markdown("Ranger `resources` fields map to UC object hierarchy:")
st.dataframe(
    {
        "Ranger resource": ["database", "table (specific)", "table = * (wildcard)", "column", "url", "udf"],
        "UC object": ["SCHEMA", "TABLE", "SCHEMA (all tables)", "column (used in masks)", "External Location", "FUNCTION"],
        "GRANT target": [
            "SCHEMA `catalog.schema`",
            "TABLE `catalog.schema.table`",
            "SCHEMA `catalog.schema` — with USE CATALOG + USE SCHEMA prepended",
            "N/A — columns appear only in mask policies",
            "VOLUME `main`.`ranger_hdfs_volumes`.`ext_loc_<path>` — derived from Ranger path",
            "FUNCTION `catalog.schema.udf_name`",
        ],
    },
    use_container_width=True,
    hide_index=True,
)
st.info(
    "When `table = *`, the tool prepends `GRANT USE CATALOG` and `GRANT USE SCHEMA` automatically. "
    "Schema-valid privileges (CREATE TABLE, DROP, ALL PRIVILEGES, etc.) are granted directly on the schema. "
    "**SELECT and MODIFY** are table-level only in UC — they are applied via a `BEGIN...END FOR` loop "
    "over all current tables in the schema (see section 3a below).",
    icon="ℹ️",
)

# ── SELECT/MODIFY on wildcard tables ─────────────────────────────────
st.header("3a. SELECT / MODIFY on `table = *` — BEGIN…END FOR Loop")
st.markdown(
    "Unity Catalog only allows `SELECT` and `MODIFY` on **TABLE** objects, not on schemas. "
    "When a Ranger policy targets `table: *` (all tables in a database), the tool generates "
    "a scripted loop instead of a direct schema-level grant:"
)
st.code(
    """-- ⚠ SELECT: table-level privilege — granted per-table via loop below.
-- Requires Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled.
-- ⚠ Tables added AFTER this script runs will NOT inherit this grant.
BEGIN
  FOR tbl AS (
    SELECT table_name FROM `main`.information_schema.tables
    WHERE table_schema = 'sales'
      AND table_type IN ('BASE TABLE', 'EXTERNAL', 'MANAGED')
  ) DO
    EXECUTE IMMEDIATE format(
      'GRANT SELECT ON TABLE `main`.`sales`.`%s` TO `analyst_group`',
      tbl.table_name
    );
  END FOR;
END;""",
    language="sql",
)
st.warning(
    "The loop grants SELECT/MODIFY to all **current** tables at execution time. "
    "Tables created afterward are NOT covered. Re-run this section after adding new tables, "
    "or issue explicit per-table grants.",
    icon="⚠️",
)
st.info(
    "The same loop pattern is used for: (1) Hive `table=*` grants, (2) schema-wildcard grants "
    "(e.g. `db=fin*`), and (3) HBase namespace `*` grants. Each uses the appropriate "
    "`information_schema.tables` filter for the scope.",
    icon="ℹ️",
)

# ── Identity / Principal Mapping ──────────────────────────────────────
st.header("4. Identity / Principal Mapping")
col1, col2 = st.columns(2)
with col1:
    st.markdown("**Ranger principal sources**")
    st.markdown(
        "- `policyItems[].groups` → group principals\n"
        "- `policyItems[].users` → user principals\n"
        "- `policyItems[].roles` → role principals\n"
        "- First principal used for function names in masks/filters\n"
        "- All principals listed in `allPrincipals` for review"
    )
with col2:
    st.markdown("**Identity Mapping page**")
    st.markdown(
        "- Map Ranger usernames/groups to Databricks identities\n"
        "- Unmapped principals pass through unchanged\n"
        "- Kerberos principals flagged automatically (contains `@`, `/`, `_svc`, `_service_account`, `svc_` prefix)\n"
        "- All mapped names are backtick-quoted in generated SQL"
    )

# ── Non-Translatable Policies ─────────────────────────────────────────
st.header("5. Non-Translatable Policies — Advisory Comments Only")
st.markdown(
    "Three policy types cannot produce any executable SQL. "
    "They emit **advisory comment blocks** describing the gap and suggesting manual steps. "
    "They are **excluded from 'Approve all valid'** and are **not counted in the readiness score**."
)
st.dataframe(
    {
        "Policy type": ["Deny (`denyPolicyItems`)", "Tag placeholder (no `resourceTags`)", "HBase wildcard `*`"],
        "Why untranslatable": [
            "UC uses an additive model — there is no DENY statement",
            "`resourceTags` absent from export — table names cannot be resolved automatically",
            "Wildcard spans all namespaces — cannot map to a specific UC catalog/schema",
        ],
        "SQL output": [
            "⛔ DENY NOT SUPPORTED comment block with remediation steps",
            "⚠ Tag placeholder comment with manual GRANT template",
            "⚠ HBase wildcard comment with manual grant instructions",
        ],
        "Included in generated SQL?": ["Yes (advisory)", "Yes (advisory)", "Yes (advisory)"],
        "Can be bulk-approved?": ["No", "No", "No"],
    },
    use_container_width=True,
    hide_index=True,
)
st.info(
    "These items remain at **Needs Review** status by default. "
    "They appear in the generated SQL as comment blocks so you have a record of the gap. "
    "The Gap Analysis readiness score and the 'Approved' count on the Review page "
    "exclude all three types.",
    icon="ℹ️",
)

st.markdown("---")
st.subheader("5a. Deny Policies")
st.markdown(
    "`denyPolicyItems` in Ranger have no direct equivalent in Unity Catalog. "
    "This tool emits SQL comment blocks instead of executable statements."
)
st.code(
    """-- ⛔ DENY NOT SUPPORTED IN UNITY CATALOG
-- Original Ranger deny: SELECT on sales.orders for analyst_group
--
-- RECOMMENDED ACTIONS:
-- 1. Remove analyst_group from the group that grants broad access
-- 2. Create a restricted schema and grant only specific tables
-- 3. Use row filters / column masks for fine-grained control
-- 4. If this was a safety-net deny, the UC additive model makes it
--    unnecessary as long as you don't grant the denied privileges
--    in the first place""",
    language="sql",
)

# ── Delegate Admin ─────────────────────────────────────────────────────
st.header("6. Delegate Admin")
st.markdown(
    "Ranger `delegateAdmin: true` lets a principal manage policies on their resources. "
    "This tool appends a comment suggesting `MANAGE` privilege:"
)
st.code(
    """GRANT SELECT ON TABLE main.sales.orders TO `analyst@company.com`;
-- Note: delegateAdmin=true in Ranger.
-- Consider granting MANAGE on TABLE main.sales.orders if admin delegation is needed.""",
    language="sql",
)
st.warning(
    "MANAGE is not the same as delegateAdmin — review each case before granting it.",
    icon="⚠️",
)

# ── Column Masking ─────────────────────────────────────────────────────
st.header("7. Column Mask Translation")
st.markdown(
    "Each `dataMaskPolicyItems` entry generates a `CREATE OR REPLACE FUNCTION` "
    "and an `ALTER COLUMN SET MASK` statement. The function uses `IS_ACCOUNT_GROUP_MEMBER` "
    "to apply masking only to the matching principal."
)
st.dataframe(
    {
        "Ranger mask type": [
            "MASK", "MASK_SHOW_LAST_4", "MASK_SHOW_FIRST_4",
            "MASK_HASH", "MASK_NONE", "MASK_DATE_SHOW_YEAR", "MASK_NULL",
            "Custom (valueExpr)",
        ],
        "Internal alias": [
            "REDACT", "LAST_4", "FIRST_4", "HASH", "NONE", "DATE_YEAR", "NULLIFY",
            "CUSTOM",
        ],
        "UC function body": [
            "'***REDACTED***'",
            "CONCAT('***-**-', RIGHT(val, 4))",
            "CONCAT(LEFT(val, 4), '***')",
            "SHA2(val, 256)",
            "val (MASK_NONE: no masking for this principal)",
            "CAST(MAKE_DATE(YEAR(TRY_CAST(val AS DATE)), 1, 1) AS STRING)",
            "NULL",
            "Auto-adapted (see 7a below)",
        ],
    },
    use_container_width=True,
    hide_index=True,
)

st.markdown("**Example output — LAST_4 mask:**")
st.code(
    """CREATE OR REPLACE FUNCTION main.hr.mask_employees_ssn_analyst(val STRING)
RETURNS STRING
RETURN IF(
  IS_ACCOUNT_GROUP_MEMBER('analyst'),
  CONCAT('***-**-', RIGHT(val, 4)),
  val
);

ALTER TABLE main.hr.employees
ALTER COLUMN ssn SET MASK main.hr.mask_employees_ssn_analyst;""",
    language="sql",
)

# ── Custom valueExpr auto-adaptation ─────────────────────────────────
st.header("7a. Custom `valueExpr` — Auto-Adaptation")
st.markdown(
    "When a Ranger column mask uses `MASK_TYPE = CUSTOM` with a `valueExpr`, the tool attempts "
    "two mechanical fixes to make the expression valid in UC before using it verbatim:"
)
st.dataframe(
    {
        "Problem pattern": [
            "CAST('<non-numeric>' AS DECIMAL/INT/DOUBLE/…)",
            "Bare column reference matching the masked column",
            "Bare column reference to a DIFFERENT column (cross-column)",
        ],
        "Auto-fix": [
            "→ NULL  (literal cannot be cast; would fail at parse time)",
            "→ val  (the mask function's parameter name for the current column)",
            "No fix possible — UC mask functions cannot access other columns",
        ],
        "Result": [
            "✅ Expression made valid",
            "✅ Expression made valid",
            "⛔ Branch replaced with '***REDACTED***' + ACTION REQUIRED advisory",
        ],
    },
    use_container_width=True,
    hide_index=True,
)
st.markdown("**Example — masked column IS `transaction_amount`:**")
st.code(
    """-- Original Ranger valueExpr:
-- CASE WHEN transaction_amount < 1000 THEN transaction_amount ELSE CAST('XXXXX' AS DECIMAL) END

-- ⚠ Auto-adapted: CAST('XXXXX' AS DECIMAL) → NULL; `transaction_amount` → `val`
-- Original: CASE WHEN transaction_amount < 1000 THEN transaction_amount ELSE CAST('XXXXX' AS DECIMAL) END
WHEN IS_ACCOUNT_GROUP_MEMBER('junior_analysts') THEN CASE WHEN val < 1000 THEN val ELSE NULL END""",
    language="sql",
)
st.markdown("**Example — masked column is `account_number` (cross-column reference):**")
st.code(
    """-- ⛔ BRANCH OMITTED — custom expression has cross-column references (principal: junior_analysts)
--   Original Ranger expression: CASE WHEN transaction_amount < 1000 THEN ...
--   Issue: Cross-column reference(s): transaction_amount. UC mask functions can only access 'val'.
--   ACTION REQUIRED: Replace the WHEN branch below with a valid UC expression.
-- WHEN IS_ACCOUNT_GROUP_MEMBER('junior_analysts') THEN <rewrite this expression manually>
WHEN IS_ACCOUNT_GROUP_MEMBER('junior_analysts') THEN '***REDACTED***'  -- conservative fallback""",
    language="sql",
)
st.warning(
    "Always review auto-adapted expressions before executing. "
    "Branches with cross-column references use `'***REDACTED***'` as a conservative fallback — "
    "they will mask the column for that principal until you manually rewrite the branch.",
    icon="⚠️",
)

# ── Row Filter ────────────────────────────────────────────────────────
st.header("8. Row Filter Translation")
st.markdown(
    "Each `rowFilterPolicyItems` entry generates a `CREATE OR REPLACE FUNCTION` "
    "returning `BOOLEAN` and an `ALTER TABLE SET ROW FILTER` statement. "
    "The Ranger `filterExpr` is embedded directly into the function body — "
    "review it carefully before executing."
)
st.code(
    """-- Row Filter for: west_manager@company.com
-- Original expression: region = 'WEST'

CREATE OR REPLACE FUNCTION main.sales.rf_orders_west_manager_company_com()
RETURNS BOOLEAN
RETURN IF(
  IS_ACCOUNT_GROUP_MEMBER('west_manager@company.com'),
  region = 'WEST',
  TRUE  -- Allow all for non-matching groups (adjust as needed)
);

ALTER TABLE main.sales.orders
SET ROW FILTER main.sales.rf_orders_west_manager_company_com ON ();""",
    language="sql",
)
st.info(
    "The function name is derived from `catalog.schema.rf_<table>_<principal>`. "
    "Non-alphanumeric characters in principal names are replaced with `_`.",
    icon="ℹ️",
)

# ── Grant with USE ─────────────────────────────────────────────────────
st.header("9. Tag-Based Policy Translation")
st.markdown(
    "Tag policies use `resources.tag` instead of `resources.database/table`. "
    "The tool handles them in two parts:"
)
col_a, col_b = st.columns(2)
with col_a:
    st.markdown("**Part 1 — SET TAGS (from `resourceTags`)**")
    st.markdown(
        "The top-level `resourceTags` field maps resource paths to tag names. "
        "Each entry becomes an `ALTER TABLE SET TAGS` or `ALTER TABLE ALTER COLUMN SET TAGS` statement. "
        "Tag attributes from `tagDefinitions.attributeDefs` are included as additional tag pairs."
    )
    st.code(
        """-- Column-level (schema.table.column):
ALTER TABLE main.sales.customers
  ALTER COLUMN ssn SET TAGS (
    'PII' = 'true', 'level' = 'high', 'category' = 'sensitive'
  );

-- Table-level (schema.table):
ALTER TABLE main.finance.transactions
  SET TAGS ('CONFIDENTIAL' = 'true', 'retention_years' = '7');""",
        language="sql",
    )
with col_b:
    st.markdown("**Part 2 — Tag-based grants (from policy `policyItems`)**")
    st.markdown(
        "Each `policyItems` entry in a tag policy resolves to GRANT statements "
        "on the specific tables that carry those tags (via `resourceTags`). "
        "If `resourceTags` is absent, a placeholder comment is emitted."
    )
    st.code(
        """-- Tag-based grant (tags: PII)
GRANT SELECT ON TABLE main.sales.customers
  TO `data_protection_team`;

-- When resourceTags is missing:
-- ⚠ Tag-based policy — tags: PII
-- GRANT SELECT ON TABLE main.<schema>.<table_with_PII>
--   TO `data_protection_team`;""",
        language="sql",
    )

st.info(
    "Row filters and column masks on tag policies are also resolved to the tagged tables "
    "and generate the same `CREATE FUNCTION` + `ALTER TABLE SET ROW FILTER / SET MASK` SQL as Hive policies.",
    icon="ℹ️",
)
st.dataframe(
    {
        "resourceTags present?": ["Yes", "Yes (tag not in map)", "No"],
        "policyItems output": [
            "tag_grant — GRANT on resolved tables (executable SQL)",
            "tag_placeholder — advisory comment only (cannot bulk-approve)",
            "tag_placeholder — advisory comment only (cannot bulk-approve)",
        ],
        "resourceTags output": [
            "tag_set — ALTER TABLE SET TAGS per resource",
            "tag_set — ALTER TABLE SET TAGS per resource",
            "Nothing (no data)",
        ],
    },
    use_container_width=True,
    hide_index=True,
)
st.warning(
    "`tag_placeholder` items are non-translatable. They stay at **Needs Review** and "
    "cannot be bulk-approved. Re-export the Ranger archive with `resourceTags` included "
    "to resolve them to executable GRANT statements.",
    icon="⚠️",
)

st.header("10. ACL Provider Test Format")
st.markdown(
    "Ranger ships with policy engine and ACL provider test files under "
    "`agents-common/src/test/resources/policyengine/`. These use a `testCases` wrapper:"
)
st.code(
    """{
  "testCases": [{
    "name": "...",
    "servicePolicies": {
      "serviceName": "hivedev",
      "policies": [ ... ],
      "tagPolicies": { ... }
    }
  }]
}""",
    language="json",
)
st.info(
    "This tool automatically unwraps the `testCases[0].servicePolicies` structure, so these files "
    "can be loaded and parsed exactly like a standard Ranger export. "
    "Only the first `testCases` entry is used.",
    icon="ℹ️",
)

st.header("11. HDFS Policy Mapping")
st.markdown(
    "HDFS policies (`serviceName` containing `hdfs`) are detected automatically. "
    "The `path` resource maps to a UC **External Location** grant."
)
st.dataframe(
    {
        "Ranger HDFS access": ["read", "write", "execute", "all"],
        "UC privilege": ["READ FILES", "WRITE FILES", "READ FILES", "ALL PRIVILEGES"],
        "Notes": ["", "", "Closest equivalent — no execute concept in UC", ""],
    },
    use_container_width=True,
    hide_index=True,
)
st.markdown("**Example output:**")
st.code(
    """-- HDFS path: /data/finance/ (recursive)
-- ⚠ Ensure External Volume `main`.`ranger_hdfs_volumes`.`ext_loc_data_finance` exists before executing
--   (see _bootstrap_prerequisites.sql — STEP 5).
GRANT READ VOLUME ON VOLUME `main`.`ranger_hdfs_volumes`.`ext_loc_data_finance` TO `analyst_group`;""",
    language="sql",
)

st.header("12. HBase Policy Mapping")
st.markdown(
    "HBase policies (`serviceName` containing `hbase`) map to UC table/schema grants, "
    "assuming HBase data has been migrated to Delta tables. "
    "HBase namespaces map to UC schemas; `namespace:table` notation is parsed automatically."
)
st.dataframe(
    {
        "Ranger HBase access": ["read", "write", "create", "admin", "all"],
        "UC privilege": ["SELECT", "MODIFY", "CREATE", "ALL PRIVILEGES", "ALL PRIVILEGES"],
    },
    use_container_width=True,
    hide_index=True,
)
st.dataframe(
    {
        "HBase resource pattern": ["table (no namespace)", "namespace:table", "namespace:*", "*"],
        "UC object": [
            "TABLE catalog.default.table",
            "TABLE catalog.namespace.table",
            "SCHEMA catalog.namespace",
            "Non-translatable — advisory comment only (cannot bulk-approve)",
        ],
        "Status": ["pending → approved", "pending → approved", "pending → approved", "needs_review (advisory)"],
    },
    use_container_width=True,
    hide_index=True,
)
st.warning(
    "The HBase `*` wildcard (all namespaces) is non-translatable. "
    "It generates a `⚠ HBase wildcard` advisory comment and stays at **Needs Review**. "
    "Grant specific schemas manually after migration.",
    icon="⚠️",
)
st.info(
    "Column families (`column-family` resource) have no UC equivalent. "
    "The tool notes them in a comment and generates a table-level grant.",
    icon="ℹ️",
)
st.markdown("**Example output:**")
st.code(
    """-- HBase column-families (restricted*) have no direct UC equivalent — table-level grant applied.
GRANT SELECT ON TABLE main.default.finance TO `finance`;
GRANT MODIFY ON TABLE main.default.finance TO `finance`;

-- Namespace wildcard example:
GRANT USE CATALOG ON CATALOG main TO `user1`;
GRANT USE SCHEMA ON SCHEMA main.namespace_1 TO `user1`;
GRANT ALL PRIVILEGES ON SCHEMA main.namespace_1 TO `user1`;""",
    language="sql",
)

st.header("13. Schema-Level Grant Pattern")
st.markdown(
    "When a Ranger policy targets a database without a specific table (wildcard or schema-only), "
    "the tool prepends `USE CATALOG` and `USE SCHEMA` grants so the principal can navigate the hierarchy:"
)
st.code(
    """GRANT USE CATALOG ON CATALOG main TO `analyst_group`;
GRANT USE SCHEMA ON SCHEMA main.sales TO `analyst_group`;
GRANT SELECT ON SCHEMA main.sales TO `analyst_group`;""",
    language="sql",
)

st.header("14. URL Resource → External Location Grant")
st.markdown(
    "Hive policies with a `url` resource (S3, ADLS, or GCS paths referenced directly in Hive) "
    "are translated to UC **External Location** grants using the same access map as HDFS:"
)
st.dataframe(
    {
        "Ranger URL access": ["read", "write", "execute", "all"],
        "UC privilege": ["READ FILES", "WRITE FILES", "READ FILES", "ALL PRIVILEGES"],
        "Notes": ["", "", "Closest equivalent — no execute concept in UC", ""],
    },
    use_container_width=True,
    hide_index=True,
)
st.markdown("**Example output:**")
st.code(
    """-- HDFS path: s3a://my-bucket/data/finance/ (recursive)
-- ⚠ Ensure External Volume `main`.`ranger_hdfs_volumes`.`ext_loc_s3a___my_bucket_data_finance` exists before executing
--   (see _bootstrap_prerequisites.sql — STEP 5).
GRANT READ VOLUME ON VOLUME `main`.`ranger_hdfs_volumes`.`ext_loc_s3a___my_bucket_data_finance` TO `analyst_group`;""",
    language="sql",
)
st.info(
    "URL policies reuse the `hdfs_grant` internal type and produce identical SQL to HDFS path policies. "
    "Volume names are derived from the Ranger path and match the bootstrap prerequisites exactly.",
    icon="ℹ️",
)

st.header("15. UDF Resource → GRANT EXECUTE ON FUNCTION")
st.markdown(
    "Hive policies with a `udf` resource generate `GRANT EXECUTE ON FUNCTION` statements. "
    "The `database` resource (if present) maps to the UC schema."
)
st.code(
    """-- ⚠ Ensure function main.hr.udf is registered in UC before granting.
GRANT EXECUTE ON FUNCTION `main`.`hr`.`udf` TO `analyst_group`;
-- Note: delegateAdmin=true. Consider granting MANAGE on FUNCTION main.hr.udf.""",
    language="sql",
)
st.warning(
    "UDF names are taken verbatim from the Ranger export. "
    "Verify each function is registered in UC (or migrated from Hive) before executing.",
    icon="⚠️",
)

st.header("16. Gap Analysis Warning Categories")
st.markdown(
    "The parser detects several Ranger-specific constructs that have no direct UC equivalent "
    "and surfaces them in the Gap Analysis page as warnings:"
)
st.dataframe(
    {
        "Warning category": ["deny_all_else", "validity_schedule", "conditions"],
        "Ranger source": [
            "`isDenyAllElse: true` on a policy",
            "`validitySchedules[]` on a policy",
            "`conditions[]` on any policyItems entry",
        ],
        "Severity": ["Critical", "Warning", "Warning"],
        "Notes": [
            "Policy denies all access not explicitly allowed — UC additive model has no equivalent; restructure access",
            "Time-scoped grants not supported in UC — grants are permanent; implement via scheduled jobs if needed",
            "Request-context conditions (IP range, user zone) not supported in UC",
        ],
    },
    use_container_width=True,
    hide_index=True,
)
