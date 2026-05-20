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
            "create", "drop", "alter", "all",
            "index", "lock", "execute",
        ],
        "UC privilege": [
            "SELECT", "SELECT", "MODIFY", "MODIFY",
            "CREATE", "DROP", "ALTER", "ALL PRIVILEGES",
            "SELECT", "SELECT", "EXECUTE",
        ],
        "Notes": [
            "", "", "", "",
            "Applies to schemas/tables",
            "⚠ UC supports DROP — see Cautions page",
            "", "",
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
        "Ranger resource": ["database", "table (specific)", "table = * (wildcard)", "column"],
        "UC object": ["SCHEMA", "TABLE", "SCHEMA (all tables)", "column (used in masks)"],
        "GRANT target": [
            "SCHEMA `catalog.schema`",
            "TABLE `catalog.schema.table`",
            "SCHEMA `catalog.schema` — with USE CATALOG + USE SCHEMA prepended",
            "N/A — columns appear only in mask policies",
        ],
    },
    use_container_width=True,
    hide_index=True,
)
st.info(
    "When `table = *`, the tool generates schema-level grants and prepends "
    "`GRANT USE CATALOG` and `GRANT USE SCHEMA` automatically.",
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

# ── Deny Policies ─────────────────────────────────────────────────────
st.header("5. Deny Policies")
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
        ],
        "Internal alias": [
            "REDACT", "LAST_4", "FIRST_4", "HASH", "NONE", "DATE_YEAR", "NULLIFY",
        ],
        "UC function body": [
            "'***REDACTED***'",
            "CONCAT('***-**-', RIGHT(val, 4))",
            "⚠ Not yet implemented — falls back to REDACT",
            "SHA2(val, 256)",
            "No SQL generated — comment only",
            "⚠ Not yet implemented — falls back to REDACT",
            "NULL",
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
st.header("9. HDFS Policy Mapping")
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
-- ⚠ Create a UC External Location covering this path first,
--   then replace the placeholder below with the actual location name.
GRANT READ FILES ON EXTERNAL LOCATION `<ext_loc_data_finance>` TO `analyst_group`;""",
    language="sql",
)

st.header("10. HBase Policy Mapping")
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
            "Cannot auto-translate — comment emitted",
        ],
    },
    use_container_width=True,
    hide_index=True,
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

st.header("12. Schema-Level Grant Pattern")
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
