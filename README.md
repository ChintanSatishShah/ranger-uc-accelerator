# Ranger → Unity Catalog Migration Accelerator

A Streamlit app that parses Apache Ranger policy exports and generates Databricks Unity Catalog SQL — covering grants, row filters, column masks, HDFS/URL External Location grants, HBase table grants, and UDF function grants — with identity mapping, gap analysis, session archiving, and a deployment checklist.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501

Compatible with Cloudera CDP 7.x, HDP 2.x/3.x, and standalone Apache Ranger 2.x.

---

## Workflow

| Step | Page | Description |
|------|------|-------------|
| 0 | **Policy Import** (home) | Upload a Ranger JSON export, paste raw JSON, or load a built-in sample |
| 1 | **Identity Mapping** | Map Ranger users/groups to Databricks principals; Kerberos principals auto-flagged |
| 2 | **Review Policies** | Filter, approve, or reject parsed policy items with inline SQL preview; "Approve all valid" skips non-translatable items |
| 3 | **Generate SQL** | Full Unity Catalog migration script — shows executable statements vs comment-only advisories separately |
| 4 | **Gap Analysis** | Deny policies, Kerberos issues, delegateAdmin, wildcards; readiness score excludes non-translatable policies |
| 5 | **Deploy** | 5-phase deployment checklist with SQL snippets and Databricks doc links |
| 📋 | **Session Archive** | Save, preview, restore, and export past migration sessions |
| 📖 | **Migration Mappings** | Reference: how every Ranger construct maps to Unity Catalog SQL |
| ⚠️ | **Cautions & Constraints** | Known gaps, limitations, and services not automatically translated |

---

## Loading Policies

Three input methods are available on the home page:

| Tab | Method |
|-----|--------|
| **Upload File** | Upload a `.json` Ranger export; saved automatically to `data/input/` with a `user_` prefix |
| **Paste JSON** | Paste raw JSON directly; saved automatically to `data/input/` for reuse |
| **Load Sample** | 49 built-in sample policies covering all Ranger service types and policy patterns |

After loading, a **View loaded JSON** expander appears above the export snippet so you can inspect the raw Ranger export in a scrollable window.

The tool also accepts **Ranger ACL provider test files** (the `testCases[].servicePolicies` format used in `agents-common/src/test/resources/policyengine`) — the wrapper is unwrapped automatically.

### Export from Ranger Admin

```bash
curl -u admin:password \
  "https://<ranger-host>:6080/service/plugins/policies/exportJson?serviceName=<hive-service>" \
  -o ranger_policies.json
```

---

## Supported Policy Types & Services

### Hive (default)
| Ranger policy type | UC output |
|---|---|
| `policyItems` (grants) | `GRANT <privilege> ON TABLE/SCHEMA ... TO ...` |
| `denyPolicyItems` | SQL comment block with remediation advice (no UC DENY) |
| `rowFilterPolicyItems` | `CREATE FUNCTION` + `ALTER TABLE SET ROW FILTER` |
| `dataMaskPolicyItems` | `CREATE FUNCTION` + `ALTER COLUMN SET MASK` |

**Privilege mapping:**

| Ranger | UC (schema-level) | UC (table-level) |
|---|---|---|
| select, read, index, lock | SELECT | SELECT |
| update, write | MODIFY | MODIFY |
| create | CREATE TABLE | ⚠ No equivalent — advisory comment emitted |
| drop | DROP | DROP |
| alter | ALL PRIVILEGES ⚠ | ALL PRIVILEGES ⚠ |
| all | ALL PRIVILEGES | ALL PRIVILEGES |
| execute | EXECUTE | EXECUTE |

> **ALTER note:** `ALTER` has no direct UC equivalent. The tool maps it to `ALL PRIVILEGES` (closest substitute for DDL access) with an advisory comment recommending object-ownership review instead.

**Principal types:** `policyItems[].groups`, `policyItems[].users`, and `policyItems[].roles` are all extracted as policy principals. Ranger roles translate directly to backtick-quoted role names in generated SQL.

**Column mask types:** All Ranger mask types are now supported:

| Ranger type | UC function body |
|---|---|
| MASK | `'***REDACTED***'` |
| MASK_SHOW_LAST_4 | `CONCAT('***-**-', RIGHT(val, 4))` |
| MASK_SHOW_FIRST_4 | `CONCAT(LEFT(val, 4), '***')` |
| MASK_HASH | `SHA2(val, 256)` |
| MASK_DATE_SHOW_YEAR | `MAKE_DATE(YEAR(val), 1, 1)` (returns DATE) |
| MASK_NULL | `NULL` |
| MASK_NONE | Comment only — no masking applied |
| Custom `valueExpr` | Auto-adapted: `CAST('<non-numeric>' AS <type>)` → `NULL`; bare column ref matching masked column → `val`; cross-column refs emit `'***REDACTED***'` with `⛔ BRANCH OMITTED` advisory |

**`SELECT`/`MODIFY` on wildcard table policies (`table: *`):**

Unity Catalog does not allow `GRANT SELECT ON SCHEMA` or `GRANT MODIFY ON SCHEMA` — these are table-level privileges. When a Ranger policy targets `table: *`, the tool generates a `BEGIN...END FOR` loop over `information_schema.tables` to apply the grant to every current table in the schema:

```sql
-- ⚠ SELECT: table-level privilege — granted per-table via loop below.
-- Requires Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled.
BEGIN
  FOR tbl AS (
    SELECT table_name FROM main.information_schema.tables
    WHERE table_schema = 'sales' AND table_type IN ('BASE TABLE', 'EXTERNAL')
  ) DO
    EXECUTE IMMEDIATE 'GRANT SELECT ON TABLE `main`.`sales`.`' || tbl.table_name || '` TO `analyst_group`';
  END FOR;
END;
```

> **Note:** Tables added to the schema **after** this script runs will NOT inherit this grant. Re-run the relevant section or add explicit per-table grants for new tables.

### URL Resource (Hive policies)
Hive policies with a `url` resource (e.g., S3/ADLS paths referenced directly in Hive) are translated to UC External Location grants using the same access map as HDFS:

| Ranger access | UC privilege |
|---|---|
| read | READ FILES |
| write | WRITE FILES |
| execute | READ FILES |
| all | ALL PRIVILEGES |

Generated SQL uses an `<ext_loc_...>` placeholder — replace with the actual External Location name.

### UDF Resource (Hive policies)
Hive policies with a `udf` resource generate `GRANT EXECUTE ON FUNCTION` statements:

```sql
-- ⚠ Ensure function main.hr.udf is registered in UC before granting.
GRANT EXECUTE ON FUNCTION `main`.`hr`.`udf` TO `analyst_group`;
```

The `database` resource (if present) maps to the UC schema. UDF names are used as-is — verify they are registered in UC before executing.

### HDFS
Detected automatically when `serviceName` contains `hdfs`/`hadoop` or when policies use a `path` resource.

| Ranger access | UC privilege |
|---|---|
| read | READ FILES |
| write | WRITE FILES |
| execute | READ FILES |
| all | ALL PRIVILEGES |

Generated SQL: `GRANT READ FILES ON EXTERNAL LOCATION \`<ext_loc_placeholder>\` TO \`user\`;`

> A placeholder is used because External Location names are admin-defined. Replace each `<ext_loc_...>` with the actual location name after creating External Locations in the UC Admin Console.

### HBase
Detected automatically when `serviceName` contains `hbase` or when policies use both `table` and `column-family` resources (assumes HBase data migrated to Delta tables).

| Ranger access | UC privilege |
|---|---|
| read | SELECT |
| write | MODIFY |
| create | CREATE |
| admin | ALL PRIVILEGES |

HBase namespace parsing: `namespace:table` → `catalog.namespace.table`, `namespace:*` → schema-level grant, `*` (all namespaces) → manual review comment.

Column families have no UC equivalent — a table-level grant is generated with a comment noting the column families.

---

## Known Gaps & Constraints

Three policy types **cannot be automatically translated** to executable SQL. They generate advisory comment blocks only, are excluded from the "Approve all valid" bulk action, and are not counted in the Gap Analysis readiness score:

| Non-translatable type | Reason | Output |
|---|---|---|
| Deny policies (`denyPolicyItems`) | UC has no DENY mechanism — additive model only | `⛔ DENY NOT SUPPORTED` comment block with remediation steps |
| Tag placeholder (`tag_placeholder`) | `resourceTags` absent from export — table names cannot be resolved | Comment block with placeholder GRANT |
| HBase wildcard `*` (all namespaces) | Cannot map to a specific UC catalog/schema | `⚠ HBase wildcard` comment block with manual instructions |

All other policy types — Hive grants, row filters, column masks, HDFS, URL, HBase (non-wildcard), UDF, tag grants — produce executable SQL and are included in the readiness score.

| Issue | Severity | Handling |
|---|---|---|
| Deny policies | 🔴 Critical | Advisory comment only — excluded from bulk approval and readiness score |
| Kerberos principals | 🔴 Critical | Auto-detected; must map to service principals via SCIM/M2M |
| `isDenyAllElse` flag | 🔴 Critical | Flagged in Gap Analysis — no UC equivalent; must restructure access |
| Tag policies (no `resourceTags`) | 🔴 Critical | Advisory comment only — table names unknown; re-export with `resourceTags` |
| HBase wildcard `*` (all namespaces) | 🔴 Critical | Advisory comment only — grant specific schemas manually |
| ALTER privilege | 🟡 Review | Mapped to ALL PRIVILEGES (no direct UC equivalent); review ownership instead |
| Row filter expressions | 🟡 Review | Copied verbatim — validate for Hive UDFs or request-context attributes |
| Custom valueExpr masks | 🟡 Review | Auto-adapted where possible; cross-column references use conservative fallback |
| SELECT/MODIFY on table=* | 🟡 Review | Applied via BEGIN…END FOR loop — tables added later won't inherit the grant |
| HDFS / URL External Location names | 🟡 Review | Placeholder generated; replace with real names |
| HBase column families | 🟡 Review | Falls back to table-level grant; no column-family isolation in UC |
| UDF grants | 🟡 Review | Function must exist in UC before GRANT EXECUTE is valid |
| delegateAdmin | 🟡 Review | Comment suggests MANAGE privilege — review each case |
| Wildcard table (`*`) | 🟡 Review | Expanded to schema-level grant (forward-looking scope) |
| `validitySchedules` | 🟡 Review | Flagged in Gap Analysis — UC has no time-scoped grants |
| Policy `conditions` | 🟡 Review | Flagged in Gap Analysis — UC has no request-context conditions |
| Disabled policies | ℹ️ Info | Parsed but excluded from SQL unless manually approved |
| Kafka, YARN, Storm, Knox, Atlas | ❌ Out of scope | No UC equivalent — excluded from translation |

See the **Cautions & Constraints** reference page in the app for full details.

---

## Session Archiving

All migration sessions can be saved as JSON archives in `data/output/`:

- **Save & Archive** — archive the current session with optional notes from the Session Archive page
- **Restore Session** — reload any archived session to continue or compare approaches
- **Download ZIP** — export a complete archive package (Ranger JSON, policy items, identity map, generated SQL)
- **Delete** — remove individual archives

User session filenames use the format `user_<service>_YYYYMMDD_HHMMSS.json`. Pre-generated sample archives (no timestamp) are tracked in git.

The Session Archive page shows each archive with:
- **Collapsible heading** displaying date · item count · file size · service name at a glance
- **Side-by-side view** when expanded: left pane shows input attributes (service metadata, policy type breakdown, schemas, principals, original Ranger JSON); right pane shows output (status breakdown, identity map, generated SQL)
- Step-by-step replay guide for restoring and continuing a session

---

## Sample Files

49 built-in samples in `data/input/` covering all policy types and services:

| Category | Samples |
|---|---|
| Cloudera CDP | 15-policy production-style sample |
| Hive access | Simple, medium, complex grants |
| Row filters | Simple, medium, complex filter expressions |
| Column masks | Simple, medium, complex mask types |
| Tag-based | Simple, medium, complex tag policies |
| Hive engine | Full policy engine test samples: mask+filter, mutex, roles, incremental, partial resources |
| HDFS | 11 samples (allaudit, noaudit, incremental, zones, resourcespec, multiple accesses, tag-based, AWS) |
| HBase | 5 samples (basic, namespace, multiple matching, tag-based) |
| ACL Provider Tests | 4 samples from the Ranger `agents-common` test suite (default Hive, HDFS, mask+filter, resource hierarchy tags) |
| Other services | Kafka, Atlas |

---

## Project Layout

```
ranger-uc-accelerator/
├── app.py                          # Entrypoint + navigation (st.navigation)
├── pages/
│   ├── 1_Identity_Mapping.py
│   ├── 2_Review_Policies.py
│   ├── 3_Generate_SQL.py
│   ├── 4_Gap_Analysis.py
│   ├── 5_Deploy.py
│   ├── 6_History.py                # Session Archive
│   ├── 7_Migration_Mappings.py     # Reference: mappings (read-only)
│   └── 8_Cautions_Constraints.py  # Reference: gaps & limitations (read-only)
├── lib/
│   ├── ranger_parser.py            # Parser, SQL generator, gap analyzer
│   ├── sample_data.py              # 49-sample catalog
│   ├── history.py                  # Session archiving (save/load/list/delete/zip)
│   └── state.py                    # Streamlit session-state helpers
├── data/
│   ├── input/                      # 49 sample JSON files (git-tracked) + user uploads (user_* gitignored)
│   └── output/                     # Pre-generated sample archives (git-tracked) + user sessions (user_* gitignored)
├── requirements.txt
└── README.md
```

---

## Navigation Structure

```
Migration Steps
  Policy Import       ← home page; upload / paste / sample
  Identity Mapping
  Review Policies
  Generate SQL
  Gap Analysis
  Deploy

History
  Session Archive

References
  Migration Mappings
  Cautions & Constraints
```
