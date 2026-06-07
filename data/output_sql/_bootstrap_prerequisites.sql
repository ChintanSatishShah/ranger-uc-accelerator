-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  Bootstrap Prerequisites — Databricks Unity Catalog Migration        ║
-- ║  Generated from all sample policy outputs in data/output_sql/       ║
-- ║                                                                      ║
-- ║  Execution order (run each step before the next):                   ║
-- ║    Step 1 — Provision identities (SCIM / Account Console)           ║
-- ║    Step 2 — Create Storage Credentials (Account Console)            ║
-- ║    Step 3 — Catalog (SQL Warehouse)                                 ║
-- ║    Step 4 — Schemas (SQL Warehouse)                                 ║
-- ║    Step 5 — External Locations (SQL Warehouse)                      ║
-- ║    Step 6 — Tables (SQL Warehouse)                                  ║
-- ║    Step 7 — UDF stubs (register before GRANT EXECUTE)               ║
-- ║    Then  — Run individual migration SQL files                       ║
-- ╚══════════════════════════════════════════════════════════════════════╝

-- Summary: 1 catalog · 37 schemas · 57 tables
--          29 external locations (7 sub-path advisories) · 4 UDF references
--          58 human users · 8 service accounts
--          0 Kerberos principals · 107 groups · 4 roles

-- ════════════════════════════════════════════════════════════════════
-- STEP 1 — IDENTITIES  (Account Console / SCIM — not SQL)
--
-- Databricks does not support CREATE USER or CREATE GROUP via SQL.
-- Provision all identities BEFORE running any GRANT statements.
--   • Human users    → SCIM sync from Okta / Azure AD / Google WS
--   • Service accts  → Account Console → Service Principals → Add
--   • Groups         → Account Console → Groups → Add group
--                      or SCIM group push from your IdP
--   • Ranger roles   → create one Databricks group per role
-- ════════════════════════════════════════════════════════════════════

-- ── Human Users (58) ──────────────────────────────────────────────
--   USER  adam
--   USER  admin
--   USER  analyst1@company.com
--   USER  auditor@company.com
--   USER  cfo
--   USER  cfo@company.com
--   USER  chief_compliance_officer
--   USER  compliance_officer@company.com
--   USER  contractor1@company.com
--   USER  controller@company.com
--   USER  data_admin@company.com
--   USER  data_scientist@company.com
--   USER  data_steward@company.com
--   USER  denieduser
--   USER  dpo@company.com
--   USER  eve
--   USER  finance
--   USER  guest
--   USER  hadoop
--   USER  hbase
--   USER  hr_director
--   USER  hrt_21
--   USER  hrt_qa
--   USER  jane
--   USER  john
--   USER  keyadmin
--   USER  michael.park
--   USER  non-user1
--   USER  non-user2
--   USER  non-user3
--   USER  non-user5
--   USER  non-user6
--   USER  non-user7
--   USER  non-user8
--   USER  rangerlookup
--   USER  sales-admin
--   USER  sales_analyst@company.com
--   USER  sales_manager@company.com
--   USER  sarah.chen
--   USER  scott
--   USER  superman
--   USER  user-override
--   USER  user-ra
--   USER  user-ra-ta
--   USER  user-ra-td
--   USER  user-rd-td
--   USER  user-td
--   USER  user1
--   USER  user2
--   USER  user3
--   USER  user31
--   USER  user32
--   USER  user4
--   USER  user5
--   USER  user6
--   USER  west_manager@company.com
--   USER  {OWNER}
--   USER  {USER}

-- ── Service Principals (8) ─────────────────────────────────────
--   SERVICE PRINCIPAL  airflow_svc
--   SERVICE PRINCIPAL  atlas
--   SERVICE PRINCIPAL  dba_finance_svc
--   SERVICE PRINCIPAL  etl_service_account
--   SERVICE PRINCIPAL  hive
--   SERVICE PRINCIPAL  nifi_svc
--   SERVICE PRINCIPAL  old_tableau_svc
--   SERVICE PRINCIPAL  vendor_api_svc

-- ── Groups (107) ─────────────────────────────────────────────────────
--   GROUP  account_managers
--   GROUP  accounting
--   GROUP  admin
--   GROUP  all_employees
--   GROUP  analytics_team
--   GROUP  audit_team
--   GROUP  bi_analysts
--   GROUP  bi_developers
--   GROUP  cluster-admin
--   GROUP  compliance_officers
--   GROUP  compliance_team
--   GROUP  contractors
--   GROUP  customer_service
--   GROUP  customer_success
--   GROUP  customer_support_agents
--   GROUP  customer_support_leads
--   GROUP  data-stewards
--   GROUP  data_analysts
--   GROUP  data_engineering
--   GROUP  data_governance
--   GROUP  data_governance_team
--   GROUP  data_protection_officers
--   GROUP  data_protection_team
--   GROUP  data_science
--   GROUP  data_scientists
--   GROUP  email-admins
--   GROUP  engg
--   GROUP  executive_team
--   GROUP  executives
--   GROUP  external_vendor_readonly
--   GROUP  external_vendors
--   GROUP  fb00_bbrut
--   GROUP  fb00_braff
--   GROUP  fb00_xbgdta
--   GROUP  fb00_xda017
--   GROUP  fb00_xda029
--   GROUP  fb00_xda034
--   GROUP  fb00_xda035
--   GROUP  fb00_xda041
--   GROUP  fb00_xda042
--   GROUP  fb00_xda043
--   GROUP  fb00_xda052
--   GROUP  fb00_xda060
--   GROUP  fb00_xda062
--   GROUP  fb00_xda066
--   GROUP  fb00_xda085
--   GROUP  fb00_xda092
--   GROUP  fb00_xda107
--   GROUP  fb00_xda108
--   GROUP  fb00_xda126
--   GROUP  fb00_xda143
--   GROUP  fb00_xda144
--   GROUP  fb00_xds020
--   GROUP  fb00_xoi022
--   GROUP  fb00_xoi025
--   GROUP  fb00_xoi033
--   GROUP  fb00_xoi097
--   GROUP  fb00_xoi098
--   GROUP  fb00_xoi099
--   GROUP  fb00_xpr203
--   GROUP  fb00_xpx091
--   GROUP  finance
--   GROUP  finance-admin
--   GROUP  finance-controller
--   GROUP  finance_analysts
--   GROUP  finance_db_admins
--   GROUP  finance_leadership
--   GROUP  finance_managers
--   GROUP  group1
--   GROUP  group2
--   GROUP  group3
--   GROUP  hive-admins
--   GROUP  housekeeping
--   GROUP  hr-admin
--   GROUP  hr_admins
--   GROUP  hr_business_partners
--   GROUP  hr_coordinators
--   GROUP  hr_interns
--   GROUP  hr_staff
--   GROUP  internal_audit
--   GROUP  junior_analysts
--   GROUP  legacy_bi_users
--   GROUP  legal
--   GROUP  marketing_americas
--   GROUP  marketing_apac
--   GROUP  marketing_emea
--   GROUP  marketing_team
--   GROUP  ml_engineers
--   GROUP  platform_team
--   GROUP  pr00_xbgdta
--   GROUP  privacy-officers
--   GROUP  privacy_officers
--   GROUP  privacy_team
--   GROUP  qqsens
--   GROUP  regional_managers
--   GROUP  role-group1
--   GROUP  sales_analysts
--   GROUP  sales_team
--   GROUP  sd00_xlx001
--   GROUP  stewards
--   GROUP  supply_chain_vp
--   GROUP  support_team
--   GROUP  vip_account_managers
--   GROUP  warehouse_eu
--   GROUP  warehouse_sg
--   GROUP  warehouse_us_west
--   GROUP  xagcla

-- ── Roles (4) — create as Databricks groups ──────────────────────
--   ROLE  eden  →  group `eden`
--   ROLE  fin-admin  →  group `fin-admin`
--   ROLE  fin-group  →  group `fin-group`
--   ROLE  tarzan  →  group `tarzan`


-- ════════════════════════════════════════════════════════════════════
-- STEP 2 — STORAGE CREDENTIALS  (Account Console — not SQL)
--
-- Storage Credentials are required before any External Location can
-- be created. Each credential covers one cloud storage account.
--
-- Create in: Account Console → Data → Storage Credentials → Add
-- Or via Terraform: databricks_storage_credential resource
--
-- You will need one credential per cloud account/subscription used
-- by the HDFS / URL paths in your Ranger export.
--
--   AWS   → IAM role ARN  (instance profile or cross-account role)
--   Azure → Managed Identity or Service Principal + client secret
--   GCP   → Service Account with GCS permissions
-- ════════════════════════════════════════════════════════════════════

-- 32 External Locations will be created in Step 5.
-- At minimum one Storage Credential is required; map paths to credentials:
-- CREATE STORAGE CREDENTIAL `<name>`
--   WITH IAM_ROLE (ROLE_ARN = 'arn:aws:iam::<account>:role/<role>');  -- AWS
-- or:
-- CREATE STORAGE CREDENTIAL `<name>`
--   WITH AZURE_MANAGED_IDENTITY (CREDENTIAL_NAME = '<connector-name>');  -- Azure

-- ════════════════════════════════════════════════════════════════════
-- STEP 3 — CATALOG
--    All generated SQL targets catalog 'main'.
--    Replace 'main' with your actual catalog name throughout.
--    Requires: metastore admin.
-- ════════════════════════════════════════════════════════════════════

-- CREATE CATALOG IF NOT EXISTS `main`;  -- uncomment if catalog does not exist
USE CATALOG `main`;

-- ════════════════════════════════════════════════════════════════════
-- STEP 4 — SCHEMAS  (37 total)
--    Requires: USE CATALOG + CREATE SCHEMA privilege.
-- ════════════════════════════════════════════════════════════════════

CREATE SCHEMA IF NOT EXISTS `main`.`SYSTEM`;
CREATE SCHEMA IF NOT EXISTS `main`.`analytics_warehouse`;
CREATE SCHEMA IF NOT EXISTS `main`.`audit_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`curated_layer`;
CREATE SCHEMA IF NOT EXISTS `main`.`customer_360`;
CREATE SCHEMA IF NOT EXISTS `main`.`customer_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`db1`;
CREATE SCHEMA IF NOT EXISTS `main`.`db2`;
CREATE SCHEMA IF NOT EXISTS `main`.`db3`;
CREATE SCHEMA IF NOT EXISTS `main`.`default`;
CREATE SCHEMA IF NOT EXISTS `main`.`demo1`;
CREATE SCHEMA IF NOT EXISTS `main`.`demo2`;
CREATE SCHEMA IF NOT EXISTS `main`.`denyAllElse`;
CREATE SCHEMA IF NOT EXISTS `main`.`dept_`;
CREATE SCHEMA IF NOT EXISTS `main`.`dept_engg`;
CREATE SCHEMA IF NOT EXISTS `main`.`dummy`;
CREATE SCHEMA IF NOT EXISTS `main`.`employee`;
CREATE SCHEMA IF NOT EXISTS `main`.`feature_store`;
CREATE SCHEMA IF NOT EXISTS `main`.`finance`;
CREATE SCHEMA IF NOT EXISTS `main`.`finance_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`governance_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`hr`;
CREATE SCHEMA IF NOT EXISTS `main`.`hr_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`legacy_analytics`;
CREATE SCHEMA IF NOT EXISTS `main`.`main`;
CREATE SCHEMA IF NOT EXISTS `main`.`marketing`;
CREATE SCHEMA IF NOT EXISTS `main`.`marketing_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`namespace_1`;
CREATE SCHEMA IF NOT EXISTS `main`.`org`;
CREATE SCHEMA IF NOT EXISTS `main`.`raw_ingest`;
CREATE SCHEMA IF NOT EXISTS `main`.`reporting_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`sales`;
CREATE SCHEMA IF NOT EXISTS `main`.`staging_zone`;
CREATE SCHEMA IF NOT EXISTS `main`.`supply_chain_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`test_db`;
CREATE SCHEMA IF NOT EXISTS `main`.`user_`;
CREATE SCHEMA IF NOT EXISTS `main`.`vendor_integration_db`;

-- ════════════════════════════════════════════════════════════════════
-- STEP 5 — EXTERNAL LOCATIONS  (29 creatable · 7 sub-path advisories)
--    Requires: account admin + Storage Credential from Step 2.
--    Bucket: ranger-uc-demo (demo). Replace with your actual bucket.
--
--    ⚠ 7 Ranger path(s) are sub-paths of another location.
--    UC does not allow overlapping External Locations — these are
--    commented out below. Use an External Volume inside the parent
--    location for fine-grained access control on sub-paths.
-- ════════════════════════════════════════════════════════════════════

-- Ranger path: \
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc__`
  URL 's3://ranger-uc-demo/ext_loc__/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /a/b*
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_a_b_`
  URL 's3://ranger-uc-demo/ext_loc_a_b_/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /a/bc*
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_a_bc_`
  URL 's3://ranger-uc-demo/ext_loc_a_bc_/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /finance
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_finance`
  URL 's3://ranger-uc-demo/ext_loc_finance/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ⛔ SKIPPED — Ranger path: /finance/limited
--    `ext_loc_finance_limited` is a sub-path of `ext_loc_finance`.
--    UC External Locations cannot overlap. Use an External Volume
--    under `ext_loc_finance` for access control on this sub-path.
-- CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_finance_limited`
--   URL 's3://ranger-uc-demo/ext_loc_finance_limited/'
--   WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ⛔ SKIPPED — Ranger path: /finance/rest*ricted/
--    `ext_loc_finance_rest_ricted` is a sub-path of `ext_loc_finance`.
--    UC External Locations cannot overlap. Use an External Volume
--    under `ext_loc_finance` for access control on this sub-path.
-- CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_finance_rest_ricted`
--   URL 's3://ranger-uc-demo/ext_loc_finance_rest_ricted/'
--   WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ⛔ SKIPPED — Ranger path: /finance/restricted/
--    `ext_loc_finance_restricted` is a sub-path of `ext_loc_finance`.
--    UC External Locations cannot overlap. Use an External Volume
--    under `ext_loc_finance` for access control on this sub-path.
-- CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_finance_restricted`
--   URL 's3://ranger-uc-demo/ext_loc_finance_restricted/'
--   WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /home/
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_home`
  URL 's3://ranger-uc-demo/ext_loc_home/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ⛔ SKIPPED — Ranger path: /home/{USER}/
--    `ext_loc_home__USER_` is a sub-path of `ext_loc_home`.
--    UC External Locations cannot overlap. Use an External Volume
--    under `ext_loc_home` for access control on this sub-path.
-- CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_home__USER_`
--   URL 's3://ranger-uc-demo/ext_loc_home__USER_/'
--   WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: http://qe-s3-bucket-mst/test_abcd/abcd/
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_http___qe_s3_bucket_mst_test_abcd_abcd`
  URL 's3://ranger-uc-demo/ext_loc_http___qe_s3_bucket_mst_test_abcd_abcd/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /mybu/admin
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_mybu_admin`
  URL 's3://ranger-uc-demo/ext_loc_mybu_admin/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /mybu/analyst
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_mybu_analyst`
  URL 's3://ranger-uc-demo/ext_loc_mybu_analyst/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /override-resource
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_override_resource`
  URL 's3://ranger-uc-demo/ext_loc_override_resource/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /public
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_public`
  URL 's3://ranger-uc-demo/ext_loc_public/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /public/*
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_public__`
  URL 's3://ranger-uc-demo/ext_loc_public__/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ⛔ SKIPPED — Ranger path: /public/finance
--    `ext_loc_public_finance` is a sub-path of `ext_loc_public`.
--    UC External Locations cannot overlap. Use an External Volume
--    under `ext_loc_public` for access control on this sub-path.
-- CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_public_finance`
--   URL 's3://ranger-uc-demo/ext_loc_public_finance/'
--   WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /ranger/audit/kms
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_ranger_audit_kms`
  URL 's3://ranger-uc-demo/ext_loc_ranger_audit_kms/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /resource
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_resource`
  URL 's3://ranger-uc-demo/ext_loc_resource/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_root`
  URL 's3://ranger-uc-demo/ext_loc_root/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: s3a://qe-s3-bucket-mst/demo
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_s3a___qe_s3_bucket_mst_demo`
  URL 's3://ranger-uc-demo/ext_loc_s3a___qe_s3_bucket_mst_demo/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: s3a://qe-s3-bucket-mst/test_abcd/abcd
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_s3a___qe_s3_bucket_mst_test_abcd_abcd`
  URL 's3://ranger-uc-demo/ext_loc_s3a___qe_s3_bucket_mst_test_abcd_abcd/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /test?
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_test_`
  URL 's3://ranger-uc-demo/ext_loc_test_/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /test/forbidden/
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_test_forbidden`
  URL 's3://ranger-uc-demo/ext_loc_test_forbidden/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /test/restricted/
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_test_restricted`
  URL 's3://ranger-uc-demo/ext_loc_test_restricted/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /tmp/{USER}
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmp__USER_`
  URL 's3://ranger-uc-demo/ext_loc_tmp__USER_/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ⛔ SKIPPED — Ranger path: /tmp/{USER}/subdir
--    `ext_loc_tmp__USER__subdir` is a sub-path of `ext_loc_tmp__USER_`.
--    UC External Locations cannot overlap. Use an External Volume
--    under `ext_loc_tmp__USER_` for access control on this sub-path.
-- CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmp__USER__subdir`
--   URL 's3://ranger-uc-demo/ext_loc_tmp__USER__subdir/'
--   WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /tmp/a/b
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmp_a_b`
  URL 's3://ranger-uc-demo/ext_loc_tmp_a_b/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /tmp/ab
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmp_ab`
  URL 's3://ranger-uc-demo/ext_loc_tmp_ab/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /tmp/ac/d/e/f
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmp_ac_d_e_f`
  URL 's3://ranger-uc-demo/ext_loc_tmp_ac_d_e_f/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /tmp.txt
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmp_txt`
  URL 's3://ranger-uc-demo/ext_loc_tmp_txt/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /tmpa/b
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmpa_b`
  URL 's3://ranger-uc-demo/ext_loc_tmpa_b/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /tmpfile
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_tmpfile`
  URL 's3://ranger-uc-demo/ext_loc_tmpfile/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /unaudited-resource
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_unaudited_resource`
  URL 's3://ranger-uc-demo/ext_loc_unaudited_resource/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /user/{USER}/*
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_user__USER___`
  URL 's3://ranger-uc-demo/ext_loc_user__USER___/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- Ranger path: /user/dir
CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_user_dir`
  URL 's3://ranger-uc-demo/ext_loc_user_dir/'
  WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ⛔ SKIPPED — Ranger path: /user/dir/subdir
--    `ext_loc_user_dir_subdir` is a sub-path of `ext_loc_user_dir`.
--    UC External Locations cannot overlap. Use an External Volume
--    under `ext_loc_user_dir` for access control on this sub-path.
-- CREATE EXTERNAL LOCATION IF NOT EXISTS `ext_loc_user_dir_subdir`
--   URL 's3://ranger-uc-demo/ext_loc_user_dir_subdir/'
--   WITH (STORAGE CREDENTIAL `<your_storage_credential>`);

-- ════════════════════════════════════════════════════════════════════
-- STEP 6 — TABLES  (57 total)
--    Columns shown are those referenced in mask or row-filter policies.
--    Add remaining columns and correct data types before migrating.
--    ⚠ Data migration (Hive → Delta / HBase → Delta) is a separate
--      process — these CREATE TABLE statements create empty stubs.
--      Populate tables from source before running migration SQL.
--    Requires: USE CATALOG + USE SCHEMA + CREATE TABLE privilege.
-- ════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS `main`.`customer_360`.`customer_details` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`customer_360`.`customers` (
  `credit_card` STRING,  -- ⚠ verify/update data type
  `email` STRING,  -- ⚠ verify/update data type
  `phone` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`customer_360`.`customers_eu` (
  `email` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`customer_db`.`consent_records` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`customer_db`.`customer_contacts` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`customer_db`.`customer_profiles` (
  `date_of_birth` STRING,  -- ⚠ verify/update data type
  `email` STRING,  -- ⚠ verify/update data type
  `mailing_address` STRING,  -- ⚠ verify/update data type
  `phone_number` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`customer_db`.`data_subject_requests` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`db1`.`tbl` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`db1`.`tbl1` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`db1`.`tmp` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`db2`.`tbl2` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`db3`.`tbl3` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`default` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`finance` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`invoices` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`prospects` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`table` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`test` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`test1` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`default`.`test2` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`demo1`.`demo1_tbl1` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`demo1`.`demo1_tbl2` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`denyAllElse`.`table` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`employee`.`personal` (
  `dummy` STRING,  -- ⚠ verify/update data type
  `name` STRING,  -- ⚠ verify/update data type
  `ssn` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`finance`.`accounts` (
  `account_balance` STRING,  -- ⚠ verify/update data type
  `account_number` STRING,  -- ⚠ verify/update data type
  `birth_date` STRING,  -- ⚠ verify/update data type
  `customer_id` STRING,  -- ⚠ verify/update data type
  `transaction_amount` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`finance`.`fin_` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`finance`.`transactions` (
  `account_number` STRING,  -- ⚠ verify/update data type
  `birth_date` STRING,  -- ⚠ verify/update data type
  `credit_card` STRING,  -- ⚠ verify/update data type
  `customer_id` STRING,  -- ⚠ verify/update data type
  `transaction_amount` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`finance_db`.`accounts_payable` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`finance_db`.`accounts_receivable` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`finance_db`.`invoices` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`finance_db`.`transactions` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr`.`employee` (
  `date_of_birth` STRING,  -- ⚠ verify/update data type
  `project` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr`.`employee2` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr`.`employees` (
  `salary` STRING,  -- ⚠ verify/update data type
  `ssn` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr`.`payroll` (
  `salary` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr_db`.`compensation` (
  `base_salary` STRING,  -- ⚠ verify/update data type
  `bonus_amount` STRING,  -- ⚠ verify/update data type
  `equity_grants` STRING,  -- ⚠ verify/update data type
  `total_compensation` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr_db`.`departments` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr_db`.`employees` (
  `bank_account_number` STRING,  -- ⚠ verify/update data type
  `home_address` STRING,  -- ⚠ verify/update data type
  `salary` STRING,  -- ⚠ verify/update data type
  `ssn` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`hr_db`.`performance_reviews` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`marketing`.`campaigns` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`marketing_db`.`ad_spend` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`marketing_db`.`campaign_metrics` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`marketing_db`.`campaigns` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`org`.`employee` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`sales`.`customers` (
  `email` STRING,  -- ⚠ verify/update data type
  `ssn` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`sales`.`orders` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`sales`.`products` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`sales`.`reports` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`sales`.`transactions` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`supply_chain_db`.`inventory` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`supply_chain_db`.`shipments` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`supply_chain_db`.`warehouse_ops` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`test_db`.`dept_` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`test_db`.`dept_hr` (
  `col1` STRING  -- ⚠ verify/update data type
  -- TODO: add remaining columns to match your source schema
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`vendor_integration_db`.`price_list` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`vendor_integration_db`.`vendor_catalog` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

CREATE TABLE IF NOT EXISTS `main`.`vendor_integration_db`.`vendor_orders` (
  id BIGINT  -- TODO: replace with actual columns
) USING DELTA;

-- ════════════════════════════════════════════════════════════════════
-- STEP 7 — UDF FUNCTION STUBS  (4 referenced)
--    The migration SQL contains GRANT EXECUTE ON FUNCTION statements.
--    Each function must exist in UC before the GRANT is executed.
--
--    Hive UDFs (JAR-based) must be reimplemented as:
--      • SQL UDFs:    CREATE FUNCTION ... RETURNS ... RETURN ...;
--      • Python UDFs: CREATE FUNCTION ... AS $$ ... $$ LANGUAGE PYTHON;
--
--    The stubs below use RETURN NULL as placeholder — replace with
--    the actual logic migrated from your Hive UDF implementation.
-- ════════════════════════════════════════════════════════════════════

-- UDF: main.hr.udf
CREATE OR REPLACE FUNCTION `main`.`hr`.`udf`(val STRING)
RETURNS STRING
RETURN NULL;  -- TODO: replace with actual UDF logic migrated from Hive

-- UDF: main.hr*.udf
CREATE OR REPLACE FUNCTION `main`.`hr*`.`udf`(val STRING)
RETURNS STRING
RETURN NULL;  -- TODO: replace with actual UDF logic migrated from Hive

-- UDF: main.main.hr
CREATE OR REPLACE FUNCTION `main`.`main`.`hr`(val STRING)
RETURNS STRING
RETURN NULL;  -- TODO: replace with actual UDF logic migrated from Hive