"""Built-in Cloudera CDP 7.1 sample export (15 realistic policies)."""

SAMPLE_RANGER_EXPORT = {
    "serviceName": "cl1_hive_production",
    "serviceType": "hive",
    "clusterName": "cloudera_prod_cluster_01",
    "description": "Ranger policies exported from Cloudera CDP 7.1 - Production Hive Service",
    "policies": [
        {
            "id": 101, "name": "finance_analysts_read_access",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0, "policyPriority": 0,
            "description": "Read-only access for finance analysts on core financial tables",
            "resources": {
                "database": {"values": ["finance_db"]},
                "table": {"values": ["transactions", "invoices", "accounts_payable", "accounts_receivable"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["finance_analysts", "finance_managers"],
                "users": ["sarah.chen", "michael.park"],
                "accesses": [{"type": "select", "isAllowed": True}, {"type": "read", "isAllowed": True}],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [], "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 102, "name": "finance_admins_full_access",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "Full DDL and DML access for finance database administrators",
            "resources": {
                "database": {"values": ["finance_db"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["finance_db_admins"],
                "users": ["dba_finance_svc"],
                "accesses": [
                    {"type": "select", "isAllowed": True}, {"type": "update", "isAllowed": True},
                    {"type": "create", "isAllowed": True}, {"type": "drop", "isAllowed": True},
                    {"type": "alter", "isAllowed": True}, {"type": "all", "isAllowed": True},
                ],
                "delegateAdmin": True,
            }],
            "denyPolicyItems": [], "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 103, "name": "hr_employee_data_access",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "HR team access to employee master data with deny for interns",
            "resources": {
                "database": {"values": ["hr_db"]},
                "table": {"values": ["employees", "departments", "compensation", "performance_reviews"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [
                {
                    "groups": ["hr_business_partners", "hr_admins"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}, {"type": "update", "isAllowed": True}],
                    "delegateAdmin": False,
                },
                {
                    "groups": ["hr_coordinators"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "delegateAdmin": False,
                },
            ],
            "denyPolicyItems": [{
                "groups": ["hr_interns"], "users": [],
                "accesses": [
                    {"type": "update", "isAllowed": True}, {"type": "create", "isAllowed": True},
                    {"type": "drop", "isAllowed": True}, {"type": "alter", "isAllowed": True},
                ],
                "delegateAdmin": False,
            }],
            "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 104, "name": "hr_pii_column_masking",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 1,
            "description": "Mask PII columns in employee table",
            "resources": {
                "database": {"values": ["hr_db"]},
                "table": {"values": ["employees"]},
                "column": {"values": ["ssn", "bank_account_number", "salary", "home_address"]},
            },
            "policyItems": [], "denyPolicyItems": [], "rowFilterPolicyItems": [],
            "dataMaskPolicyItems": [
                {
                    "groups": ["hr_admins"], "users": ["hr_director"],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_NONE", "valueExpr": ""},
                },
                {
                    "groups": ["hr_business_partners"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_SHOW_LAST_4", "valueExpr": ""},
                },
                {
                    "groups": ["hr_coordinators", "hr_interns"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_HASH", "valueExpr": ""},
                },
            ],
        },
        {
            "id": 105, "name": "marketing_regional_row_filter",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 2,
            "description": "Row-level security: marketing teams see only their region",
            "resources": {
                "database": {"values": ["marketing_db"]},
                "table": {"values": ["campaigns", "ad_spend", "campaign_metrics"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["marketing_apac"], "users": [],
                "accesses": [{"type": "select", "isAllowed": True}],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [],
            "rowFilterPolicyItems": [
                {
                    "groups": ["marketing_apac"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "rowFilterInfo": {"filterExpr": "region = 'APAC'"},
                },
                {
                    "groups": ["marketing_emea"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "rowFilterInfo": {"filterExpr": "region = 'EMEA'"},
                },
                {
                    "groups": ["marketing_americas"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "rowFilterInfo": {"filterExpr": "region IN ('NA', 'LATAM')"},
                },
            ],
            "dataMaskPolicyItems": [],
        },
        {
            "id": 106, "name": "data_engineering_etl_pipelines",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "Full access for data engineering across raw/staging/curated",
            "resources": {
                "database": {"values": ["raw_ingest", "staging_zone", "curated_layer"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["data_engineering"],
                "users": ["etl_service_account", "airflow_svc", "nifi_svc"],
                "accesses": [
                    {"type": "select", "isAllowed": True}, {"type": "update", "isAllowed": True},
                    {"type": "create", "isAllowed": True}, {"type": "drop", "isAllowed": True},
                    {"type": "alter", "isAllowed": True}, {"type": "all", "isAllowed": True},
                ],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [], "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 107, "name": "data_science_read_curated",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "Data scientists can read curated and feature store data",
            "resources": {
                "database": {"values": ["curated_layer", "feature_store"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["data_scientists", "ml_engineers"], "users": [],
                "accesses": [{"type": "select", "isAllowed": True}, {"type": "read", "isAllowed": True}],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [{
                "groups": ["data_scientists"], "users": [],
                "accesses": [
                    {"type": "drop", "isAllowed": True},
                    {"type": "alter", "isAllowed": True},
                    {"type": "create", "isAllowed": True},
                ],
                "delegateAdmin": False,
            }],
            "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 108, "name": "bi_analysts_reporting",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "BI analysts access to reporting and analytics schemas",
            "resources": {
                "database": {"values": ["reporting_db", "analytics_warehouse"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [
                {
                    "groups": ["bi_analysts", "bi_developers", "executive_team"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "delegateAdmin": False,
                },
                {
                    "groups": ["bi_developers"], "users": [],
                    "accesses": [{"type": "create", "isAllowed": True}, {"type": "alter", "isAllowed": True}],
                    "delegateAdmin": False,
                },
            ],
            "denyPolicyItems": [], "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 109, "name": "customer_data_restricted",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "Restricted access to customer PII - GDPR compliant",
            "resources": {
                "database": {"values": ["customer_db"]},
                "table": {"values": ["customer_profiles", "customer_contacts", "consent_records", "data_subject_requests"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [
                {
                    "groups": ["privacy_officers", "data_governance_team"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}, {"type": "update", "isAllowed": True}],
                    "delegateAdmin": False,
                },
                {
                    "groups": ["customer_support_leads"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "delegateAdmin": False,
                },
            ],
            "denyPolicyItems": [{
                "groups": ["customer_support_agents"], "users": [],
                "accesses": [
                    {"type": "update", "isAllowed": True}, {"type": "drop", "isAllowed": True},
                    {"type": "alter", "isAllowed": True},
                ],
                "delegateAdmin": False,
            }],
            "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 110, "name": "customer_pii_masking",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 1,
            "description": "Mask customer PII for non-privileged users",
            "resources": {
                "database": {"values": ["customer_db"]},
                "table": {"values": ["customer_profiles"]},
                "column": {"values": ["email", "phone_number", "mailing_address", "date_of_birth"]},
            },
            "policyItems": [], "denyPolicyItems": [], "rowFilterPolicyItems": [],
            "dataMaskPolicyItems": [
                {
                    "groups": ["privacy_officers"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_NONE", "valueExpr": ""},
                },
                {
                    "groups": ["customer_support_leads"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_SHOW_LAST_4", "valueExpr": ""},
                },
                {
                    "groups": ["customer_support_agents", "bi_analysts"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_HASH", "valueExpr": ""},
                },
            ],
        },
        {
            "id": 111, "name": "supply_chain_row_security",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 2,
            "description": "Warehouse managers see only their warehouse data",
            "resources": {
                "database": {"values": ["supply_chain_db"]},
                "table": {"values": ["inventory", "shipments", "warehouse_ops"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["warehouse_sg"], "users": [],
                "accesses": [{"type": "select", "isAllowed": True}],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [],
            "rowFilterPolicyItems": [
                {
                    "groups": ["warehouse_sg"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "rowFilterInfo": {"filterExpr": "warehouse_code = 'SG-01'"},
                },
                {
                    "groups": ["warehouse_us_west"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "rowFilterInfo": {"filterExpr": "warehouse_code IN ('US-W1', 'US-W2')"},
                },
                {
                    "groups": ["warehouse_eu"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "rowFilterInfo": {"filterExpr": "warehouse_code LIKE 'EU-%'"},
                },
                {
                    "groups": ["supply_chain_vp"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "rowFilterInfo": {"filterExpr": "1=1"},
                },
            ],
            "dataMaskPolicyItems": [],
        },
        {
            "id": 112, "name": "legacy_analytics_disabled",
            "isEnabled": False, "isAuditEnabled": True, "policyType": 0,
            "description": "OLD - Legacy analytics access - disabled after migration",
            "resources": {
                "database": {"values": ["legacy_analytics"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["legacy_bi_users"], "users": ["old_tableau_svc"],
                "accesses": [{"type": "select", "isAllowed": True}],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [], "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 113, "name": "compliance_audit_tables",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "Compliance team read access to audit and governance tables",
            "resources": {
                "database": {"values": ["audit_db", "governance_db"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["compliance_officers", "internal_audit"],
                "users": ["chief_compliance_officer"],
                "accesses": [{"type": "select", "isAllowed": True}, {"type": "read", "isAllowed": True}],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [], "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 114, "name": "vendor_external_limited",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 0,
            "description": "External vendor access - strictly limited",
            "resources": {
                "database": {"values": ["vendor_integration_db"]},
                "table": {"values": ["vendor_orders", "vendor_catalog", "price_list"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [{
                "groups": ["external_vendor_readonly"], "users": ["vendor_api_svc"],
                "accesses": [{"type": "select", "isAllowed": True}],
                "delegateAdmin": False,
            }],
            "denyPolicyItems": [{
                "groups": ["external_vendor_readonly"], "users": ["vendor_api_svc"],
                "accesses": [
                    {"type": "update", "isAllowed": True}, {"type": "create", "isAllowed": True},
                    {"type": "drop", "isAllowed": True}, {"type": "alter", "isAllowed": True},
                ],
                "delegateAdmin": False,
            }],
            "rowFilterPolicyItems": [], "dataMaskPolicyItems": [],
        },
        {
            "id": 115, "name": "compensation_data_masking",
            "isEnabled": True, "isAuditEnabled": True, "policyType": 1,
            "description": "Mask compensation figures for non-HR/exec users",
            "resources": {
                "database": {"values": ["hr_db"]},
                "table": {"values": ["compensation"]},
                "column": {"values": ["base_salary", "bonus_amount", "equity_grants", "total_compensation"]},
            },
            "policyItems": [], "denyPolicyItems": [], "rowFilterPolicyItems": [],
            "dataMaskPolicyItems": [
                {
                    "groups": ["hr_admins", "executive_team"], "users": ["cfo"],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_NONE", "valueExpr": ""},
                },
                {
                    "groups": ["hr_business_partners"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK", "valueExpr": ""},
                },
                {
                    "groups": ["bi_analysts"], "users": [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                    "dataMaskInfo": {"dataMaskType": "MASK_NULL", "valueExpr": ""},
                },
            ],
        },
    ],
}
