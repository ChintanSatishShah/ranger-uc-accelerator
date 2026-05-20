# Ranger → Unity Catalog Migration Accelerator (Streamlit)

Streamlit port of the Ranger → Unity Catalog migration tool. Converts Apache
Ranger policies (Cloudera CDP / HDP / standalone) into Databricks Unity Catalog
SQL — with gap analysis, identity mapping, and a deployment checklist.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501

## Workflow

| Step | Page | Description |
|------|------|-------------|
| 1 | **Upload** (home) | Parse Ranger JSON export or load the built-in 15-policy sample |
| 2 | **Identity Mapping** | Map Ranger groups/users to Databricks principals, flag Kerberos issues |
| 3 | **Review Policies** | Filter / approve / reject parsed policy items with SQL preview |
| 4 | **Generate SQL** | Full Unity Catalog migration script — GRANTs, row filters, column masks |
| 5 | **Gap Analysis** | Deny policies, Kerberos issues, delegate admin, wildcards, readiness score |
| 6 | **Deploy** | 5-phase deployment checklist with SQL snippets and Databricks doc links |

## Supported Ranger Policy Types

- Resource-based grants (SELECT, MODIFY, CREATE, DROP, ALTER, ALL)
- Row-level filters → UC SQL filter functions
- Column masking (MASK, LAST_4, HASH, NULL, NONE) → UC mask functions
- Delegate admin detection → UC MANAGE privilege advisory
- Kerberos principal and service account detection

## How to Export Ranger Policies

```bash
curl -u admin:password \
  "https://<ranger-host>:6080/service/plugins/policies/exportJson?serviceName=<hive-service>" \
  -o ranger_policies.json
```

Works with Cloudera CDP 7.x, HDP 2.x/3.x, and standalone Apache Ranger 2.x.

## Project Layout

```
ranger-migrator-streamlit/
├── app.py                    # Upload page (home / entrypoint)
├── pages/
│   ├── 1_Identity_Mapping.py
│   ├── 2_Review_Policies.py
│   ├── 3_Generate_SQL.py
│   ├── 4_Gap_Analysis.py
│   └── 5_Deploy.py
├── lib/
│   ├── ranger_parser.py      # Parser + UC SQL generator + gap analyzer
│   ├── sample_data.py        # 15-policy Cloudera CDP sample
│   └── state.py              # Session-state helpers
├── .streamlit/config.toml
├── requirements.txt
└── README.md
```
