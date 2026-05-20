"""Ranger → Unity Catalog policy parser, SQL generator, and gap analyzer.

Python port of ranger-migrator/lib/ranger-parser.js.
"""
from __future__ import annotations

import re
from typing import Any

# ─── Ranger Access Type → Unity Catalog Privilege ────────────────────
ACCESS_MAP: dict[str, str] = {
    "select": "SELECT",
    "read": "SELECT",
    "update": "MODIFY",
    "create": "CREATE",
    "drop": "DROP",
    "alter": "ALTER",
    "all": "ALL PRIVILEGES",
    "write": "MODIFY",
    "index": "SELECT",
    "lock": "SELECT",
    "execute": "EXECUTE",
}

MASK_TYPE_MAP: dict[str, str] = {
    "MASK": "REDACT",
    "MASK_SHOW_LAST_4": "LAST_4",
    "MASK_SHOW_FIRST_4": "FIRST_4",
    "MASK_HASH": "HASH",
    "MASK_NONE": "NONE",
    "MASK_DATE_SHOW_YEAR": "DATE_YEAR",
    "MASK_NULL": "NULLIFY",
}

SEVERITY = {
    "info": "info",
    "warning": "warning",
    "error": "error",
    "critical": "critical",
}


def _principals(groups: list[str], users: list[str]) -> list[dict[str, str]]:
    return (
        [{"type": "group", "name": g} for g in groups]
        + [{"type": "user", "name": u} for u in users]
    )


def _flatten_users(policy: dict[str, Any]) -> list[str]:
    keys = ("policyItems", "denyPolicyItems", "dataMaskPolicyItems", "rowFilterPolicyItems")
    out: list[str] = []
    for k in keys:
        for item in policy.get(k) or []:
            out.extend(item.get("users") or [])
    return out


def _allowed_accesses(item: dict[str, Any]) -> list[str]:
    return [
        ACCESS_MAP.get(a["type"], a["type"].upper())
        for a in (item.get("accesses") or [])
        if a.get("isAllowed")
    ]


def parse_ranger_policies(json_data: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Parse a Ranger export and return normalized policy items, warnings, etc."""
    if isinstance(json_data, list):
        policies = json_data
        service_name = "unknown"
        service_type = "hive"
        cluster_name = "unknown"
    else:
        policies = json_data.get("policies") or []
        service_name = json_data.get("serviceName", "unknown")
        service_type = json_data.get("serviceType", "hive")
        cluster_name = json_data.get("clusterName", "unknown")

    catalog = "main"
    results: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()  # (type, name)
    kerberos_issues: list[dict[str, Any]] = []

    for policy in policies:
        resources = policy.get("resources") or {}
        dbs = (resources.get("database") or {}).get("values") or ["default"]
        tables = (resources.get("table") or {}).get("values") or ["*"]
        columns = (resources.get("column") or {}).get("values") or ["*"]
        is_enabled = policy.get("isEnabled", True) is not False
        item_counter = 0  # Counter for unique IDs within each policy

        if not is_enabled:
            warnings.append({
                "policyId": policy.get("id"),
                "policyName": policy.get("name"),
                "type": "info",
                "severity": SEVERITY["info"],
                "message": f'Policy "{policy.get("name")}" is disabled in Ranger — will be skipped unless manually enabled',
                "recommendation": "Review if this policy is still needed before migration. If deprecated, exclude it.",
            })

        # Kerberos / service account detection
        for user in _flatten_users(policy):
            looks_kerb = (
                "/" in user
                or "@" in user
                or user.endswith("_svc")
                or user.endswith("_service_account")
                or user.startswith("svc_")
            )
            if not looks_kerb:
                continue
            principal_type = (
                "kerberos_principal" if "@" in user
                else "kerberos_service" if "/" in user
                else "service_account"
            )
            kerberos_issues.append({
                "policyId": policy.get("id"),
                "policyName": policy.get("name"),
                "principal": user,
                "type": principal_type,
                "severity": SEVERITY["warning"],
                "message": (
                    f'"{user}" looks like a '
                    f'{"Kerberos principal" if "@" in user else "service account"} — '
                    "needs mapping to Databricks service principal or managed identity"
                ),
                "recommendation": (
                    "Map to a Databricks user via SCIM/IdP integration. Remove the Kerberos realm suffix."
                    if "@" in user
                    else "Create a corresponding Databricks service principal and use OAuth M2M tokens instead of keytabs."
                ),
            })

        # ── Resource-based grants ──
        for item in policy.get("policyItems") or []:
            principals = _principals(item.get("groups") or [], item.get("users") or [])
            accesses = list(dict.fromkeys(_allowed_accesses(item)))
            for p in principals:
                identities.add((p["type"], p["name"]))

            for db in dbs:
                for tbl in tables:
                    for principal in principals:
                        item_counter += 1
                        results.append({
                            "id": f'{policy.get("id")}-grant-{db}-{tbl}-{principal["name"]}-{item_counter}',
                            "rangerPolicyId": policy.get("id"),
                            "rangerPolicyName": policy.get("name"),
                            "rangerPolicyDesc": policy.get("description", ""),
                            "type": "grant",
                            "catalog": catalog,
                            "schema": db,
                            "table": None if tbl == "*" else tbl,
                            "columns": None if columns[0] == "*" else columns,
                            "privileges": accesses,
                            "principal": principal,
                            "delegateAdmin": item.get("delegateAdmin", False),
                            "enabled": is_enabled,
                            "status": "pending",
                        })

        # ── Deny policies ──
        for item in policy.get("denyPolicyItems") or []:
            principals = _principals(item.get("groups") or [], item.get("users") or [])
            accesses = _allowed_accesses(item)
            for p in principals:
                identities.add((p["type"], p["name"]))

            for db in dbs:
                for tbl in tables:
                    for principal in principals:
                        item_counter += 1
                        warnings.append({
                            "policyId": policy.get("id"),
                            "policyName": policy.get("name"),
                            "type": "warning",
                            "severity": SEVERITY["critical"],
                            "message": (
                                f'DENY policy for {principal["name"]} on {db}.{tbl or "*"} '
                                f'[{", ".join(accesses)}] — Unity Catalog has no DENY mechanism'
                            ),
                            "recommendation": (
                                "Restructure: move sensitive data into a separate schema with restricted grants, "
                                "or use row filters/column masks to limit visibility instead of denying access."
                            ),
                        })
                        results.append({
                            "id": f'{policy.get("id")}-deny-{db}-{tbl}-{principal["name"]}-{item_counter}',
                            "rangerPolicyId": policy.get("id"),
                            "rangerPolicyName": policy.get("name"),
                            "rangerPolicyDesc": policy.get("description", ""),
                            "type": "deny",
                            "catalog": catalog,
                            "schema": db,
                            "table": None if tbl == "*" else tbl,
                            "columns": None,
                            "privileges": accesses,
                            "principal": principal,
                            "enabled": is_enabled,
                            "status": "needs_review",
                        })

        # ── Row filters ──
        for item in policy.get("rowFilterPolicyItems") or []:
            principals = _principals(item.get("groups") or [], item.get("users") or [])
            for p in principals:
                identities.add((p["type"], p["name"]))
            row_info = item.get("rowFilterInfo") or {}

            for db in dbs:
                for tbl in tables:
                    item_counter += 1
                    primary = principals[0] if principals else {"type": "group", "name": "ALL"}
                    results.append({
                        "id": f'{policy.get("id")}-rowfilter-{db}-{tbl}-{primary["name"]}-{item_counter}',
                        "rangerPolicyId": policy.get("id"),
                        "rangerPolicyName": policy.get("name"),
                        "rangerPolicyDesc": policy.get("description", ""),
                        "type": "row_filter",
                        "catalog": catalog,
                        "schema": db,
                        "table": tbl,
                        "columns": None,
                        "privileges": [],
                        "principal": primary,
                        "allPrincipals": principals,
                        "filterExpr": row_info.get("filterExpr", ""),
                        "enabled": is_enabled,
                        "status": "needs_review",
                    })

        # ── Data masking ──
        for item in policy.get("dataMaskPolicyItems") or []:
            principals = _principals(item.get("groups") or [], item.get("users") or [])
            for p in principals:
                identities.add((p["type"], p["name"]))
            mask_info = item.get("dataMaskInfo") or {}

            for db in dbs:
                for tbl in tables:
                    for col in columns:
                        item_counter += 1
                        primary = principals[0] if principals else {"type": "group", "name": "ALL"}
                        results.append({
                            "id": f'{policy.get("id")}-mask-{db}-{tbl}-{col}-{primary["name"]}-{item_counter}',
                            "rangerPolicyId": policy.get("id"),
                            "rangerPolicyName": policy.get("name"),
                            "rangerPolicyDesc": policy.get("description", ""),
                            "type": "column_mask",
                            "catalog": catalog,
                            "schema": db,
                            "table": tbl,
                            "columns": [col],
                            "privileges": [],
                            "principal": primary,
                            "allPrincipals": principals,
                            "maskType": mask_info.get("dataMaskType", "MASK"),
                            "maskExpr": mask_info.get("valueExpr", ""),
                            "enabled": is_enabled,
                            "status": "needs_review",
                        })

    return {
        "results": results,
        "warnings": warnings,
        "identities": [{"type": t, "name": n} for (t, n) in sorted(identities, key=lambda x: (x[0], x[1]))],
        "kerberosIssues": kerberos_issues,
        "serviceName": service_name,
        "serviceType": service_type,
        "clusterName": cluster_name,
        "totalRangerPolicies": len(policies),
    }


# ─── Generate Unity Catalog SQL ──────────────────────────────────────
_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_]")


def _safe(name: str) -> str:
    return _SAFE_NAME_RE.sub("_", name)


def generate_uc_sql(
    item: dict[str, Any],
    identity_map: dict[str, str] | None = None,
    catalog_name: str = "main",
) -> str:
    identity_map = identity_map or {}
    cat = catalog_name or item.get("catalog") or "main"
    raw_principal = (item.get("principal") or {}).get("name") or "unknown"
    principal_name = identity_map.get(raw_principal, raw_principal)
    principal = f"`{principal_name}`"
    schema = item.get("schema")
    table = item.get("table")
    lines: list[str] = []
    t = item.get("type")

    if t == "grant":
        target = (
            f"TABLE {cat}.{schema}.{table}" if table else f"SCHEMA {cat}.{schema}"
        )
        if not table:
            lines.append(f"GRANT USE CATALOG ON CATALOG {cat} TO {principal};")
            lines.append(f"GRANT USE SCHEMA ON SCHEMA {cat}.{schema} TO {principal};")
        for priv in item.get("privileges") or []:
            lines.append(f"GRANT {priv} ON {target} TO {principal};")
        if item.get("delegateAdmin"):
            lines.append(
                f"-- Note: delegateAdmin=true in Ranger. "
                f"Consider granting MANAGE on {target} if admin delegation is needed."
            )

    elif t == "deny":
        privs = ", ".join(item.get("privileges") or [])
        lines.append("-- ⛔ DENY NOT SUPPORTED IN UNITY CATALOG")
        lines.append(
            f"-- Original Ranger deny: {privs} on {cat}.{schema}.{table or '*'} for {principal_name}"
        )
        lines.append("--")
        lines.append("-- RECOMMENDED ACTIONS:")
        lines.append(f"-- 1. Remove {principal_name} from the group that grants broad access")
        lines.append("-- 2. Create a restricted schema and grant only specific tables")
        lines.append("-- 3. Use row filters / column masks for fine-grained control")
        lines.append("-- 4. If this was a safety-net deny, the UC additive model makes it unnecessary")
        lines.append("--    as long as you don't grant the denied privileges in the first place")

    elif t == "row_filter":
        fn = f"{cat}.{schema}.rf_{table}_{_safe(principal_name)}"
        expr = item.get("filterExpr") or "TRUE"
        lines.append(f"-- Row Filter for: {principal_name}")
        lines.append(f"-- Original expression: {expr}")
        lines.append("")
        lines.append(f"CREATE OR REPLACE FUNCTION {fn}()")
        lines.append("RETURNS BOOLEAN")
        lines.append("RETURN IF(")
        lines.append(f"  IS_ACCOUNT_GROUP_MEMBER('{principal_name}'),")
        lines.append(f"  {expr},")
        lines.append("  TRUE  -- Allow all for non-matching groups (adjust as needed)")
        lines.append(");")
        lines.append("")
        lines.append(f"ALTER TABLE {cat}.{schema}.{table}")
        lines.append(f"SET ROW FILTER {fn} ON ();")

    elif t == "column_mask":
        mask_uc = MASK_TYPE_MAP.get(item.get("maskType") or "MASK", "REDACT")
        col = (item.get("columns") or ["col"])[0]
        fn = f"{cat}.{schema}.mask_{table}_{col}_{_safe(principal_name)}"

        if mask_uc == "NONE":
            lines.append(f"-- ✅ No masking for {principal_name} on {col} (full access granted)")
            lines.append("-- No SQL needed — this principal sees unmasked data")
        elif mask_uc == "LAST_4":
            lines.append(f"-- Column Mask: Show last 4 characters for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  IS_ACCOUNT_GROUP_MEMBER('{principal_name}'),")
            lines.append("  CONCAT('***-**-', RIGHT(val, 4)),")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {cat}.{schema}.{table}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        elif mask_uc == "HASH":
            lines.append(f"-- Column Mask: SHA-256 hash for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  IS_ACCOUNT_GROUP_MEMBER('{principal_name}'),")
            lines.append("  SHA2(val, 256),")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {cat}.{schema}.{table}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        elif mask_uc == "NULLIFY":
            lines.append(f"-- Column Mask: NULL value for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  IS_ACCOUNT_GROUP_MEMBER('{principal_name}'),")
            lines.append("  NULL,")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {cat}.{schema}.{table}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        else:
            lines.append(f"-- Column Mask: Full redaction for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  IS_ACCOUNT_GROUP_MEMBER('{principal_name}'),")
            lines.append("  '***REDACTED***',")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {cat}.{schema}.{table}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")

    return "\n".join(lines)


def generate_full_script(
    policy_items: list[dict[str, Any]],
    identity_map: dict[str, str],
    catalog_name: str,
    service_name: str,
    today: str,
) -> str:
    eligible = [p for p in policy_items if p.get("status") in ("approved", "needs_review")]
    header = (
        "-- ╔═══════════════════════════════════════════════════════════╗\n"
        "-- ║  Unity Catalog Migration Script                          ║\n"
        "-- ║  Generated by Ranger → UC Migrator                       ║\n"
        f"-- ║  Source: {service_name}\n"
        f"-- ║  Target Catalog: {catalog_name}\n"
        f"-- ║  Date: {today}\n"
        f"-- ║  Policies: {len(eligible)} of {len(policy_items)}\n"
        "-- ╚═══════════════════════════════════════════════════════════╝\n\n"
    )
    blocks: list[str] = []
    for item in eligible:
        sql = generate_uc_sql(item, identity_map, catalog_name)
        blocks.append(
            "-- ═══════════════════════════════════════════════════════\n"
            f"-- Policy: {item.get('rangerPolicyName')} (Ranger ID: {item.get('rangerPolicyId')})\n"
            f"-- Type: {str(item.get('type')).upper()} | Principal: {item.get('principal', {}).get('name')}\n"
            "-- ═══════════════════════════════════════════════════════\n"
            f"{sql}\n"
        )
    return header + "\n".join(blocks)


# ─── Gap Analysis ────────────────────────────────────────────────────
def generate_gap_analysis(
    parsed_data: dict[str, Any],
    identity_map: dict[str, str] | None = None,
    catalog_name: str = "main",
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    results = parsed_data.get("results") or []
    kerberos_issues = parsed_data.get("kerberosIssues") or []

    deny_policies = [r for r in results if r.get("type") == "deny"]
    if deny_policies:
        gaps.append({
            "category": "Deny Policies",
            "severity": "critical",
            "count": len(deny_policies),
            "description": "Unity Catalog uses an additive (allowlist) permission model with no DENY mechanism.",
            "items": [
                {
                    "resource": f'{d.get("schema")}.{d.get("table") or "*"}',
                    "principal": d.get("principal", {}).get("name"),
                    "detail": f'Denied: {", ".join(d.get("privileges") or [])}',
                }
                for d in deny_policies
            ],
            "remediation": (
                "Restructure into separate schemas with restricted grants. "
                "Use row filters for partial access. Remove principals from over-privileged groups."
            ),
        })

    if kerberos_issues:
        gaps.append({
            "category": "Kerberos / Service Accounts",
            "severity": "critical",
            "count": len(kerberos_issues),
            "description": (
                "Kerberos principals and service accounts need to be mapped to Databricks "
                "service principals or cloud managed identities."
            ),
            "items": [
                {
                    "resource": k.get("policyName"),
                    "principal": k.get("principal"),
                    "detail": (
                        "Kerberos realm principal"
                        if k.get("type") == "kerberos_principal"
                        else "Service account (keytab-based)"
                    ),
                }
                for k in kerberos_issues
            ],
            "remediation": (
                "Create Databricks service principals for each service account. "
                "Configure OAuth M2M authentication. Sync user principals via SCIM from your IdP."
            ),
        })

    delegate_admins = [r for r in results if r.get("delegateAdmin")]
    if delegate_admins:
        gaps.append({
            "category": "Delegate Admin",
            "severity": "warning",
            "count": len(delegate_admins),
            "description": (
                "Ranger delegateAdmin allows principals to manage policies for their resources. "
                "Unity Catalog uses MANAGE privilege instead."
            ),
            "items": [
                {
                    "resource": f'{d.get("schema")}.{d.get("table") or "*"}',
                    "principal": d.get("principal", {}).get("name"),
                    "detail": "Has delegateAdmin in Ranger",
                }
                for d in delegate_admins
            ],
            "remediation": (
                "Grant MANAGE privilege on the corresponding UC object, or assign the principal "
                "as a metastore/catalog admin if broader admin access is needed."
            ),
        })

    wildcard_policies = [r for r in results if r.get("table") is None and r.get("type") == "grant"]
    if wildcard_policies:
        gaps.append({
            "category": "Wildcard Table Access",
            "severity": "warning",
            "count": len(wildcard_policies),
            "description": (
                "Ranger wildcard table policies (database.*) translate to schema-level grants in UC. "
                "Verify this is intentional."
            ),
            "items": [
                {
                    "resource": f'{w.get("schema")}.*',
                    "principal": w.get("principal", {}).get("name"),
                    "detail": f'Privileges: {", ".join(w.get("privileges") or [])}',
                }
                for w in wildcard_policies
            ],
            "remediation": (
                "Review if schema-level grants are appropriate. "
                "Consider granting on specific tables for least-privilege access."
            ),
        })

    disabled = [r for r in results if not r.get("enabled")]
    if disabled:
        gaps.append({
            "category": "Disabled Policies",
            "severity": "info",
            "count": len(disabled),
            "description": "These policies are disabled in Ranger and will not be migrated by default.",
            "items": [
                {
                    "resource": f'{d.get("schema")}.{d.get("table") or "*"}',
                    "principal": d.get("principal", {}).get("name"),
                    "detail": f'Policy: {d.get("rangerPolicyName")}',
                }
                for d in disabled[:10]
            ],
            "remediation": "Confirm these are intentionally disabled. Remove from migration scope or re-enable if still needed.",
        })

    row_filters = [r for r in results if r.get("type") == "row_filter"]
    if row_filters:
        gaps.append({
            "category": "Row Filter Translation",
            "severity": "warning",
            "count": len(row_filters),
            "description": (
                "Ranger row filters translate to UC SQL functions. "
                "Complex expressions may need manual adjustment."
            ),
            "items": [
                {
                    "resource": f'{r.get("schema")}.{r.get("table")}',
                    "principal": r.get("principal", {}).get("name"),
                    "detail": f'Filter: {r.get("filterExpr")}',
                }
                for r in row_filters
            ],
            "remediation": (
                "Review generated filter functions. Test with sample queries to verify filter "
                "behavior matches Ranger. Watch for UDF dependencies."
            ),
        })

    return gaps


# ─── Statistics ──────────────────────────────────────────────────────
def calculate_stats(policy_items: list[dict[str, Any]]) -> dict[str, Any]:
    stats = {
        "total": len(policy_items),
        "grants": 0, "denies": 0, "rowFilters": 0, "masks": 0,
        "approved": 0, "needsReview": 0, "pending": 0, "rejected": 0,
        "disabled": 0,
    }
    schemas: set[str] = set()
    principals: set[str] = set()
    for p in policy_items:
        t = p.get("type")
        if t == "grant": stats["grants"] += 1
        elif t == "deny": stats["denies"] += 1
        elif t == "row_filter": stats["rowFilters"] += 1
        elif t == "column_mask": stats["masks"] += 1

        s = p.get("status")
        if s == "approved": stats["approved"] += 1
        elif s == "needs_review": stats["needsReview"] += 1
        elif s == "pending": stats["pending"] += 1
        elif s == "rejected": stats["rejected"] += 1

        if not p.get("enabled"):
            stats["disabled"] += 1
        if p.get("schema"):
            schemas.add(p["schema"])
        pname = (p.get("principal") or {}).get("name")
        if pname:
            principals.add(pname)

    stats["schemaCount"] = len(schemas)
    stats["principalCount"] = len(principals)
    stats["schemas"] = sorted(schemas)
    stats["principals"] = sorted(principals)
    return stats
