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
    "CUSTOM": "CUSTOM",
}

# SQL keywords and UC built-in functions that are NOT column references.
# Used by _fix_custom_mask_expr to detect bare column refs in custom expressions.
_SQL_BUILTINS: frozenset[str] = frozenset({
    "case", "when", "then", "else", "end", "and", "or", "not", "is", "in",
    "like", "between", "as", "null", "true", "false", "val",
    "cast", "try_cast", "if", "coalesce", "ifnull", "nvl", "greatest", "least", "nullif",
    "left", "right", "concat", "concat_ws", "length", "len", "substr", "substring",
    "sha2", "sha", "md5", "year", "month", "day", "hour", "minute", "second",
    "make_date", "date", "repeat", "lpad", "rpad",
    "upper", "lower", "trim", "ltrim", "rtrim", "replace", "regexp_replace",
    "to_date", "to_timestamp", "date_format", "datediff", "add_months",
    "string", "int", "integer", "bigint", "smallint", "tinyint",
    "double", "float", "real", "boolean", "decimal", "numeric",
    "array", "map", "struct", "current_user",
})

HDFS_ACCESS_MAP: dict[str, str] = {
    "read": "READ FILES",
    "write": "WRITE FILES",
    "execute": "READ FILES",
    "all": "ALL PRIVILEGES",
}

HBASE_ACCESS_MAP: dict[str, str] = {
    "read": "SELECT",
    "write": "MODIFY",
    "create": "CREATE",
    "admin": "ALL PRIVILEGES",
    "all": "ALL PRIVILEGES",
}

SEVERITY = {
    "info": "info",
    "warning": "warning",
    "error": "error",
    "critical": "critical",
}


def _principals(groups: list[str], users: list[str], roles: list[str] | None = None) -> list[dict[str, str]]:
    # Strip empty/whitespace-only names — they produce `unknown` principals and invalid SQL
    return (
        [{"type": "group", "name": g} for g in groups if g and g.strip()]
        + [{"type": "user", "name": u} for u in users if u and u.strip()]
        + [{"type": "role", "name": r} for r in (roles or []) if r and r.strip()]
    )


def _blank_principals(groups: list[str], users: list[str], roles: list[str] | None = None) -> list[str]:
    """Return a list of labels for any blank/empty principal entries in the raw Ranger lists."""
    blanks = []
    for i, u in enumerate(users):
        if not (u and u.strip()):
            blanks.append(f"users[{i}] is empty")
    for i, g in enumerate(groups):
        if not (g and g.strip()):
            blanks.append(f"groups[{i}] is empty")
    for i, r in enumerate(roles or []):
        if not (r and r.strip()):
            blanks.append(f"roles[{i}] is empty")
    return blanks


def _blank_advisory_item(
    policy: dict[str, Any],
    raw_item: dict[str, Any],
    catalog: str,
    schema: str | None,
    table: str | None,
    counter: int,
) -> dict[str, Any] | None:
    """Return a skipped_blank_principal result item if the raw policy item had blank entries, else None."""
    blanks = _blank_principals(
        raw_item.get("groups") or [], raw_item.get("users") or [], raw_item.get("roles")
    )
    if not blanks:
        return None
    return {
        "id": f'{policy.get("id")}-blank-{counter}',
        "rangerPolicyId": policy.get("id"),
        "rangerPolicyName": policy.get("name"),
        "rangerPolicyDesc": policy.get("description", ""),
        "type": "skipped_blank_principal",
        "catalog": catalog,
        "schema": schema,
        "table": table,
        "blanks": blanks,
        "enabled": True,
        "status": "needs_review",
    }


def _flatten_users(policy: dict[str, Any]) -> list[str]:
    keys = ("policyItems", "denyPolicyItems", "dataMaskPolicyItems", "rowFilterPolicyItems")
    out: list[str] = []
    for k in keys:
        for item in policy.get(k) or []:
            out.extend(item.get("users") or [])
    return out


def _allowed_accesses(item: dict[str, Any]) -> list[str]:
    # isAllowed defaults to True when absent — Ranger omits it in many exports
    return [
        ACCESS_MAP.get(a["type"], a["type"].upper())
        for a in (item.get("accesses") or [])
        if a.get("isAllowed", True)
    ]


def parse_ranger_policies(json_data: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Parse a Ranger export and return normalized policy items, warnings, etc."""
    # Unwrap Ranger ACL provider test format: { testCases: [{ servicePolicies: {...} }] }
    if isinstance(json_data, dict) and "testCases" in json_data:
        test_cases = json_data.get("testCases") or []
        if test_cases and isinstance(test_cases[0], dict) and "servicePolicies" in test_cases[0]:
            json_data = test_cases[0]["servicePolicies"]

    if isinstance(json_data, list):
        policies = json_data
        service_name = "unknown"
        service_type = "hive"
        cluster_name = "unknown"
    else:
        policies = json_data.get("policies") or []
        service_name = json_data.get("serviceName", "unknown")
        _st = (json_data.get("serviceType") or "").lower()
        if not _st:
            _sn = service_name.lower()
            _first_resources = ((json_data.get("policies") or [{}])[0].get("resources") or {})
            if "hdfs" in _sn or "hadoop" in _sn or "path" in _first_resources:
                _st = "hdfs"
            elif "hbase" in _sn or (
                "table" in _first_resources and "column-family" in _first_resources
            ):
                _st = "hbase"
            else:
                _st = "hive"
        service_type = _st
        cluster_name = json_data.get("clusterName", "unknown")

    catalog = "main"
    results: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()  # (type, name)
    kerberos_issues: list[dict[str, Any]] = []

    # ── Tag metadata: tagDefinitions + resourceTags (top-level fields) ───────
    tag_definitions: dict[str, Any] = {}
    tag_to_resources: dict[str, list[dict[str, Any]]] = {}  # tag_name → [{schema,table,column}]

    if isinstance(json_data, dict):
        raw_td = json_data.get("tagDefinitions") or {}
        if isinstance(raw_td, dict):
            tag_definitions = raw_td
        elif isinstance(raw_td, list):
            tag_definitions = {t["name"]: t for t in raw_td if isinstance(t, dict) and "name" in t}

        raw_rt = json_data.get("resourceTags") or {}
        resource_tags_dict: dict[str, list] = raw_rt if isinstance(raw_rt, dict) else {}

        for res_path, tn_val in resource_tags_dict.items():
            tn_list = tn_val if isinstance(tn_val, list) else [tn_val]
            parts = res_path.split(".")
            if len(parts) == 3:
                rt_schema, rt_table, rt_col = parts[0], parts[1], parts[2]
            elif len(parts) == 2:
                rt_schema, rt_table, rt_col = parts[0], parts[1], None
            else:
                continue
            for tn in tn_list:
                tag_to_resources.setdefault(tn, []).append(
                    {"schema": rt_schema, "table": rt_table, "column": rt_col}
                )

        # Generate tag_set items (ALTER TABLE / ALTER COLUMN SET TAGS)
        for res_path, tn_val in resource_tags_dict.items():
            tn_list = tn_val if isinstance(tn_val, list) else [tn_val]
            parts = res_path.split(".")
            if len(parts) == 3:
                ts_schema, ts_table, ts_col = parts[0], parts[1], parts[2]
            elif len(parts) == 2:
                ts_schema, ts_table, ts_col = parts[0], parts[1], None
            else:
                continue
            tag_attrs: dict[str, str] = {}
            for tn in tn_list:
                tag_attrs[tn] = "true"
                for k, v in (tag_definitions.get(tn, {}).get("attributeDefs") or {}).items():
                    tag_attrs[k] = str(v)
            results.append({
                "id": f"tag_set_{ts_schema}_{ts_table}_{ts_col or 'tbl'}",
                "rangerPolicyId": None,
                "rangerPolicyName": f"SET TAGS — {res_path}",
                "rangerPolicyDesc": "",
                "type": "tag_set",
                "catalog": catalog,
                "schema": ts_schema,
                "table": ts_table,
                "column": ts_col,
                "tag_attrs": tag_attrs,
                "principal": {"type": "system", "name": ""},
                "enabled": True,
                "status": "pending",
            })

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

        # isDenyAllElse — default-deny semantics cannot be enforced in UC
        if policy.get("isDenyAllElse"):
            warnings.append({
                "policyId": policy.get("id"),
                "policyName": policy.get("name"),
                "category": "deny_all_else",
                "severity": SEVERITY["critical"],
                "message": (
                    f'Policy "{policy.get("name")}" uses isDenyAllElse=true — '
                    "all principals not explicitly listed are denied in Ranger; "
                    "UC grants do not enforce this restriction"
                ),
                "recommendation": (
                    "Audit all principals with access to this resource in UC. "
                    "Ensure only explicitly listed principals receive grants."
                ),
            })

        # Validity schedules — time-bound policies have no UC equivalent
        _schedules = policy.get("validitySchedules") or []
        if _schedules:
            _s0 = _schedules[0]
            warnings.append({
                "policyId": policy.get("id"),
                "policyName": policy.get("name"),
                "category": "validity_schedule",
                "severity": SEVERITY["warning"],
                "message": (
                    f'Policy "{policy.get("name")}" is time-limited in Ranger '
                    f'({_s0.get("startTime", "—")} → {_s0.get("endTime", "no end")}) '
                    "— UC grants are permanent"
                ),
                "recommendation": (
                    "Manage the grant lifecycle manually or via automation. "
                    "Revoke the grant in UC when the validity period ends."
                ),
            })

        # Conditions in policy items — IP-range, time-of-day, custom evaluators not translated
        _condition_types: set[str] = set()
        for _it in (
            (policy.get("policyItems") or [])
            + (policy.get("denyPolicyItems") or [])
            + (policy.get("rowFilterPolicyItems") or [])
            + (policy.get("dataMaskPolicyItems") or [])
        ):
            for _cond in (_it.get("conditions") or []):
                if _cond.get("type"):
                    _condition_types.add(_cond["type"])
        if _condition_types:
            warnings.append({
                "policyId": policy.get("id"),
                "policyName": policy.get("name"),
                "category": "conditions",
                "severity": SEVERITY["warning"],
                "message": (
                    f'Policy "{policy.get("name")}" has conditions '
                    f'[{", ".join(sorted(_condition_types))}] with no UC equivalent — '
                    "grants will apply unconditionally"
                ),
                "recommendation": (
                    "IP-range, time-based, and custom conditions cannot be enforced in UC. "
                    "Apply equivalent restrictions at the network or application layer."
                ),
            })

        # Blank / empty principal detection — empty string principals produce invalid SQL
        for _item_key in ("policyItems", "denyPolicyItems", "rowFilterPolicyItems", "dataMaskPolicyItems"):
            for _it in (policy.get(_item_key) or []):
                _blanks = _blank_principals(
                    _it.get("groups") or [], _it.get("users") or [], _it.get("roles")
                )
                if _blanks:
                    warnings.append({
                        "policyId": policy.get("id"),
                        "policyName": policy.get("name"),
                        "category": "blank_principal",
                        "severity": SEVERITY["warning"],
                        "message": (
                            f'Policy "{policy.get("name")}" contains blank principal entries '
                            f'({"; ".join(_blanks)}) — skipped, no SQL generated for these entries'
                        ),
                        "recommendation": (
                            "Review the Ranger policy and assign explicit user, group, or role names. "
                            "Blank principal entries are ignored during migration."
                        ),
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

        # ── Tag-based policies ───────────────────────────────────────────────
        tag_resource_vals = (resources.get("tag") or {}).get("values") or []
        if tag_resource_vals:
            def _resolve_tag_tables(tag_vals: list[str]) -> list[dict]:
                seen: set = set()
                out: list[dict] = []
                for tn in tag_vals:
                    for r in tag_to_resources.get(tn, []):
                        key = (r["schema"], r["table"])
                        if key not in seen:
                            seen.add(key)
                            out.append(r)
                return out

            # Access grants
            for item in policy.get("policyItems") or []:
                principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
                accesses = list(dict.fromkeys(_allowed_accesses(item)))
                for p in principals:
                    identities.add((p["type"], p["name"]))
                resolved = _resolve_tag_tables(tag_resource_vals)
                if resolved:
                    for res in resolved:
                        for principal in principals:
                            item_counter += 1
                            results.append({
                                "id": f'{policy.get("id")}-tag_grant-{res["schema"]}-{res["table"]}-{principal["name"]}-{item_counter}',
                                "rangerPolicyId": policy.get("id"),
                                "rangerPolicyName": policy.get("name"),
                                "rangerPolicyDesc": policy.get("description", ""),
                                "type": "tag_grant",
                                "catalog": catalog,
                                "schema": res["schema"],
                                "table": res["table"],
                                "columns": None,
                                "privileges": accesses,
                                "principal": principal,
                                "tag_names": tag_resource_vals,
                                "delegateAdmin": item.get("delegateAdmin", False),
                                "enabled": is_enabled,
                                "status": "pending",
                            })
                else:
                    for principal in principals:
                        item_counter += 1
                        results.append({
                            "id": f'{policy.get("id")}-tag_placeholder-{principal["name"]}-{item_counter}',
                            "rangerPolicyId": policy.get("id"),
                            "rangerPolicyName": policy.get("name"),
                            "rangerPolicyDesc": policy.get("description", ""),
                            "type": "tag_placeholder",
                            "tag_names": tag_resource_vals,
                            "privileges": accesses,
                            "principal": principal,
                            "schema": None, "table": None,
                            "enabled": is_enabled,
                            "status": "needs_review",
                        })

            # Row filters on tag policies
            for item in policy.get("rowFilterPolicyItems") or []:
                principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
                for p in principals:
                    identities.add((p["type"], p["name"]))
                row_info = item.get("rowFilterInfo") or {}
                primary = principals[0] if principals else {"type": "group", "name": "ALL"}
                tag_tables = _resolve_tag_tables(tag_resource_vals) or [
                    {"schema": f"<schema_with_{'_'.join(tag_resource_vals)}>",
                     "table": f"<table_with_{'_'.join(tag_resource_vals)}>", "column": None}
                ]
                for res in tag_tables:
                    item_counter += 1
                    results.append({
                        "id": f'{policy.get("id")}-rowfilter-tag-{res["table"]}-{primary["name"]}-{item_counter}',
                        "rangerPolicyId": policy.get("id"),
                        "rangerPolicyName": policy.get("name"),
                        "rangerPolicyDesc": policy.get("description", ""),
                        "type": "row_filter",
                        "catalog": catalog,
                        "schema": res["schema"],
                        "table": res["table"],
                        "columns": None, "privileges": [],
                        "principal": primary,
                        "allPrincipals": principals,
                        "filterExpr": row_info.get("filterExpr", ""),
                        "enabled": is_enabled,
                        "status": "needs_review",
                    })

            # Column masks on tag policies
            for item in policy.get("dataMaskPolicyItems") or []:
                principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
                for p in principals:
                    identities.add((p["type"], p["name"]))
                mask_info = item.get("dataMaskInfo") or {}
                primary = principals[0] if principals else {"type": "group", "name": "ALL"}
                tag_tables = _resolve_tag_tables(tag_resource_vals) or [
                    {"schema": f"<schema_with_{'_'.join(tag_resource_vals)}>",
                     "table": f"<table_with_{'_'.join(tag_resource_vals)}>", "column": None}
                ]
                for res in tag_tables:
                    col = res.get("column") or f"<col_with_{'_'.join(tag_resource_vals)}>"
                    item_counter += 1
                    results.append({
                        "id": f'{policy.get("id")}-mask-tag-{res["table"]}-{col}-{primary["name"]}-{item_counter}',
                        "rangerPolicyId": policy.get("id"),
                        "rangerPolicyName": policy.get("name"),
                        "rangerPolicyDesc": policy.get("description", ""),
                        "type": "column_mask",
                        "catalog": catalog,
                        "schema": res["schema"],
                        "table": res["table"],
                        "columns": [col], "privileges": [],
                        "principal": primary,
                        "allPrincipals": principals,
                        "maskType": mask_info.get("dataMaskType", "MASK"),
                        "maskExpr": mask_info.get("valueExpr", ""),
                        "enabled": is_enabled,
                        "status": "needs_review",
                    })

            continue  # skip Hive/HDFS/HBase resource processing

        # ── HDFS path grants → UC External Location ──
        if service_type == "hdfs":
            paths = (resources.get("path") or {}).get("values") or ["/"]
            is_recursive = (resources.get("path") or {}).get("isRecursive", False)
            for item in policy.get("policyItems") or []:
                principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
                accesses = list(dict.fromkeys(
                    HDFS_ACCESS_MAP.get(a["type"], a["type"].upper())
                    for a in (item.get("accesses") or [])
                    if a.get("isAllowed", True)
                ))
                for p in principals:
                    identities.add((p["type"], p["name"]))
                for path in paths:
                    for principal in principals:
                        item_counter += 1
                        results.append({
                            "id": f'{policy.get("id")}-hdfs-{principal["name"]}-{item_counter}',
                            "rangerPolicyId": policy.get("id"),
                            "rangerPolicyName": policy.get("name"),
                            "rangerPolicyDesc": policy.get("description", ""),
                            "type": "hdfs_grant",
                            "path": path,
                            "isRecursive": is_recursive,
                            "schema": None,
                            "table": None,
                            "privileges": accesses,
                            "principal": principal,
                            "delegateAdmin": item.get("delegateAdmin", False),
                            "enabled": is_enabled,
                            "status": "pending",
                        })
            continue  # no row filters or masks for HDFS

        # ── HBase table grants → UC table/schema grants ──
        if service_type == "hbase":
            hbase_tables = (resources.get("table") or {}).get("values") or ["*"]
            col_families = (resources.get("column-family") or {}).get("values") or ["*"]
            for item in policy.get("policyItems") or []:
                principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
                accesses = list(dict.fromkeys(
                    HBASE_ACCESS_MAP.get(a["type"], a["type"].upper())
                    for a in (item.get("accesses") or [])
                    if a.get("isAllowed", True)
                ))
                for p in principals:
                    identities.add((p["type"], p["name"]))
                for hbtbl in hbase_tables:
                    if ":" in hbtbl:
                        ns, tbl = hbtbl.split(":", 1)
                        tbl_resolved = None if tbl == "*" else tbl
                    elif hbtbl == "*":
                        ns, tbl_resolved = "_all_namespaces", None
                    else:
                        ns, tbl_resolved = "default", hbtbl
                    for principal in principals:
                        item_counter += 1
                        results.append({
                            "id": f'{policy.get("id")}-hbase-{principal["name"]}-{item_counter}',
                            "rangerPolicyId": policy.get("id"),
                            "rangerPolicyName": policy.get("name"),
                            "rangerPolicyDesc": policy.get("description", ""),
                            "type": "hbase_grant",
                            "catalog": catalog,
                            "schema": ns,
                            "table": tbl_resolved,
                            "col_families": col_families if col_families != ["*"] else [],
                            "privileges": accesses,
                            "principal": principal,
                            "delegateAdmin": item.get("delegateAdmin", False),
                            "enabled": is_enabled,
                            "status": "needs_review" if ns == "_all_namespaces" else "pending",
                        })
            continue  # no row filters or masks for HBase

        # ── URL resource → UC External Location grants (reuse hdfs_grant type) ──
        url_vals = (resources.get("url") or {}).get("values") or []
        if url_vals:
            for item in policy.get("policyItems") or []:
                principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
                accesses = list(dict.fromkeys(
                    HDFS_ACCESS_MAP.get(a["type"], "READ FILES")
                    for a in (item.get("accesses") or [])
                    if a.get("isAllowed", True)
                ))
                for p in principals:
                    identities.add((p["type"], p["name"]))
                for url_path in url_vals:
                    for principal in principals:
                        item_counter += 1
                        results.append({
                            "id": f'{policy.get("id")}-url-{principal["name"]}-{item_counter}',
                            "rangerPolicyId": policy.get("id"),
                            "rangerPolicyName": policy.get("name"),
                            "rangerPolicyDesc": policy.get("description", ""),
                            "type": "hdfs_grant",
                            "path": url_path,
                            "isRecursive": (resources.get("url") or {}).get("isRecursive", False),
                            "schema": None,
                            "table": None,
                            "privileges": accesses,
                            "principal": principal,
                            "delegateAdmin": item.get("delegateAdmin", False),
                            "enabled": is_enabled,
                            "status": "pending",
                        })
            continue  # no row filters or masks for URL policies

        # ── UDF resource → GRANT EXECUTE ON FUNCTION ──
        udf_vals = (resources.get("udf") or {}).get("values") or []
        if udf_vals:
            udf_dbs = (resources.get("database") or {}).get("values") or ["default"]
            for item in policy.get("policyItems") or []:
                principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
                for p in principals:
                    identities.add((p["type"], p["name"]))
                for udf_db in udf_dbs:
                    for udf_name in udf_vals:
                        for principal in principals:
                            item_counter += 1
                            results.append({
                                "id": f'{policy.get("id")}-udf-{udf_db}-{udf_name}-{principal["name"]}-{item_counter}',
                                "rangerPolicyId": policy.get("id"),
                                "rangerPolicyName": policy.get("name"),
                                "rangerPolicyDesc": policy.get("description", ""),
                                "type": "udf_grant",
                                "catalog": catalog,
                                "schema": udf_db,
                                "udf_name": udf_name,
                                "principal": principal,
                                "delegateAdmin": item.get("delegateAdmin", False),
                                "enabled": is_enabled,
                                "status": "pending",
                            })
            continue  # no row filters or masks for UDF policies

        # ── Resource-based grants (Hive / default) ──
        for item in policy.get("policyItems") or []:
            principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
            accesses = list(dict.fromkeys(_allowed_accesses(item)))
            for p in principals:
                identities.add((p["type"], p["name"]))

            for db in dbs:
                for tbl in tables:
                    item_counter += 1
                    adv = _blank_advisory_item(policy, item, catalog, db, None if tbl == "*" else tbl, item_counter)
                    if adv:
                        results.append(adv)
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
        # Parse denyExceptions once — these are the "except these principals" carve-outs
        deny_exceptions: list[dict] = []
        for _exc in policy.get("denyExceptions") or []:
            _exc_principals = _principals(
                _exc.get("groups") or [], _exc.get("users") or [], _exc.get("roles") or []
            )
            deny_exceptions.extend(_exc_principals)

        for item in policy.get("denyPolicyItems") or []:
            principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
            accesses = _allowed_accesses(item)
            conditions = item.get("conditions") or []
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
                            "columns": None if columns[0] == "*" else columns,
                            "privileges": accesses,
                            "principal": principal,
                            "conditions": conditions,
                            "denyExceptions": deny_exceptions,
                            "enabled": is_enabled,
                            "status": "needs_review",
                        })

        # ── Row filters ──
        for item in policy.get("rowFilterPolicyItems") or []:
            principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
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
            principals = _principals(item.get("groups") or [], item.get("users") or [], item.get("roles") or [])
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

# SQL keywords and built-ins that are NOT column references in filter expressions
_FILTER_NON_COLUMNS: frozenset[str] = frozenset({
    "select", "from", "where", "and", "or", "not", "in", "like", "is", "null",
    "true", "false", "between", "case", "when", "then", "else", "end", "if",
    "exists", "all", "any", "some", "union", "intersect", "except",
    "current_user", "current_date", "current_timestamp", "current_schema",
    "is_account_group_member",
})


def _extract_filter_columns(expr: str) -> list[str]:
    """Extract likely column names from a Ranger row filter expression.

    Returns an ordered, deduplicated list of identifiers that appear to be
    column references (not string literals, numeric literals, or SQL keywords).
    Falls back to an empty list when no column-like identifiers are found.
    """
    # Strip string literals to avoid treating values as identifiers
    cleaned = re.sub(r"'[^']*'", " ", expr)
    cleaned = re.sub(r'"[^"]*"', " ", cleaned)
    # Find all word-token identifiers
    tokens = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", cleaned)
    seen: set[str] = set()
    cols: list[str] = []
    for tok in tokens:
        if tok.lower() in _FILTER_NON_COLUMNS:
            continue
        if tok not in seen:
            seen.add(tok)
            cols.append(tok)
    return cols


def _safe(name: str) -> str:
    return _SAFE_NAME_RE.sub("_", name)


# Ranger request-context pattern: ${{USER.attr}}, ${{UGNAMES}}, ${{TAG.x}}, etc.
_REQUEST_CTX_RE = re.compile(r"\$\{\{[^}]+\}\}")

# Ranger column placeholder {col} and Ranger built-in mask UDFs (Hive-only, not in UC)
_RANGER_PLACEHOLDER_RE = re.compile(r"\{col\}", re.IGNORECASE)
_RANGER_MASK_BUILTINS_RE = re.compile(
    r"\b(mask|mask_first_n|mask_last_n|mask_show_first_n|mask_show_last_n|mask_hash)\s*\(",
    re.IGNORECASE,
)


def _ranger_expr_issues(expr: str) -> list[str]:
    """Return a list of human-readable issue descriptions for Ranger-specific constructs
    in a filter or mask expression that cannot be automatically translated to UC SQL."""
    issues: list[str] = []
    ctx_matches = _REQUEST_CTX_RE.findall(expr)
    if ctx_matches:
        attrs = ", ".join(dict.fromkeys(ctx_matches))  # deduplicated, order-preserving
        issues.append(
            f"Request-context attribute(s) {attrs}: Ranger substitutes these at query time "
            "from the user's identity attributes. Unity Catalog has no equivalent mechanism. "
            "Replace with IS_ACCOUNT_GROUP_MEMBER() checks or a lookup table join."
        )
    if _RANGER_PLACEHOLDER_RE.search(expr):
        issues.append(
            "{col}: Ranger column placeholder — not valid SQL. "
            "Replace with 'val' (the UC mask function parameter) or the literal column name."
        )
    builtins = _RANGER_MASK_BUILTINS_RE.findall(expr)
    if builtins:
        fns = ", ".join(dict.fromkeys(b.rstrip("(") for b in builtins))
        issues.append(
            f"Ranger/Hive built-in mask function(s): {fns}(). "
            "These are Hive UDFs not registered in Unity Catalog. "
            "Rewrite using UC-native expressions (CONCAT, LEFT, RIGHT, SHA2, etc.)."
        )
    # Strip string literals before checking for subquery keywords so that a
    # value like 'SELECT' inside an IN list doesn't trigger a false positive.
    _expr_no_literals = re.sub(r"'[^']*'", " ", expr)
    if re.search(r"\bSELECT\b", _expr_no_literals, re.IGNORECASE):
        issues.append(
            "Subquery detected (SELECT inside expression): Unity Catalog row filter "
            "functions do not support subqueries. Rewrite using a lookup table, "
            "IS_ACCOUNT_GROUP_MEMBER() checks, or a pre-computed membership column."
        )
    return issues


def _approx_ranger_mask_udf(expr: str) -> str | None:
    """Return a UC-native approximation of a Ranger built-in mask UDF call, or None if unrecognised.

    Substitutions (best-effort; always adds a review comment in the caller):
      mask_show_last_n(val, N, ...)  → CONCAT(REPEAT('x', GREATEST(0, LENGTH(val)-N)), RIGHT(val, N))
      mask_show_first_n(val, N, ...) → CONCAT(LEFT(val, N), REPEAT('x', GREATEST(0, LENGTH(val)-N)))
      mask_hash(val)                 → SHA2(val, 256)
      mask_first_n(val, N, ...)      → CONCAT(REPEAT('x', N), RIGHT(val, GREATEST(0, LENGTH(val)-N)))
      mask_last_n(val, N, ...)       → CONCAT(LEFT(val, GREATEST(0, LENGTH(val)-N)), REPEAT('x', N))
      mask(val, ...)                 → REGEXP_REPLACE(val, '[A-Za-z0-9]', 'x')
    """
    s = expr.strip()
    # mask_show_last_n(val, N, ...)
    m = re.match(r"mask_show_last_n\s*\(\s*\{col\}\s*,\s*(\d+)\s*(?:,.*)?\)", s, re.IGNORECASE)
    if m:
        n = m.group(1)
        return f"CONCAT(REPEAT('x', GREATEST(0, LENGTH(val) - {n})), RIGHT(val, {n}))"
    # mask_show_first_n(val, N, ...)
    m = re.match(r"mask_show_first_n\s*\(\s*\{col\}\s*,\s*(\d+)\s*(?:,.*)?\)", s, re.IGNORECASE)
    if m:
        n = m.group(1)
        return f"CONCAT(LEFT(val, {n}), REPEAT('x', GREATEST(0, LENGTH(val) - {n})))"
    # mask_hash(val)
    m = re.match(r"mask_hash\s*\(\s*\{col\}\s*\)", s, re.IGNORECASE)
    if m:
        return "SHA2(val, 256)"
    # mask_first_n(val, N, ...)
    m = re.match(r"mask_first_n\s*\(\s*\{col\}\s*,\s*(\d+)\s*(?:,.*)?\)", s, re.IGNORECASE)
    if m:
        n = m.group(1)
        return f"CONCAT(REPEAT('x', {n}), RIGHT(val, GREATEST(0, LENGTH(val) - {n})))"
    # mask_last_n(val, N, ...)
    m = re.match(r"mask_last_n\s*\(\s*\{col\}\s*,\s*(\d+)\s*(?:,.*)?\)", s, re.IGNORECASE)
    if m:
        n = m.group(1)
        return f"CONCAT(LEFT(val, GREATEST(0, LENGTH(val) - {n})), REPEAT('x', {n}))"
    # mask(val, ...) — generic, just redact all alphanumeric
    m = re.match(r"mask\s*\(\s*\{col\}\s*(?:,.*)?\)", s, re.IGNORECASE)
    if m:
        return "REGEXP_REPLACE(val, '[A-Za-z0-9]', 'x')"
    return None


# Matches: CASE WHEN <cond> THEN <result> ELSE <else_expr> END  (simplified, single WHEN)
_CASE_SINGLE_WHEN_RE = re.compile(
    r"(?i)^\s*CASE\s+WHEN\s+.+?\s+THEN\s+.+?\s+ELSE\s+(.+?)\s+END\s*$",
    re.DOTALL,
)


def _extract_else_fallback(expr: str) -> str | None:
    """If expr is a single-WHEN CASE expression, return the ELSE branch text; else None."""
    m = _CASE_SINGLE_WHEN_RE.match(expr)
    return m.group(1).strip() if m else None


def _ranger_wildcard_to_like(pattern: str) -> str:
    """Convert a Ranger glob pattern to a SQL LIKE pattern.  test* → test%,  ?col → _col"""
    return pattern.replace("*", "%").replace("?", "_")


def _has_wildcard(name: str | None) -> bool:
    return bool(name and ("*" in name or "?" in name))


def _wildcard_grant_loop(
    cat: str, schema: str, tbl_pattern: str, privileges: list[str], principal: str
) -> list[str]:
    """Generate a BEGIN…END FOR loop that applies grants to all tables matching a wildcard."""
    like = _ranger_wildcard_to_like(tbl_pattern)
    lines: list[str] = []
    lines.append(f"-- ⚠ Ranger wildcard table pattern: {tbl_pattern}  →  SQL LIKE: '{like}'")
    lines.append("-- UC does not support wildcards in GRANT statements.")
    lines.append("-- The block below loops through all matching tables at runtime and applies the grant.")
    lines.append("-- Requires Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled.")
    lines.append("BEGIN")
    lines.append("  FOR tbl AS (")
    lines.append("    SELECT table_name")
    lines.append(f"    FROM `{cat}`.information_schema.tables")
    lines.append(f"    WHERE table_catalog = '{cat}'")
    lines.append(f"      AND table_schema   = '{schema}'")
    lines.append(f"      AND table_name LIKE '{like}'")
    lines.append("  ) DO")
    for priv in privileges:
        uc_p, note = _uc_priv(priv, on_table=True)
        if note:
            lines.append(f"    {note}")
        if uc_p:
            lines.append(
                f"    EXECUTE IMMEDIATE 'GRANT {uc_p} ON TABLE {_q(cat)}.{_q(schema)}.`'"
                f" || tbl.table_name || '` TO {principal}';"
            )
    lines.append("  END FOR;")
    lines.append("END;")
    return lines


def _sql_escape(s: str) -> str:
    """Escape single quotes for use inside an EXECUTE IMMEDIATE format string."""
    return s.replace("'", "''")


def _norm_hdfs_path(path: str) -> str:
    """Normalise an HDFS/URL path for prefix-nesting comparison.

    Strips trailing slashes and wildcard suffixes so that
    '/data/*' and '/data/' both compare as '/data'.
    """
    p = path.rstrip("/")
    if p.endswith("*"):
        p = p[:-1].rstrip("/")
    return p or "/"


def _wildcard_column_grant_loop(
    cat: str,
    schema: str,
    table: str,
    col_pattern: str,
    permitted_items: list[dict],
    identity_map: dict[str, Any],
) -> list[str]:
    """Generate a BEGIN…END FOR loop that masks columns matching col_pattern
    to NULL for any principal who is NOT in permitted_items.

    Strategy: UC lacks column-level GRANT, so we invert the restriction —
    mask the *allowed* columns for non-permitted principals.
    """
    like = _ranger_wildcard_to_like(col_pattern)
    safe_tbl = _safe(table)
    fn_prefix = f"mask_{safe_tbl}_col_restrict"
    fn_full_prefix = f"{_q(cat)}.{_q(schema)}.{fn_prefix}"

    permitted_preds: list[str] = []
    principal_names: list[str] = []
    for it in permitted_items:
        p = it.get("principal") or {}
        p_type = p.get("type") or "group"
        raw = p.get("name") or ""
        p_name = identity_map.get(raw, raw)
        if p_type == "user" and "@" not in p_name:
            p_name = f"{p_name}@company.com"
        principal_names.append(p_name)
        if p_type == "user":
            permitted_preds.append(f"current_user() = ''{p_name}''")
        else:
            permitted_preds.append(f"IS_ACCOUNT_GROUP_MEMBER(''{p_name}'')")

    unique_preds = list(dict.fromkeys(permitted_preds))
    combined_esc = " OR ".join(f"({p})" for p in unique_preds)
    not_permitted_esc = f"NOT ({combined_esc})"

    lines: list[str] = [
        f"-- ⚠ COLUMN-SCOPED GRANT — pattern '{col_pattern}' → SQL LIKE '{like}'",
        f"-- Permitted principals: {', '.join(principal_names)}",
        "-- UC has no column-level GRANT. Strategy: mask matching columns to NULL for non-permitted principals.",
        "-- Requires Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled.",
        "BEGIN",
        "  FOR col AS (",
        "    SELECT column_name",
        f"    FROM {_q(cat)}.information_schema.columns",
        f"    WHERE table_catalog = '{cat}'",
        f"      AND table_schema   = '{schema}'",
        f"      AND table_name     = '{table}'",
        f"      AND column_name LIKE '{like}'",
        "  ) DO",
        f"    EXECUTE IMMEDIATE 'CREATE OR REPLACE FUNCTION {fn_full_prefix}_'"
        f" || col.column_name || '(val STRING) RETURNS STRING"
        f" RETURN IF({not_permitted_esc}, NULL, val)';",
        f"    EXECUTE IMMEDIATE 'ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}"
        f" ALTER COLUMN `' || col.column_name || '` SET MASK {fn_full_prefix}_' || col.column_name;",
        "  END FOR;",
        "END;",
    ]
    return lines


def _wildcard_column_deny_loop(
    cat: str,
    schema: str,
    table: str,
    col_pattern: str,
    deny_item: dict,
    identity_map: dict[str, Any],
) -> list[str]:
    """Generate a BEGIN…END FOR loop that masks columns matching col_pattern
    to NULL for the denied principal (excluding denyExceptions).
    """
    like = _ranger_wildcard_to_like(col_pattern)
    safe_tbl = _safe(table)
    p = deny_item.get("principal") or {}
    p_type = p.get("type") or "group"
    raw = p.get("name") or ""
    p_name = identity_map.get(raw, raw)
    if p_type == "user" and "@" not in p_name:
        p_name = f"{p_name}@company.com"
    safe_pname = _safe(p_name)

    if p_type == "user":
        deny_pred = f"current_user() = ''{p_name}''"
    else:
        deny_pred = f"IS_ACCOUNT_GROUP_MEMBER(''{p_name}'')"

    deny_exceptions = deny_item.get("denyExceptions") or []
    exc_clauses: list[str] = []
    for exc in deny_exceptions:
        exc_name = exc.get("name") or ""
        exc_type = exc.get("type") or "group"
        if exc_type == "user" and "@" not in exc_name:
            exc_name = f"{exc_name}@company.com"
        if exc_type == "user":
            exc_clauses.append(f"current_user() = ''{exc_name}''")
        else:
            exc_clauses.append(f"IS_ACCOUNT_GROUP_MEMBER(''{exc_name}'')")
    exc_clauses = list(dict.fromkeys(exc_clauses))

    if exc_clauses:
        deny_condition = f"({deny_pred} AND NOT ({' OR '.join(f'({c})' for c in exc_clauses)}))"
    else:
        deny_condition = deny_pred

    fn_prefix = f"mask_{safe_tbl}_deny_{safe_pname}"
    fn_full_prefix = f"{_q(cat)}.{_q(schema)}.{fn_prefix}"

    lines: list[str] = [
        f"-- ✅ SUGGESTED DENY APPROXIMATION — column pattern '{col_pattern}' → SQL LIKE '{like}'",
        f"-- Denied principal: {p_name}" + (f" (except: {', '.join(e.get('name','') for e in deny_exceptions)})" if deny_exceptions else ""),
        "-- Strategy: mask columns matching the pattern to NULL for the denied principal.",
        "-- ⚠ UC has no DENY — this is an additive mask approximation. Do NOT grant the",
        f"-- denied principal ({p_name}) SELECT on this table.",
        "-- Requires Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled.",
        "BEGIN",
        "  FOR col AS (",
        "    SELECT column_name",
        f"    FROM {_q(cat)}.information_schema.columns",
        f"    WHERE table_catalog = '{cat}'",
        f"      AND table_schema   = '{schema}'",
        f"      AND table_name     = '{table}'",
        f"      AND column_name LIKE '{like}'",
        "  ) DO",
        f"    EXECUTE IMMEDIATE 'CREATE OR REPLACE FUNCTION {fn_full_prefix}_'"
        f" || col.column_name || '(val STRING) RETURNS STRING"
        f" RETURN IF({deny_condition}, NULL, val)';",
        f"    EXECUTE IMMEDIATE 'ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}"
        f" ALTER COLUMN `' || col.column_name || '` SET MASK {fn_full_prefix}_' || col.column_name;",
        "  END FOR;",
        "END;",
    ]
    return lines


# Ranger access types that are service-specific or otherwise have no UC equivalent.
# These produce an advisory comment only — no GRANT statement is emitted.
_NO_UC_EQUIVALENT: frozenset[str] = frozenset({
    "SERVICEADMIN",   # Hive service-administration privilege
    "REPLADMIN",      # Hive replication admin
    "TEMPUDFADMIN",   # Hive temporary UDF admin
    "URLAUTH",        # Hive URL-based authorization
    "CONSUME",        # Kafka consumer privilege
    "PUBLISH",        # Kafka producer privilege
    "DESCRIBE",       # Kafka/other — SELECT covers describe access in UC
    "ENTITY-READ",    # Apache Atlas lineage/classification privilege — no UC equivalent
})


def _uc_priv(priv: str, on_table: bool) -> tuple[str | None, str | None]:
    """Translate a parsed privilege to a valid UC privilege for the given target type.

    Returns (uc_privilege, advisory_comment).
    When uc_privilege is None no GRANT line is emitted; advisory_comment explains why.
    """
    if priv == "CREATE":
        if on_table:
            # No CREATE privilege exists at the TABLE level in Unity Catalog
            return None, (
                "-- ⚠ CREATE privilege has no direct equivalent on a UC TABLE "
                "(Ranger 'create' at table scope). "
                "Grant MODIFY for write access, or ALL PRIVILEGES for full control."
            )
        # Schema-level: Ranger 'create' = ability to create objects in the schema
        return "CREATE TABLE", None
    if priv == "DROP":
        # DROP is not a valid UC privilege — converted to MANAGE (closest equivalent)
        return "MANAGE", (
            "-- ⚠ DROP privilege has no direct equivalent in Unity Catalog. "
            "Converted to MANAGE (allows managing grants on the object). "
            "To allow dropping the object, grant ALL PRIVILEGES or assign object ownership instead."
        )
    if priv == "ALTER":
        # ALTER in Ranger/Hive = DDL structural changes (ALTER TABLE ADD COLUMN, etc.).
        # UC has no ALTER privilege; DDL access is governed by object ownership.
        # ALL PRIVILEGES is the closest grantable equivalent — it covers DML + grant management,
        # which is the broadest access short of ownership.
        # MODIFY is intentionally NOT used here because it covers DML only (INSERT/UPDATE/DELETE),
        # not DDL, making it a weaker and semantically incorrect substitution for ALTER.
        return "ALL PRIVILEGES", (
            "-- ⚠ ALTER privilege has no direct equivalent in Unity Catalog. "
            "Converted to ALL PRIVILEGES (closest available substitute for DDL access). "
            "In UC, table/schema structural changes (ADD COLUMN, RENAME, etc.) require ownership. "
            "Review: consider assigning object ownership instead of granting ALL PRIVILEGES."
        )
    if priv == "EXECUTE":
        # EXECUTE is only valid on UC functions (udf_grant handles that path directly).
        # On tables or schemas it is not a recognised UC privilege.
        return None, (
            "-- ⚠ EXECUTE privilege is only valid on UC functions, not on tables or schemas. "
            "No GRANT is emitted. Use a UDF policy resource to grant EXECUTE on a specific function."
        )
    if priv in _NO_UC_EQUIVALENT:
        return None, (
            f"-- ⚠ '{priv}' is a Ranger/service-specific privilege with no Unity Catalog equivalent. "
            "No GRANT is emitted. Review manually."
        )
    return priv, None


def _q(name: str) -> str:
    """Wrap an identifier in backticks for safe use in UC SQL statements."""
    return f"`{name}`"


def is_not_translatable(item: dict[str, Any]) -> bool:
    """Return True for items that cannot produce any executable SQL (comment blocks only)."""
    t = item.get("type")
    if t in ("deny", "tag_placeholder"):
        return True
    if t == "hbase_grant" and item.get("schema") == "_all_namespaces":
        return True
    return False


def generate_uc_sql(
    item: dict[str, Any],
    identity_map: dict[str, str] | None = None,
    catalog_name: str = "main",
) -> str:
    identity_map = identity_map or {}
    cat = catalog_name or item.get("catalog") or "main"
    raw_principal = (item.get("principal") or {}).get("name") or "unknown"
    principal_type = (item.get("principal") or {}).get("type") or "group"
    principal_name = identity_map.get(raw_principal, raw_principal)
    # UC users must be email addresses — append @company.com if no domain present
    if principal_type == "user" and "@" not in principal_name:
        principal_name = f"{principal_name}@company.com"
    principal = f"`{principal_name}`"
    # UC predicate: individual users use current_user(); groups/roles use IS_ACCOUNT_GROUP_MEMBER()
    if principal_type == "user":
        uc_predicate = f"current_user() = '{principal_name}'"
    else:
        uc_predicate = f"IS_ACCOUNT_GROUP_MEMBER('{principal_name}')"
    schema = item.get("schema")
    table = item.get("table")
    lines: list[str] = []
    t = item.get("type")

    # ── Guard: Ranger request-context in resource names ──────────────────
    resource_parts = [p for p in [schema, table] if p]
    resource_ctx_issues = [p for p in resource_parts if _REQUEST_CTX_RE.search(p or "")]
    if resource_ctx_issues:
        policy_name = item.get("rangerPolicyName") or "—"
        affected = ", ".join(f"`{p}`" for p in resource_ctx_issues)
        lines.append("-- ⛔ RESOURCE NOT TRANSLATED — Ranger request-context attribute in resource name")
        lines.append(f"-- Policy: {policy_name}")
        lines.append(f"-- Affected resource component(s): {affected}")
        lines.append(f"-- Principal: {principal_name}")
        lines.append("--")
        lines.append("-- Ranger supports dynamic resource names like dept_${{USER.dept}} where the")
        lines.append("-- table name is resolved per-user at query time. Unity Catalog requires")
        lines.append("-- fixed, pre-known resource names — dynamic resource names are not supported.")
        lines.append("--")
        lines.append("-- ACTION REQUIRED: Identify all concrete table names this policy covers,")
        lines.append("-- then create one GRANT statement per table for each applicable principal.")
        return "\n".join(lines)

    # ── Guard: {USER} wildcard principal ──────────────────────────────
    if "{USER}" in raw_principal:
        policy_name = item.get("rangerPolicyName") or "—"
        resource = f"{_q(cat)}.{_q(schema)}.{_q(table)}" if table else (
            f"{_q(cat)}.{_q(schema)}" if schema else _q(cat)
        )
        lines.append("-- ⛔ PRINCIPAL NOT TRANSLATED — Ranger {USER} wildcard")
        lines.append(f"-- Policy: {policy_name}")
        lines.append(f"-- Resource: {resource}")
        lines.append(f"-- Original principal: {raw_principal}")
        lines.append("--")
        lines.append("-- {USER} is a Ranger placeholder meaning 'the currently authenticated user'.")
        lines.append("-- It cannot be used as a named principal in a UC GRANT statement.")
        lines.append("--")
        lines.append("-- If the intent is 'grant to all users': use GRANT ... TO `account users`.")
        lines.append("-- If the intent is 'row/column access based on the calling user': express")
        lines.append("-- the logic in a row filter or column mask using current_user().")
        return "\n".join(lines)

    if t == "grant":
        privs = item.get("privileges") or []
        # ── database = * (all schemas wildcard) ──────────────────────
        if schema == "*":
            lines.append("-- ⚠ Ranger policy targets database=* (all schemas in the cluster).")
            lines.append(f"-- UC equivalent is a catalog-level grant on `{cat}`.")
            lines.append("-- Only USE CATALOG, CREATE SCHEMA, and ALL PRIVILEGES are valid at catalog level.")
            lines.append("-- Other privileges (SELECT, MODIFY, etc.) must be granted per-schema or per-table.")
            lines.append(f"GRANT USE CATALOG ON CATALOG {_q(cat)} TO {principal};")
            for priv in privs:
                if priv == "ALL PRIVILEGES":
                    lines.append(f"GRANT ALL PRIVILEGES ON CATALOG {_q(cat)} TO {principal};")
                else:
                    lines.append(
                        f"-- GRANT {priv} ON CATALOG — not valid in UC; "
                        f"grant on individual schemas or tables instead."
                    )
            if item.get("delegateAdmin"):
                lines.append(f"-- Note: delegateAdmin=true. Consider ownership of catalog `{cat}` if full admin needed.")
        # ── partial table wildcard (e.g. test*, fin_*, tbl?) ─────────
        elif _has_wildcard(table):
            lines.extend(_wildcard_grant_loop(cat, schema, table, privs, principal))
            if item.get("delegateAdmin"):
                lines.append(f"-- Note: delegateAdmin=true. Consider MANAGE on each matched table if delegation needed.")
        # ── schema wildcard (database pattern like user_* ) ──────────
        elif _has_wildcard(schema):
            like = _ranger_wildcard_to_like(schema)
            _TABLE_LEVEL_PRIVS = {"SELECT", "MODIFY"}
            _loop_privs   = [p for p in privs if p in _TABLE_LEVEL_PRIVS]
            _schema_privs = [p for p in privs if p not in _TABLE_LEVEL_PRIVS]
            lines.append(f"-- ⚠ Ranger wildcard schema pattern: {schema}  →  SQL LIKE: '{like}'")
            lines.append("-- UC does not support wildcards in GRANT ON SCHEMA.")
            lines.append("-- The block below loops through all matching schemas and applies the grant.")
            if _loop_privs:
                lines.append(f"-- SELECT and MODIFY are table-level privileges — a nested per-table loop")
                lines.append(f"-- follows the schema loop to apply them to every table in each matched schema.")
                lines.append(f"-- ⚠ Tables added after this script runs will NOT inherit these grants.")
            lines.append("-- Requires Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled.")
            lines.append("BEGIN")
            lines.append("  FOR sch AS (")
            lines.append("    SELECT schema_name")
            lines.append(f"    FROM {_q(cat)}.information_schema.schemata")
            lines.append(f"    WHERE catalog_name = '{cat}'")
            lines.append(f"      AND schema_name LIKE '{like}'")
            lines.append("  ) DO")
            lines.append(f"    EXECUTE IMMEDIATE 'GRANT USE CATALOG ON CATALOG {_q(cat)} TO {principal}';")
            lines.append(
                f"    EXECUTE IMMEDIATE 'GRANT USE SCHEMA ON SCHEMA {_q(cat)}.`' || sch.schema_name || '` TO {principal}';"
            )
            for priv in _schema_privs:
                uc_p, note = _uc_priv(priv, on_table=False)
                if note:
                    lines.append(f"    {note}")
                if uc_p:
                    lines.append(
                        f"    EXECUTE IMMEDIATE 'GRANT {uc_p} ON SCHEMA {_q(cat)}.`' || sch.schema_name || '` TO {principal}';"
                    )
            lines.append("  END FOR;")
            lines.append("END;")
            # SELECT / MODIFY: table-level — emit a nested BEGIN...END FOR loop per matched schema.
            # This outer loop runs after the schema loop above so sch.schema_name is no longer in scope;
            # we use a correlated subquery on information_schema.columns instead.
            for priv in _loop_privs:
                lines.append(f"-- ⚠ {priv}: table-level privilege — applied per-table below for schemas LIKE '{like}'.")
                lines.append("BEGIN")
                lines.append("  FOR tbl AS (")
                lines.append("    SELECT table_schema, table_name")
                lines.append(f"    FROM {_q(cat)}.information_schema.tables")
                lines.append(f"    WHERE table_catalog = '{cat}'")
                lines.append(f"      AND table_schema LIKE '{like}'")
                lines.append("  ) DO")
                uc_p, _ = _uc_priv(priv, on_table=True)
                lines.append(
                    f"    EXECUTE IMMEDIATE 'GRANT {uc_p} ON TABLE {_q(cat)}.`'"
                    f" || tbl.table_schema || '`.`' || tbl.table_name || '` TO {principal}';"
                )
                lines.append("  END FOR;")
                lines.append("END;")
        # ── normal table or schema-level grant ────────────────────────
        else:
            target = (
                f"TABLE {_q(cat)}.{_q(schema)}.{_q(table)}" if table
                else f"SCHEMA {_q(cat)}.{_q(schema)}"
            )
            col_scope = item.get("columns")
            if col_scope:
                # Ranger column-scoped grants have no UC equivalent — grant is widened to table-level
                col_str = ", ".join(col_scope)
                lines.append(f"-- ⚠ COLUMN-SCOPED GRANT WIDENED TO TABLE LEVEL")
                lines.append(f"-- Original Ranger grant was limited to column(s): {col_str}")
                lines.append("-- Unity Catalog has no column-level GRANT — privileges apply to the whole table.")
                lines.append("-- If column-level restriction is required, apply column masks on the")
                lines.append("-- other columns to return NULL/redacted values for non-permitted principals.")
            if not table:
                # Ranger table=* → schema-level target. SELECT and MODIFY are table-level
                # privileges in UC and cannot be applied to a schema object.
                # Split: route table-level privs through a per-table loop; others grant on schema.
                _TABLE_LEVEL_PRIVS = {"SELECT", "MODIFY"}
                _loop_privs   = [p for p in privs if p in _TABLE_LEVEL_PRIVS]
                _schema_privs = [p for p in privs if p not in _TABLE_LEVEL_PRIVS]

                lines.append(f"-- ⚠ Ranger policy targeted table=* (all tables in `{schema}`).")
                lines.append("-- SELECT and MODIFY are table-level privileges in UC — they cannot be granted on SCHEMA.")
                lines.append("-- They are applied via a BEGIN...END FOR loop over all tables in the schema.")
                if _schema_privs:
                    lines.append(f"-- Other privileges ({', '.join(_schema_privs)}) are granted directly on the schema.")
                lines.append(f"GRANT USE CATALOG ON CATALOG {_q(cat)} TO {principal};")
                lines.append(f"GRANT USE SCHEMA ON SCHEMA {_q(cat)}.{_q(schema)} TO {principal};")

                for priv in _schema_privs:
                    uc_p, note = _uc_priv(priv, on_table=False)
                    if note:
                        lines.append(note)
                    if uc_p:
                        lines.append(f"GRANT {uc_p} ON SCHEMA {_q(cat)}.{_q(schema)} TO {principal};")

                for priv in _loop_privs:
                    lines.append(f"-- ⚠ {priv}: table-level privilege — granted per-table via loop below.")
                    lines.append(f"-- Requires Databricks Runtime 14.0+ or a SQL Warehouse with scripting enabled.")
                    lines.append(f"-- ⚠ Tables added to `{schema}` AFTER this script runs will NOT inherit this grant.")
                    lines.append(f"-- Re-run the relevant GRANT or add explicit per-table grants for new tables.")
                    lines.extend(_wildcard_grant_loop(cat, schema, "*", [priv], principal))
            else:
                for priv in privs:
                    uc_p, note = _uc_priv(priv, on_table=True)
                    if note:
                        lines.append(note)
                    if uc_p:
                        lines.append(f"GRANT {uc_p} ON {target} TO {principal};")
            if item.get("delegateAdmin"):
                lines.append(
                    f"-- Note: delegateAdmin=true in Ranger. "
                    f"Consider granting MANAGE on {target} if admin delegation is needed."
                )

    elif t == "hdfs_grant":
        path = item.get("path") or "/"
        is_recursive = item.get("isRecursive", False)
        safe_loc = _safe(path.strip("/")) or "root"
        recursive_note = " (recursive)" if is_recursive else ""
        lines.append(f"-- HDFS path: {path}{recursive_note}")
        lines.append("-- ⚠ Create a UC External Location covering this path first,")
        lines.append("--   then replace the placeholder below with the actual location name.")
        for priv in item.get("privileges") or []:
            lines.append(f"GRANT {priv} ON EXTERNAL LOCATION `<ext_loc_{safe_loc}>` TO {principal};")
        if item.get("delegateAdmin"):
            lines.append("-- Note: delegateAdmin=true. Consider granting MANAGE on the External Location.")

    elif t == "hbase_grant":
        schema = item.get("schema") or "default"
        table = item.get("table")
        cf_list = item.get("col_families") or []
        if schema == "_all_namespaces":
            lines.append("-- ⚠ HBase wildcard (*) spans all namespaces — cannot be automatically translated.")
            lines.append(f"-- Grant on specific schemas under catalog {cat} manually.")
        else:
            if cf_list:
                lines.append(f"-- HBase column-families ({', '.join(cf_list)}) have no direct UC equivalent — table-level grant applied.")
            privs = item.get("privileges") or []
            if _has_wildcard(table):
                # partial table wildcard e.g. fb00_*da017*
                lines.extend(_wildcard_grant_loop(cat, schema, table, privs, principal))
                if item.get("delegateAdmin"):
                    lines.append("-- Note: delegateAdmin=true. Consider MANAGE on each matched table if delegation needed.")
            else:
                target = (
                    f"TABLE {_q(cat)}.{_q(schema)}.{_q(table)}" if table
                    else f"SCHEMA {_q(cat)}.{_q(schema)}"
                )
                if not table:
                    _TABLE_LEVEL_PRIVS = {"SELECT", "MODIFY"}
                    _loop_privs   = [p for p in privs if p in _TABLE_LEVEL_PRIVS]
                    _schema_privs = [p for p in privs if p not in _TABLE_LEVEL_PRIVS]
                    lines.append(
                        f"-- ⚠ HBase wildcard namespace:* — grant on schema `{schema}` covers"
                        " all current AND future tables, broader than the original HBase namespace policy."
                    )
                    lines.append("-- SELECT and MODIFY are table-level privileges in UC — applied via loop below.")
                    lines.append(f"GRANT USE CATALOG ON CATALOG {_q(cat)} TO {principal};")
                    lines.append(f"GRANT USE SCHEMA ON SCHEMA {_q(cat)}.{_q(schema)} TO {principal};")
                    for priv in _schema_privs:
                        uc_p, note = _uc_priv(priv, on_table=False)
                        if note:
                            lines.append(note)
                        if uc_p:
                            lines.append(f"GRANT {uc_p} ON SCHEMA {_q(cat)}.{_q(schema)} TO {principal};")
                    for priv in _loop_privs:
                        lines.append(f"-- ⚠ {priv}: table-level privilege — granted per-table via loop below.")
                        lines.append(f"-- ⚠ Tables added to `{schema}` AFTER this script runs will NOT inherit this grant.")
                        lines.extend(_wildcard_grant_loop(cat, schema, "*", [priv], principal))
                else:
                    for priv in privs:
                        uc_p, note = _uc_priv(priv, on_table=True)
                        if note:
                            lines.append(note)
                        if uc_p:
                            lines.append(f"GRANT {uc_p} ON {target} TO {principal};")
                if item.get("delegateAdmin"):
                    lines.append(f"-- Note: delegateAdmin=true. Consider MANAGE on {target} if admin delegation needed.")

    elif t == "udf_grant":
        udf_name = item.get("udf_name") or "unknown"
        schema = item.get("schema") or "default"
        lines.append(f"-- ⚠ Ensure function {cat}.{schema}.{udf_name} is registered in UC before granting.")
        lines.append(f"GRANT EXECUTE ON FUNCTION `{cat}`.`{schema}`.`{udf_name}` TO {principal};")
        if item.get("delegateAdmin"):
            lines.append(f"-- Note: delegateAdmin=true. Consider granting MANAGE on FUNCTION {cat}.{schema}.{udf_name}.")

    elif t == "tag_set":
        schema = item.get("schema") or ""
        table = item.get("table") or ""
        column = item.get("column")
        tag_attrs = item.get("tag_attrs") or {}
        pairs = ", ".join(f"'{k}' = '{v}'" for k, v in tag_attrs.items())
        if column:
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
            lines.append(f"  ALTER COLUMN {_q(column)} SET TAGS ({pairs});")
        else:
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)} SET TAGS ({pairs});")

    elif t == "tag_grant":
        tag_names = item.get("tag_names") or []
        lines.append(f"-- Tag-based grant (tags: {', '.join(tag_names)})")
        schema = item.get("schema") or ""
        table = item.get("table")
        target = (
            f"TABLE {_q(cat)}.{_q(schema)}.{_q(table)}" if table
            else f"SCHEMA {_q(cat)}.{_q(schema)}"
        )
        if not table:
            lines.append(
                f"-- ⚠ Tag resolved to schema `{schema}` (no specific table). "
                "Schema-level grant applies to all current AND future tables."
            )
            lines.append(f"GRANT USE CATALOG ON CATALOG {_q(cat)} TO {principal};")
            lines.append(f"GRANT USE SCHEMA ON SCHEMA {_q(cat)}.{_q(schema)} TO {principal};")
        for priv in item.get("privileges") or []:
            lines.append(f"GRANT {priv} ON {target} TO {principal};")
        if item.get("delegateAdmin"):
            lines.append(f"-- Note: delegateAdmin=true. Consider MANAGE on {target}.")

    elif t == "tag_placeholder":
        tag_names = item.get("tag_names") or []
        privs = ", ".join(item.get("privileges") or [])
        placeholder = f"<table_with_{'_'.join(tag_names)}>"
        lines.append(f"-- ⚠ Tag-based policy — tags: {', '.join(tag_names)}")
        lines.append(f"-- Principal: {principal_name} | Privileges: {privs}")
        lines.append("-- No resourceTags metadata in export — table names cannot be resolved automatically.")
        lines.append("-- Add 'resourceTags' to the export JSON, or replace the placeholder below:")
        lines.append(f"-- GRANT {privs} ON TABLE {cat}.<schema>.{placeholder} TO {principal};")

    elif t == "deny":
        privs = ", ".join(item.get("privileges") or [])
        col_scope = item.get("columns")
        conditions = item.get("conditions") or []
        deny_exceptions = item.get("denyExceptions") or []

        lines.append("-- ⛔ DENY NOT SUPPORTED IN UNITY CATALOG")
        lines.append(
            f"-- Original Ranger deny: {privs} on {cat}.{schema}.{table or '*'} for {principal_name}"
        )
        if col_scope:
            lines.append(f"-- Column scope of deny: {', '.join(col_scope)}")

        # Emit accessed-together / other conditions with full explanation
        for cond in conditions:
            cond_type = cond.get("type") or "unknown"
            cond_vals = cond.get("values") or []
            if cond_type == "accessed-together":
                lines.append("--")
                lines.append("-- ⚠ MUTUAL EXCLUSION (accessed-together) CONDITION DETECTED")
                lines.append("-- This deny only triggers when ALL of the following columns are queried")
                lines.append("-- SIMULTANEOUSLY in a single query (column co-access prevention):")
                for v in cond_vals:
                    lines.append(f"--   • {v}")
                lines.append("-- Unity Catalog has NO equivalent for query-level column co-access prevention.")
                lines.append("-- Ranger uses this to stop correlation attacks (e.g. joining quasi-identifiers).")
                lines.append("-- UC ALTERNATIVE: Apply a column mask on each sensitive column so that")
                lines.append("-- non-exempt principals always see a masked/null value regardless of")
                lines.append("-- which other columns are queried at the same time.")
            else:
                lines.append(f"-- Condition ({cond_type}): {', '.join(cond_vals)}")

        # Emit denyExceptions
        if deny_exceptions:
            exc_names = [e["name"] for e in deny_exceptions]
            lines.append("--")
            lines.append("-- DENY EXCEPTIONS (these principals are exempt from this deny):")
            for exc in deny_exceptions:
                lines.append(f"--   • {exc['type']}: {exc['name']}")
            lines.append("-- These principals retain access even though the deny applies to the group above.")
            lines.append("-- In UC (additive model), simply grant them explicitly and do not grant the")
            lines.append(f"-- denied group ({principal_name}) at all — or apply column masks only for that group.")

        lines.append("--")
        lines.append("-- RECOMMENDED ACTIONS:")
        lines.append(f"-- 1. Remove {principal_name} from the group that grants broad access")
        lines.append("-- 2. Create a restricted schema and grant only specific tables")
        lines.append("-- 3. Use row filters / column masks for fine-grained control")
        lines.append("-- 4. If this was a safety-net deny, the UC additive model makes it unnecessary")
        lines.append("--    as long as you don't grant the denied privileges in the first place")

        # ── Suggested column masks for specific (non-wildcard) columns ────────
        specific_deny_cols: list[str] = []
        for cond in conditions:
            if cond.get("type") == "accessed-together":
                for v in cond.get("values") or []:
                    col_name = v.rsplit(".", 1)[-1]
                    if "*" not in col_name and "?" not in col_name:
                        specific_deny_cols.append(col_name)

        if specific_deny_cols:
            # Build deny predicate, excluding denyExceptions
            if principal_type == "group":
                _is_denied = f"IS_ACCOUNT_GROUP_MEMBER('{principal_name}')"
            else:
                _is_denied = f"current_user() = '{principal_name}'"
            _exc_clauses: list[str] = []
            for exc in deny_exceptions:
                exc_pname = exc["name"]
                if exc["type"] == "user" and "@" not in exc_pname:
                    exc_pname = f"{exc_pname}@company.com"
                if exc["type"] == "user":
                    _exc_clauses.append(f"current_user() = '{exc_pname}'")
                else:
                    _exc_clauses.append(f"IS_ACCOUNT_GROUP_MEMBER('{exc_pname}')")
            # Deduplicate while preserving order
            _exc_clauses = list(dict.fromkeys(_exc_clauses))
            _deny_pred = (
                f"({_is_denied} AND NOT ({' OR '.join(_exc_clauses)}))"
                if _exc_clauses else _is_denied
            )
            lines.append("--")
            lines.append("-- ✅ SUGGESTED COLUMN MASKS — UC approximation of the accessed-together deny:")
            lines.append(f"-- Applies NULL masking on each affected column for '{principal_name}',")
            lines.append("-- while exempting the denyException principals listed above.")
            lines.append("-- ⚠ BEHAVIOR DIFFERENCE: In Ranger the deny fires only when ALL listed columns")
            lines.append("-- are accessed SIMULTANEOUSLY. These masks restrict EACH column independently,")
            lines.append("-- which is MORE restrictive. Verify this is acceptable before deploying.")
            if len(specific_deny_cols) > 1:
                lines.append(f"-- Columns masked: {', '.join(specific_deny_cols)}")
            for dc in specific_deny_cols:
                _fn = f"{_q(cat)}.{_q(schema)}.mask_{table}_{dc}_deny_{_safe(principal_name)}"
                lines.append("")
                lines.append(f"CREATE OR REPLACE FUNCTION {_fn}(val STRING)")
                lines.append("RETURNS STRING")
                lines.append(f"RETURN IF({_deny_pred}, NULL, val);")
                lines.append("")
                lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
                lines.append(f"ALTER COLUMN {dc} SET MASK {_fn};")

        # ── Wildcard deny columns: generate BEGIN...END FOR loop approximation ──
        if table:
            wildcard_deny_cols = [c for c in (col_scope or []) if _has_wildcard(c) and c != "*"]
            for wc in wildcard_deny_cols:
                lines.append("--")
                lines.extend(_wildcard_column_deny_loop(
                    cat, schema, table, wc, item, identity_map or {}
                ))

    elif t == "skipped_blank_principal":
        blanks = item.get("blanks") or []
        resource = (
            f"{_q(cat)}.{_q(schema)}.{_q(table)}" if table
            else f"{_q(cat)}.{_q(schema)}" if schema else _q(cat)
        )
        policy_name = item.get("rangerPolicyName") or "—"
        lines.append("-- ⚠ BLANK PRINCIPAL SKIPPED — NO GRANT GENERATED")
        lines.append(f"-- Policy: {policy_name}")
        lines.append(f"-- Resource: {resource}")
        lines.append(f"-- Blank entries found: {'; '.join(blanks)}")
        lines.append("-- These entries were omitted because an empty user/group/role name")
        lines.append("-- cannot be mapped to a Databricks principal.")
        lines.append("-- ACTION REQUIRED: Open the Ranger policy, assign explicit principal names,")
        lines.append("-- re-export the policy JSON, and re-run the migration.")

    elif t == "row_filter":
        fn = f"{_q(cat)}.{_q(schema)}.rf_{table}_{_safe(principal_name)}"
        expr = item.get("filterExpr") or "TRUE"
        expr_issues = _ranger_expr_issues(expr)
        if expr_issues:
            lines.append("-- ⛔ ROW FILTER NOT TRANSLATED — Ranger-specific constructs detected")
            lines.append(f"-- Policy:    {item.get('rangerPolicyName') or '—'}")
            lines.append(f"-- Principal: {principal_name}")
            lines.append(f"-- Original expression: {expr}")
            lines.append("--")
            lines.append("-- The expression contains constructs that have no Unity Catalog equivalent:")
            for issue in expr_issues:
                for part in issue.split(". "):
                    if part:
                        lines.append(f"--   • {part.strip()}.")
            lines.append("--")
            lines.append("-- ACTION REQUIRED: Rewrite this row filter manually using UC-native expressions.")
            lines.append("-- Common patterns:")
            lines.append("--   • Attribute-based: use IS_ACCOUNT_GROUP_MEMBER() for group membership,")
            lines.append("--     or join an attribute lookup table on current_user().")
            lines.append("--   • {col} → replace with the column name or the 'val' parameter.")
            lines.append("--   • Ranger mask UDFs → replace with CONCAT, LEFT, RIGHT, SHA2, etc.")
            lines.append(f"-- Target function: {fn}")
        else:
            filter_cols = _extract_filter_columns(expr)
            if filter_cols:
                params = ", ".join(f"{c} STRING" for c in filter_cols)
                on_cols = ", ".join(filter_cols)
            else:
                params = ""
                on_cols = ""
            lines.append(f"-- Row Filter for: {principal_name}")
            lines.append(f"-- Original expression: {expr}")
            if not filter_cols:
                lines.append("-- ⚠ No column references detected in filter expression — review manually.")
            lines.append("")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}({params})")
            lines.append("RETURNS BOOLEAN")
            lines.append("RETURN IF(")
            lines.append(f"  {uc_predicate},")
            lines.append(f"  {expr},")
            lines.append("  TRUE  -- Allow access for principals not matching the condition")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
            lines.append(f"SET ROW FILTER {fn} ON ({on_cols});")

    elif t == "column_mask":
        mask_uc = MASK_TYPE_MAP.get(item.get("maskType") or "MASK", "REDACT")
        col = (item.get("columns") or ["col"])[0]
        fn = f"{_q(cat)}.{_q(schema)}.mask_{table}_{col}_{_safe(principal_name)}"

        if mask_uc == "NONE":
            lines.append(f"-- ✅ No masking for {principal_name} on {col} (full access granted)")
            lines.append("-- No SQL needed — this principal sees unmasked data")
        elif mask_uc == "LAST_4":
            lines.append(f"-- Column Mask: Show last 4 characters for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  {uc_predicate},")
            lines.append("  CONCAT('***-**-', RIGHT(val, 4)),")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        elif mask_uc == "HASH":
            lines.append(f"-- Column Mask: SHA-256 hash for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  {uc_predicate},")
            lines.append("  SHA2(val, 256),")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        elif mask_uc == "NULLIFY":
            lines.append(f"-- Column Mask: NULL value for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  {uc_predicate},")
            lines.append("  NULL,")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        elif mask_uc == "FIRST_4":
            _body = (item.get("maskExpr") or "").strip() or "CONCAT(LEFT(val, 4), '***')"
            lines.append(f"-- Column Mask: Show first 4 characters for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
            lines.append("RETURNS STRING")
            lines.append("RETURN IF(")
            lines.append(f"  {uc_predicate},")
            lines.append(f"  {_body},")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        elif mask_uc == "DATE_YEAR":
            _body = (item.get("maskExpr") or "").strip() or "MAKE_DATE(YEAR(val), 1, 1)"
            lines.append(f"-- Column Mask: Date year-only masking for {principal_name}")
            lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val DATE)")
            lines.append("RETURNS DATE")
            lines.append("RETURN IF(")
            lines.append(f"  {uc_predicate},")
            lines.append(f"  {_body},")
            lines.append("  val")
            lines.append(");")
            lines.append("")
            lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
            lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
        else:
            _custom = (item.get("maskExpr") or "").strip()
            if _custom:
                expr_issues = _ranger_expr_issues(_custom)
                if expr_issues:
                    lines.append("-- ⛔ COLUMN MASK NOT TRANSLATED — Ranger-specific constructs detected")
                    lines.append(f"-- Policy:    {item.get('rangerPolicyName') or '—'}")
                    lines.append(f"-- Column:    {col}")
                    lines.append(f"-- Principal: {principal_name}")
                    lines.append(f"-- Original expression: {_custom}")
                    lines.append("--")
                    lines.append("-- The expression contains constructs that have no Unity Catalog equivalent:")
                    for issue in expr_issues:
                        for part in issue.split(". "):
                            if part:
                                lines.append(f"--   • {part.strip()}.")
                    lines.append("--")
                    lines.append("-- ACTION REQUIRED: Rewrite this mask expression manually using UC-native expressions.")
                    lines.append("-- Common patterns:")
                    lines.append("--   • {col} → replace with 'val' (the UC mask function parameter).")
                    lines.append("--   • ${{USER.attr}} → use IS_ACCOUNT_GROUP_MEMBER() or a lookup table on current_user().")
                    lines.append("--   • Ranger mask UDFs → replace with CONCAT, LEFT, RIGHT, SHA2, etc.")
                    lines.append(f"-- Target function: {fn}")
                    # ── Try to derive a safe fallback from the ELSE branch ──────────
                    _else_branch = _extract_else_fallback(_custom)
                    if _else_branch is not None:
                        _else_issues = _ranger_expr_issues(_else_branch)
                        if _else_issues:
                            # ELSE branch still has Ranger constructs — try UDF approximation
                            _approx = _approx_ranger_mask_udf(_else_branch)
                            _fallback_expr = _approx
                        else:
                            # ELSE branch is clean — use as-is (substitute {col} just in case)
                            _fallback_expr = _RANGER_PLACEHOLDER_RE.sub("val", _else_branch)
                    else:
                        # No ELSE branch detected — check if the whole expr can be approximated
                        _fallback_expr = _approx_ranger_mask_udf(_custom)

                    if _fallback_expr:
                        lines.append("--")
                        lines.append("-- ✅ SUGGESTED SAFE-FALLBACK SQL (conservative — applies masking to all users):")
                        lines.append("-- The WHEN condition requiring request-context (${{USER.attr}}) has been dropped.")
                        lines.append("-- This is MORE restrictive than the original: no user receives the unmasked value")
                        lines.append("-- via the exemption condition. Verify this is acceptable before deploying.")
                        lines.append("-- Ranger UDF calls are approximated with UC-native string functions.")
                        lines.append("--")
                        lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
                        lines.append("RETURNS STRING")
                        lines.append("RETURN IF(")
                        lines.append(f"  {uc_predicate},")
                        lines.append(f"  {_fallback_expr},")
                        lines.append("  val")
                        lines.append(");")
                        lines.append("")
                        lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
                        lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
                else:
                    lines.append(f"-- Column Mask: Custom expression for {principal_name} (review before executing)")
                    lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
                    lines.append("RETURNS STRING")
                    lines.append("RETURN IF(")
                    lines.append(f"  {uc_predicate},")
                    lines.append(f"  {_custom},")
                    lines.append("  val")
                    lines.append(");")
                    lines.append("")
                    lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
                    lines.append(f"ALTER COLUMN {col} SET MASK {fn};")
            else:
                lines.append(f"-- Column Mask: Full redaction for {principal_name}")
                lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
                lines.append("RETURNS STRING")
                lines.append("RETURN IF(")
                lines.append(f"  {uc_predicate},")
                lines.append("  '***REDACTED***',")
                lines.append("  val")
                lines.append(");")
                lines.append("")
                lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
                lines.append(f"ALTER COLUMN {col} SET MASK {fn};")

    return "\n".join(lines)


def _resolved_principal(item: dict[str, Any], identity_map: dict[str, str]) -> tuple[str, str]:
    """Return (uc_predicate, display_name) for an item, respecting identity_map and @company.com rule."""
    raw = (item.get("principal") or {}).get("name") or "unknown"
    p_type = (item.get("principal") or {}).get("type") or "group"
    p_name = identity_map.get(raw, raw)
    if p_type == "user" and "@" not in p_name:
        p_name = f"{p_name}@company.com"
    predicate = f"current_user() = '{p_name}'" if p_type == "user" else f"IS_ACCOUNT_GROUP_MEMBER('{p_name}')"
    return predicate, p_name


def _mask_body(item: dict[str, Any]) -> tuple[str, str]:
    """Return (mask_expression, val_type) for a column_mask item. val_type is 'DATE' or 'STRING'."""
    mask_uc = MASK_TYPE_MAP.get(item.get("maskType") or "MASK", "REDACT")
    custom = (item.get("maskExpr") or "").strip()
    if mask_uc == "LAST_4":
        return "CONCAT('***-**-', RIGHT(val, 4))", "STRING"
    if mask_uc == "FIRST_4":
        return custom or "CONCAT(LEFT(val, 4), '***')", "STRING"
    if mask_uc == "HASH":
        return "SHA2(val, 256)", "STRING"
    if mask_uc == "NULLIFY":
        return "NULL", "STRING"
    if mask_uc == "DATE_YEAR":
        return custom or "MAKE_DATE(YEAR(val), 1, 1)", "DATE"
    if mask_uc == "NONE":
        return "val", "STRING"  # no-op
    if custom:
        return custom, "STRING"
    return "'***REDACTED***'", "STRING"


def _mask_body_as_string(item: dict[str, Any]) -> tuple[str, bool]:
    """Return (mask_expression, has_custom) where expression is always STRING-compatible.

    Used in merged mask functions where the unified parameter type is STRING.
    DATE_YEAR is rewritten to TRY_CAST so val (STRING) is safely coerced.
    Returns has_custom=True when the expression came from a Ranger valueExpr —
    the caller should emit an advisory comment in that case.
    """
    mask_uc = MASK_TYPE_MAP.get(item.get("maskType") or "MASK", "REDACT")
    custom = (item.get("maskExpr") or "").strip()
    if mask_uc == "LAST_4":
        return "CONCAT('***-**-', RIGHT(val, 4))", False
    if mask_uc == "FIRST_4":
        if custom:
            return custom, True
        return "CONCAT(LEFT(val, 4), '***')", False
    if mask_uc == "HASH":
        return "SHA2(val, 256)", False
    if mask_uc == "NULLIFY":
        return "NULL", False
    if mask_uc == "DATE_YEAR":
        # val is STRING in merged context; cast safely to DATE, then back to STRING
        if custom:
            return custom, True
        return "CAST(MAKE_DATE(YEAR(TRY_CAST(val AS DATE)), 1, 1) AS STRING)", False
    if mask_uc == "NONE":
        return "val", False
    if custom:
        return custom, True
    return "'***REDACTED***'", False


_BAD_CAST_RE = re.compile(
    r"CAST\s*\(\s*'([^']*)'\s+AS\s+"
    r"(DECIMAL|INT|INTEGER|BIGINT|SMALLINT|TINYINT|DOUBLE|FLOAT|REAL|NUMERIC|NUMBER)"
    r"(?:\s*\([^)]*\))?\s*\)",
    re.IGNORECASE,
)


def _fix_custom_mask_expr(
    expr: str, col: str
) -> tuple[str, list[str], list[str]]:
    """Attempt to adapt a custom Ranger mask expression for use in a UC mask function.

    Applies two mechanical fixes:
      1. CAST('<non-numeric-literal>' AS <numeric-type>) → NULL
         (the literal cannot be cast; CAST fails at parse time)
      2. Bare references to `col` (the masked column) → `val`
         (the mask function only receives the current column as 'val')

    Returns (adapted_expr, fixes_applied, remaining_issues).
    remaining_issues is empty when the result is likely valid UC SQL.
    Cross-column references that survive after fix #2 are reported as issues —
    the caller should emit a commented fallback for that branch.
    """
    fixes: list[str] = []
    issues: list[str] = []
    result = expr

    def _replace_bad_cast(m: re.Match[str]) -> str:
        literal, typ = m.group(1), m.group(2).upper()
        try:
            float(literal)
            return m.group(0)  # valid numeric literal — keep as-is
        except (ValueError, TypeError):
            fixes.append(
                f"CAST('{literal}' AS {typ}) → NULL "
                f"('{literal}' is not a valid {typ} — would fail at parse time)"
            )
            return "NULL"

    result = _BAD_CAST_RE.sub(_replace_bad_cast, result)

    col_re = re.compile(r"\b" + re.escape(col) + r"\b")
    if col_re.search(result):
        result = col_re.sub("val", result)
        fixes.append(
            f"Column reference `{col}` → `val` (the mask function parameter)"
        )

    remaining_ids = [
        ident
        for ident in re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b(?!\s*\()", result)
        if ident.lower() not in _SQL_BUILTINS
    ]
    if remaining_ids:
        unique = list(dict.fromkeys(remaining_ids))
        issues.append(
            f"Cross-column reference(s): {', '.join(unique)}. "
            "UC mask functions can only access 'val' (the current column value) — "
            "other column references cannot be resolved at mask-evaluation time. "
            "Rewrite this branch manually."
        )

    return result, fixes, issues


def _merge_row_filters(items: list[dict[str, Any]], identity_map: dict[str, str], cat: str) -> str:
    """Generate a single merged row filter function for multiple principals on the same table.

    If any item's filterExpr contains Ranger-specific constructs (request-context attributes,
    Ranger UDFs) an advisory comment replaces that WHEN branch — the function is still generated
    but those branches are commented out so the file remains syntactically valid.
    """
    item0 = items[0]
    schema = item0.get("schema") or "default"
    table = item0.get("table") or "unknown"

    # Collect column refs only from clean (translatable) expressions
    all_cols: list[str] = []
    seen_cols: set[str] = set()
    for it in items:
        expr = it.get("filterExpr") or ""
        if not _ranger_expr_issues(expr):
            for c in _extract_filter_columns(expr):
                if c not in seen_cols:
                    seen_cols.add(c)
                    all_cols.append(c)

    params   = ", ".join(f"{c} STRING" for c in all_cols) if all_cols else ""
    on_cols  = ", ".join(all_cols) if all_cols else ""
    fn       = f"{_q(cat)}.{_q(schema)}.rf_{table}"
    names    = [_resolved_principal(i, identity_map)[1] for i in items]

    # Determine if any item has untranslatable expressions
    problematic = [it for it in items if _ranger_expr_issues(it.get("filterExpr") or "")]
    clean        = [it for it in items if not _ranger_expr_issues(it.get("filterExpr") or "")]

    lines: list[str] = []
    lines.append("-- ⚠ MERGED ROW FILTER — Unity Catalog supports only ONE row filter per table.")
    lines.append(f"-- Multiple Ranger principals for `{schema}`.`{table}` have been combined into one function.")
    lines.append(f"-- Principals merged ({len(items)}): {', '.join(names)}")
    if problematic:
        prob_names = [_resolved_principal(i, identity_map)[1] for i in problematic]
        lines.append(f"-- ⛔ {len(problematic)} branch(es) contain Ranger-specific constructs and CANNOT be auto-translated:")
        lines.append(f"--   Affected principals: {', '.join(prob_names)}")
        lines.append("--   These branches are commented out below — rewrite them manually before executing.")
    lines.append("-- Each WHEN clause applies the original Ranger filter for that principal.")
    lines.append("")

    if not clean:
        # Every branch is problematic — emit pure advisory, no function
        lines.append("-- ⛔ ALL branches require manual rewriting. No function generated.")
        lines.append("-- Rewrite each expression below and uncomment the function block.")
        lines.append(f"-- Target function: {fn}")
        lines.append("--")
        for it in problematic:
            predicate, p_name = _resolved_principal(it, identity_map)
            expr = it.get("filterExpr") or "TRUE"
            issues = _ranger_expr_issues(expr)
            lines.append(f"-- Principal: {p_name}")
            lines.append(f"--   Original: {expr}")
            for iss in issues:
                lines.append(f"--   Issue: {iss}")
        return "\n".join(lines)

    lines.append(f"CREATE OR REPLACE FUNCTION {fn}({params})")
    lines.append("RETURNS BOOLEAN")
    lines.append("RETURN")
    lines.append("  CASE")
    for it in items:
        predicate, p_name = _resolved_principal(it, identity_map)
        expr = it.get("filterExpr") or "TRUE"
        issues = _ranger_expr_issues(expr)
        if issues:
            lines.append(f"    -- ⛔ BRANCH OMITTED — principal: {p_name} — original expression: {expr}")
            for iss in issues:
                lines.append(f"    --   {iss}")
            lines.append(f"    -- WHEN {predicate} THEN <rewrite expression here>")
        else:
            lines.append(f"    WHEN {predicate} THEN {expr}")
    lines.append("    ELSE TRUE  -- allow access for all other principals")
    lines.append("  END;")
    lines.append("")
    lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
    lines.append(f"SET ROW FILTER {fn} ON ({on_cols});")
    return "\n".join(lines)


def _merge_column_masks(items: list[dict[str, Any]], identity_map: dict[str, str], cat: str) -> str:
    """Generate a single merged column mask function for multiple principals on the same column.

    Always uses STRING as the unified parameter/return type to avoid type mismatches
    when principals have different mask types (e.g. DATE_YEAR mixed with REDACT/HASH).
    DATE_YEAR expressions are rewritten with TRY_CAST so they are STRING-safe.
    """
    item0 = items[0]
    schema = item0.get("schema") or "default"
    table  = item0.get("table") or "unknown"
    col    = (item0.get("columns") or ["col"])[0]

    fn    = f"{_q(cat)}.{_q(schema)}.mask_{table}_{col}"
    names = [_resolved_principal(i, identity_map)[1] for i in items]

    has_date_year = any(
        MASK_TYPE_MAP.get(it.get("maskType") or "MASK", "REDACT") == "DATE_YEAR"
        for it in items
    )
    has_custom = any((it.get("maskExpr") or "").strip() for it in items)

    lines: list[str] = []
    lines.append("-- ⚠ MERGED COLUMN MASK — Unity Catalog supports only ONE mask per column.")
    lines.append(f"-- Multiple Ranger principals for `{schema}`.`{table}`.{col} have been combined.")
    lines.append(f"-- Principals merged ({len(items)}): {', '.join(names)}")
    lines.append("-- Function parameter is STRING. If the actual column type differs, adjust the signature.")
    if has_date_year:
        lines.append("-- DATE_YEAR branches use TRY_CAST(val AS DATE) — verify the column holds date strings.")
    if has_custom:
        lines.append("-- ⚠ Custom Ranger valueExpr detected. Auto-adaptation is attempted:")
        lines.append("--   • CAST('<non-numeric>' AS <type>) → NULL")
        lines.append("--   • Bare column references matching the masked column → val")
        lines.append("--   Branches with cross-column references (other columns) cannot be adapted —")
        lines.append("--   they use a '***REDACTED***' fallback and must be rewritten manually.")
    lines.append("")
    lines.append(f"CREATE OR REPLACE FUNCTION {fn}(val STRING)")
    lines.append("RETURNS STRING")
    lines.append("RETURN")
    lines.append("  CASE")
    for it in items:
        predicate, p_name = _resolved_principal(it, identity_map)
        mask_uc = MASK_TYPE_MAP.get(it.get("maskType") or "MASK", "REDACT")
        custom_expr = (it.get("maskExpr") or "").strip()
        if mask_uc == "NONE":
            lines.append(f"    WHEN {predicate} THEN val  -- MASK_NONE: no masking for this principal")
        elif custom_expr:
            fixed_expr, fixes_applied, remaining_issues = _fix_custom_mask_expr(custom_expr, col)
            if remaining_issues:
                lines.append(f"    -- ⛔ BRANCH OMITTED — custom expression has cross-column references (principal: {p_name})")
                lines.append(f"    --   Original Ranger expression: {custom_expr}")
                for iss in remaining_issues:
                    lines.append(f"    --   Issue: {iss}")
                if fixes_applied:
                    lines.append(f"    --   Partial fixes applied: {'; '.join(fixes_applied)}")
                    lines.append(f"    --   Partially adapted (still not valid): {fixed_expr}")
                lines.append(f"    --   ACTION REQUIRED: Replace the WHEN branch below with a valid UC expression.")
                lines.append(f"    -- WHEN {predicate} THEN <rewrite this expression manually>")
                lines.append(f"    WHEN {predicate} THEN '***REDACTED***'  -- conservative fallback, rewrite before executing")
            else:
                if fixes_applied:
                    lines.append(f"    -- ⚠ Auto-adapted: {'; '.join(fixes_applied)}")
                    lines.append(f"    -- Original: {custom_expr}")
                lines.append(f"    WHEN {predicate} THEN {fixed_expr}")
        else:
            body, _ = _mask_body_as_string(it)
            lines.append(f"    WHEN {predicate} THEN {body}")
    lines.append("    ELSE val  -- no masking for other principals")
    lines.append("  END;")
    lines.append("")
    lines.append(f"ALTER TABLE {_q(cat)}.{_q(schema)}.{_q(table)}")
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

    # ── Detect row_filter and column_mask conflicts ───────────────────
    from collections import defaultdict
    rf_groups: dict[tuple, list[dict]] = defaultdict(list)
    cm_groups: dict[tuple, list[dict]] = defaultdict(list)
    for item in eligible:
        t = item.get("type")
        s, tbl = item.get("schema"), item.get("table")
        if t == "row_filter" and tbl:
            rf_groups[(s, tbl)].append(item)
        elif t == "column_mask" and tbl:
            col = (item.get("columns") or ["col"])[0]
            cm_groups[(s, tbl, col)].append(item)

    merged_rf_ids: set[str] = set()
    merged_cm_ids: set[str] = set()
    conflict_blocks: list[str] = []

    for (s, tbl), grp in rf_groups.items():
        if len(grp) > 1:
            conflict_blocks.append(_merge_row_filters(grp, identity_map, catalog_name))
            for it in grp:
                merged_rf_ids.add(it["id"])

    for (s, tbl, col), grp in cm_groups.items():
        if len(grp) > 1:
            conflict_blocks.append(_merge_column_masks(grp, identity_map, catalog_name))
            for it in grp:
                merged_cm_ids.add(it["id"])

    merged_ids = merged_rf_ids | merged_cm_ids
    n_conflicts = len(rf_groups_conflict := {k: v for k, v in rf_groups.items() if len(v) > 1}) + \
                  len(cm_groups_conflict := {k: v for k, v in cm_groups.items() if len(v) > 1})

    conflict_note = ""
    if n_conflicts:
        conflict_note = (
            f"-- ⚠ CONFLICT NOTICE: {n_conflicts} row-filter/column-mask conflict(s) detected.\n"
            "-- Unity Catalog supports only ONE row filter per table and ONE mask per column.\n"
            "-- Conflicting items have been automatically MERGED into combined CASE functions below.\n"
            "-- Review each merged function carefully before executing.\n\n"
        )

    # ── Detect grant/deny conflicts (same principal has both a GRANT and a DENY) ──
    grant_keys: set[tuple] = set()
    deny_items_by_key: dict[tuple, list[dict]] = defaultdict(list)
    for item in eligible:
        t = item.get("type")
        s, tbl = item.get("schema"), item.get("table")
        p_name = (item.get("principal") or {}).get("name") or ""
        key = (s, tbl, p_name)
        if t == "grant":
            grant_keys.add(key)
        elif t == "deny":
            deny_items_by_key[key].append(item)

    gd_conflict_keys = [k for k in deny_items_by_key if k in grant_keys]
    if gd_conflict_keys:
        conflict_note += (
            f"-- ⚠ GRANT/DENY CONFLICT: {len(gd_conflict_keys)} principal(s) have both a GRANT\n"
            "-- and a DENY on the same table. In UC (additive model), GRANTs are permanent —\n"
            "-- there is no DENY mechanism. The deny advisory below has NO effect unless either:\n"
            "--   (a) the GRANT is revoked, or\n"
            "--   (b) column masks are applied to restrict what the principal can see.\n"
        )
        for s, tbl, pname in gd_conflict_keys:
            conflict_note += f"--   Affected: {pname} on {s}.{tbl}\n"
        conflict_note += "\n"

    # ── Detect nested HDFS/URL paths ─────────────────────────────────────────────────
    # UC External Locations cannot overlap. If two Ranger paths have a parent→child
    # relationship (e.g. /data/ and /data/restricted/) only one External Location can
    # cover the parent; the child should become an External Volume instead.
    hdfs_paths = list(dict.fromkeys(
        item.get("path") or "/"
        for item in eligible
        if item.get("type") == "hdfs_grant"
    ))
    nested_pairs: list[tuple[str, str]] = []
    norm_list = [(p, _norm_hdfs_path(p)) for p in hdfs_paths]
    for i, (orig_a, norm_a) in enumerate(norm_list):
        for orig_b, norm_b in norm_list[i + 1:]:
            if norm_b.startswith(norm_a + "/"):
                nested_pairs.append((orig_a, orig_b))
            elif norm_a.startswith(norm_b + "/"):
                nested_pairs.append((orig_b, orig_a))
    if nested_pairs:
        conflict_note += (
            f"-- ⚠ NESTED PATH NOTICE: {len(nested_pairs)} HDFS/URL path pair(s) have a "
            "parent→child relationship.\n"
            "-- Unity Catalog External Locations cannot have overlapping paths.\n"
            "-- Recommended fix: create ONE External Location at the parent path and use\n"
            "-- External Volumes (inside a catalog schema) for the child sub-paths,\n"
            "-- then grant READ VOLUME / WRITE VOLUME instead of READ FILES / WRITE FILES.\n"
        )
        for parent, child in nested_pairs:
            conflict_note += f"--   Parent: {parent}  →  Child (use External Volume): {child}\n"
        conflict_note += "\n"

    # ── Deduplicate grants: skip identical (principal, table, privileges) seen before ──
    emitted_grants: set[tuple] = set()

    # ── Group grant items that use wildcard column patterns (e.g. col*, tmp*) ──────────
    # Multiple principals may each have a col* grant on the same table.
    # They must be combined into a single BEGIN...END FOR loop, otherwise each
    # CREATE OR REPLACE FUNCTION would overwrite the previous one.
    wc_col_grant_groups: dict[tuple, list[dict]] = defaultdict(list)
    for item in eligible:
        if item.get("type") != "grant":
            continue
        col_scope = item.get("columns") or []
        schema_i = item.get("schema") or ""
        table_i = item.get("table") or ""
        if not table_i:
            continue
        for col in col_scope:
            if _has_wildcard(col) and col != "*":
                wc_col_grant_groups[(schema_i, table_i, col)].append(item)

    # First item in each group emits the combined loop; followers are silently consumed.
    wc_col_grant_emit: dict[str, str] = {}   # item_id → combined loop SQL (emitter only)
    wc_col_grant_ids: set[str] = set()       # all item IDs consumed by a wildcard col loop

    for (schema_i, table_i, col_pat), grp in wc_col_grant_groups.items():
        loop_lines = _wildcard_column_grant_loop(
            catalog_name, schema_i, table_i, col_pat, grp, identity_map
        )
        for i, it in enumerate(grp):
            wc_col_grant_ids.add(it["id"])
            if i == 0:
                wc_col_grant_emit[it["id"]] = "\n".join(loop_lines)

    header = (
        "-- ╔═══════════════════════════════════════════════════════════╗\n"
        "-- ║  Unity Catalog Migration Script                          ║\n"
        "-- ║  Generated by Ranger → UC Migrator                       ║\n"
        f"-- ║  Source: {service_name}\n"
        f"-- ║  Target Catalog: {catalog_name}\n"
        f"-- ║  Date: {today}\n"
        f"-- ║  Policies: {len(eligible)} of {len(policy_items)}\n"
        "-- ╚═══════════════════════════════════════════════════════════╝\n\n"
        + conflict_note
    )

    blocks: list[str] = []

    # Emit merged conflict blocks first
    for cb in conflict_blocks:
        blocks.append(
            "-- ═══════════════════════════════════════════════════════\n"
            + cb + "\n"
        )

    # Emit remaining items (skip those already merged)
    for item in eligible:
        if item["id"] in merged_ids:
            continue

        # ── Wildcard column grant: emit combined loop for first item, skip followers ──
        if item["id"] in wc_col_grant_ids:
            loop_sql = wc_col_grant_emit.get(item["id"])
            if loop_sql is not None:
                # Collect all principal names in this group for the header
                col_scope = item.get("columns") or []
                wc_cols = [c for c in col_scope if _has_wildcard(c) and c != "*"]
                col_pat = wc_cols[0] if wc_cols else "col*"
                schema_i = item.get("schema") or ""
                table_i = item.get("table") or ""
                grp = wc_col_grant_groups.get((schema_i, table_i, col_pat), [item])
                p_names = [(it.get("principal") or {}).get("name") or "" for it in grp]
                blocks.append(
                    "-- ═══════════════════════════════════════════════════════\n"
                    f"-- Policy: {item.get('rangerPolicyName')} (Ranger ID: {item.get('rangerPolicyId')})\n"
                    f"-- Type: GRANT (WILDCARD COLUMN '{col_pat}') | Principals: {', '.join(p_names)}\n"
                    "-- ═══════════════════════════════════════════════════════\n"
                    + loop_sql + "\n"
                )
            # followers: silently skip — their logic is covered by the loop above
            continue

        # Deduplicate grants: if an identical (principal, table, privilege set) was already
        # emitted from a different policy, emit a note instead of a redundant GRANT.
        if item.get("type") == "grant":
            p_name = (item.get("principal") or {}).get("name") or ""
            grant_sig = (
                item.get("schema"), item.get("table"), p_name,
                tuple(sorted(item.get("privileges") or []))
            )
            if grant_sig in emitted_grants:
                blocks.append(
                    "-- ═══════════════════════════════════════════════════════\n"
                    f"-- Policy: {item.get('rangerPolicyName')} (Ranger ID: {item.get('rangerPolicyId')})\n"
                    f"-- Type: GRANT | Principal: {p_name}\n"
                    "-- ═══════════════════════════════════════════════════════\n"
                    f"-- ℹ DUPLICATE GRANT SKIPPED — identical GRANT for {p_name} on "
                    f"{item.get('schema')}.{item.get('table')} was already emitted above.\n"
                    f"-- Original column scope: {item.get('columns') or '*'} (widened to table-level in UC).\n"
                )
                continue
            emitted_grants.add(grant_sig)

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

    # Import here to avoid circular reference at module level
    _no_uc = _NO_UC_EQUIVALENT | {"EXECUTE"}
    unsupported_priv_items = []
    for r in results:
        if r.get("type") not in ("grant", "hbase_grant", "tag_grant"):
            continue
        dropped = [p for p in (r.get("privileges") or []) if p in _no_uc]
        if dropped:
            unsupported_priv_items.append((r, dropped))
    if unsupported_priv_items:
        gaps.append({
            "category": "Ranger-Specific Privileges (No UC Equivalent)",
            "severity": "warning",
            "count": len(unsupported_priv_items),
            "description": (
                "These items contain Ranger or service-specific privileges that have no Unity Catalog "
                "equivalent (e.g. SERVICEADMIN, EXECUTE on table/schema, CONSUME, PUBLISH, DESCRIBE). "
                "No GRANT statement is emitted for the affected privilege — other privileges on the same "
                "item are still translated."
            ),
            "items": [
                {
                    "resource": f'{r.get("schema")}.{r.get("table") or "*"}',
                    "principal": r.get("principal", {}).get("name"),
                    "detail": f'Dropped privileges: {", ".join(dropped)} — review manually',
                }
                for r, dropped in unsupported_priv_items
            ],
            "remediation": (
                "Review each item: determine whether any of the dropped privileges require a manual "
                "replacement grant (e.g. ALL PRIVILEGES or ownership) in Unity Catalog."
            ),
        })

    drop_grants = [
        r for r in results
        if r.get("type") in ("grant", "hbase_grant")
        and "DROP" in (r.get("privileges") or [])
    ]
    if drop_grants:
        gaps.append({
            "category": "DROP Privilege Converted to MANAGE",
            "severity": "warning",
            "count": len(drop_grants),
            "description": (
                "Ranger 'drop' has no direct equivalent in Unity Catalog. "
                "GRANT DROP ON TABLE/SCHEMA is invalid UC SQL — converted to GRANT MANAGE. "
                "MANAGE allows managing grants on the object but does NOT permit dropping it."
            ),
            "items": [
                {
                    "resource": f'{r.get("schema")}.{r.get("table") or "*"}',
                    "principal": r.get("principal", {}).get("name"),
                    "detail": f'Ranger privileges: {", ".join(r.get("privileges") or [])} — DROP → MANAGE',
                }
                for r in drop_grants
            ],
            "remediation": (
                "Review each converted grant: if the principal truly needs to drop objects, "
                "grant ALL PRIVILEGES or assign object ownership via ALTER ... OWNER TO. "
                "If MANAGE is sufficient, no action needed."
            ),
        })

    create_on_table = [
        r for r in results
        if r.get("type") in ("grant", "hbase_grant")
        and r.get("table") is not None
        and "CREATE" in (r.get("privileges") or [])
    ]
    if create_on_table:
        gaps.append({
            "category": "CREATE Privilege Dropped (Table Scope)",
            "severity": "warning",
            "count": len(create_on_table),
            "description": (
                "Ranger 'create' at table level has no direct Unity Catalog equivalent — "
                "no GRANT statement is emitted for this privilege. "
                "The remaining privileges on each item are still granted."
            ),
            "items": [
                {
                    "resource": f'{r.get("schema")}.{r.get("table")}',
                    "principal": r.get("principal", {}).get("name"),
                    "detail": f'All Ranger privileges: {", ".join(r.get("privileges") or [])} — CREATE was dropped',
                }
                for r in create_on_table
            ],
            "remediation": (
                "Decide the appropriate replacement for each principal: "
                "grant MODIFY if they need to write to the table, "
                "or ALL PRIVILEGES if they need full control. "
                "Schema-level CREATE TABLE is already translated correctly where 'create' applies to a schema."
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
        # Split: translatable vs. request-context/ranger-builtin expressions
        rf_req_ctx = [
            r for r in row_filters
            if _ranger_expr_issues(r.get("filterExpr") or "")
        ]
        rf_clean = [r for r in row_filters if r not in rf_req_ctx]

        if rf_req_ctx:
            gaps.append({
                "category": "Row Filters with Untranslatable Expressions",
                "severity": "critical",
                "count": len(rf_req_ctx),
                "description": (
                    "These row filter expressions contain Ranger-specific constructs "
                    "(request-context attributes like ${{USER.attr}}, Ranger UDFs, or {col} placeholders) "
                    "that have no Unity Catalog equivalent. "
                    "No executable SQL is generated — only advisory comment blocks."
                ),
                "items": [
                    {
                        "resource": f'{r.get("schema")}.{r.get("table")}',
                        "principal": (r.get("principal") or {}).get("name"),
                        "detail": f'Expression: {r.get("filterExpr")} — Issues: {"; ".join(_ranger_expr_issues(r.get("filterExpr") or ""))}',
                    }
                    for r in rf_req_ctx
                ],
                "remediation": (
                    "Rewrite each row filter manually using UC-native predicates: "
                    "IS_ACCOUNT_GROUP_MEMBER() for group membership, current_user() for user identity, "
                    "or a lookup table join for attribute-based access. "
                    "Replace {col} with 'val' (the mask function parameter). "
                    "Replace Ranger mask UDFs with CONCAT, LEFT, RIGHT, SHA2, etc."
                ),
            })

        if rf_clean:
            gaps.append({
                "category": "Row Filter Translation",
                "severity": "warning",
                "count": len(rf_clean),
                "description": (
                    "Ranger row filters translate to UC SQL functions. "
                    "Complex expressions may need manual adjustment."
                ),
                "items": [
                    {
                        "resource": f'{r.get("schema")}.{r.get("table")}',
                        "principal": (r.get("principal") or {}).get("name"),
                        "detail": f'Filter: {r.get("filterExpr")}',
                    }
                    for r in rf_clean
                ],
                "remediation": (
                    "Review generated filter functions. Test with sample queries to verify filter "
                    "behavior matches Ranger. Watch for UDF dependencies."
                ),
            })

    # ── Row filter / column mask conflict detection ───────────────────
    from collections import defaultdict as _dd
    _rf_groups: dict[tuple, list[dict]] = _dd(list)
    _cm_groups: dict[tuple, list[dict]] = _dd(list)
    for _item in results:
        _t = _item.get("type")
        _s, _tbl = _item.get("schema"), _item.get("table")
        if _t == "row_filter" and _tbl:
            _rf_groups[(_s, _tbl)].append(_item)
        elif _t == "column_mask" and _tbl:
            _col = (_item.get("columns") or ["col"])[0]
            _cm_groups[(_s, _tbl, _col)].append(_item)

    rf_conflicts = {k: v for k, v in _rf_groups.items() if len(v) > 1}
    cm_conflicts = {k: v for k, v in _cm_groups.items() if len(v) > 1}
    n_rf_conflicts = len(rf_conflicts)
    n_cm_conflicts = len(cm_conflicts)

    if n_rf_conflicts or n_cm_conflicts:
        conflict_items = []
        for (s, tbl), grp in rf_conflicts.items():
            names = [((g.get("principal") or {}).get("name") or "?") for g in grp]
            conflict_items.append({
                "resource": f"{s}.{tbl}",
                "principal": ", ".join(names),
                "detail": f"Row filter conflict — {len(grp)} principals merged into one CASE function",
            })
        for (s, tbl, col), grp in cm_conflicts.items():
            names = [((g.get("principal") or {}).get("name") or "?") for g in grp]
            conflict_items.append({
                "resource": f"{s}.{tbl}.{col}",
                "principal": ", ".join(names),
                "detail": f"Column mask conflict — {len(grp)} principals merged into one CASE function",
            })
        gaps.append({
            "category": "Row Filter / Column Mask Conflicts Merged",
            "severity": "warning",
            "count": n_rf_conflicts + n_cm_conflicts,
            "description": (
                f"{n_rf_conflicts + n_cm_conflicts} conflict(s) detected: Unity Catalog supports only ONE "
                "row filter per table and ONE mask per column. Multiple Ranger principals targeting the "
                "same table/column have been automatically merged into combined CASE functions. "
                "Review each merged function to ensure the per-principal logic is correct."
            ),
            "items": conflict_items,
            "remediation": (
                "Open each merged function in the generated SQL and verify the CASE branches match the "
                "intended access rules. Test with representative user accounts before deploying."
            ),
        })

    warnings = parsed_data.get("warnings") or []

    deny_all_warns = [w for w in warnings if w.get("category") == "deny_all_else"]
    if deny_all_warns:
        gaps.append({
            "category": "isDenyAllElse Policies",
            "severity": "critical",
            "count": len(deny_all_warns),
            "description": (
                "These policies use isDenyAllElse=true in Ranger, meaning all principals not "
                "explicitly listed are denied. Unity Catalog has no equivalent — generated grants "
                "will not restrict unlisted principals."
            ),
            "items": [
                {
                    "resource": w.get("policyName", "—"),
                    "principal": "—",
                    "detail": "isDenyAllElse=true in Ranger",
                }
                for w in deny_all_warns
            ],
            "remediation": (
                "Audit all principals with access to these resources in UC. "
                "Only grant access to explicitly listed principals."
            ),
        })

    sched_warns = [w for w in warnings if w.get("category") == "validity_schedule"]
    if sched_warns:
        gaps.append({
            "category": "Time-Limited Policies",
            "severity": "warning",
            "count": len(sched_warns),
            "description": (
                "These policies have validity schedules (start/end times) in Ranger. "
                "Unity Catalog grants are permanent — there is no built-in expiry mechanism."
            ),
            "items": [
                {
                    "resource": w.get("policyName", "—"),
                    "principal": "—",
                    "detail": w.get("message", ""),
                }
                for w in sched_warns
            ],
            "remediation": (
                "Manage grant lifecycle manually or via automation. "
                "Revoke grants in UC when the validity period ends."
            ),
        })

    blank_warns = [w for w in warnings if w.get("category") == "blank_principal"]
    if blank_warns:
        gaps.append({
            "category": "Blank / Empty Principals Skipped",
            "severity": "warning",
            "count": len(blank_warns),
            "description": (
                "One or more Ranger policy items contain blank or empty user/group/role entries. "
                "These entries are silently skipped — no GRANT is generated and no SQL error occurs, "
                "but the intended access is not migrated."
            ),
            "items": [
                {
                    "resource": w.get("policyName", "—"),
                    "principal": "— (blank)",
                    "detail": w.get("message", ""),
                }
                for w in blank_warns
            ],
            "remediation": (
                "Open the Ranger policy and assign explicit user, group, or role names to each policy item. "
                "Re-export and re-run the migration after fixing the blank entries."
            ),
        })

    cond_warns = [w for w in warnings if w.get("category") == "conditions"]
    if cond_warns:
        gaps.append({
            "category": "Policy Conditions (Not Translated)",
            "severity": "warning",
            "count": len(cond_warns),
            "description": (
                "These policies include conditions (e.g. ip-range, time-of-day, custom evaluators) "
                "that restrict access in Ranger but have no UC equivalent. "
                "Generated grants apply unconditionally."
            ),
            "items": [
                {
                    "resource": w.get("policyName", "—"),
                    "principal": "—",
                    "detail": w.get("message", ""),
                }
                for w in cond_warns
            ],
            "remediation": (
                "Enforce IP-range and context-based restrictions at the network or application layer. "
                "Review each affected policy carefully before executing the migration SQL."
            ),
        })

    return gaps


# ─── Statistics ──────────────────────────────────────────────────────
def calculate_stats(policy_items: list[dict[str, Any]]) -> dict[str, Any]:
    stats = {
        "total": len(policy_items),
        "grants": 0, "denies": 0, "rowFilters": 0, "masks": 0,
        "hdfsGrants": 0, "hbaseGrants": 0, "udfGrants": 0,
        "tagSets": 0, "tagGrants": 0, "tagPlaceholders": 0,
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
        elif t == "hdfs_grant": stats["hdfsGrants"] += 1
        elif t == "hbase_grant": stats["hbaseGrants"] += 1
        elif t == "udf_grant": stats["udfGrants"] += 1
        elif t == "tag_set": stats["tagSets"] += 1
        elif t == "tag_grant": stats["tagGrants"] += 1
        elif t == "tag_placeholder": stats["tagPlaceholders"] += 1

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
    # Items that cannot produce any executable SQL — comment blocks only
    stats["notTranslatable"] = sum(1 for p in policy_items if is_not_translatable(p))
    return stats
