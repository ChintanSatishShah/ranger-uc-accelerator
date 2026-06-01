"""Session history and archiving — save/load migration sessions as JSON."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st


HISTORY_DIR = Path(__file__).parent.parent / "data" / "output"
HISTORY_DIR.mkdir(exist_ok=True)
SQL_DIR = Path(__file__).parent.parent / "data" / "output_sql"


def _load_sql_for_archive(filename: str) -> str:
    """Load pre-generated SQL from data/output_sql/ matching the archive filename."""
    if not filename:
        return ""
    basename = Path(filename).stem
    sql_path = SQL_DIR / f"{basename}.sql"
    if sql_path.exists():
        return sql_path.read_text()
    return ""


_INPUT_DIR = Path(__file__).parent.parent / "data" / "input"


def _infer_source_file(filename: str) -> str:
    """Return the input filename if a matching file exists in data/input/."""
    if not filename:
        return ""
    basename = Path(filename).name  # e.g. masking_complex.json
    if (_INPUT_DIR / basename).exists():
        return basename
    return ""


def _normalize_archive(data: dict[str, Any], filename: str = "") -> dict[str, Any]:
    """Normalize both old flat camelCase and new nested snake_case archive formats."""
    if "metadata" in data and "parsed_data" in data:
        result = dict(data)
        if not result.get("generated_sql"):
            result["generated_sql"] = _load_sql_for_archive(filename)
        if not result["metadata"].get("source_file"):
            result["metadata"] = {**result["metadata"], "source_file": _infer_source_file(filename)}
        return result

    # Old flat camelCase format
    service_name = data.get("serviceName", "unknown")
    catalog_name = data.get("catalogName", "main")
    cluster_name = data.get("clusterName", "unknown")
    policy_items = data.get("policyItems", [])
    identity_map = data.get("identityMap", {})
    generated_sql = data.get("generatedSQL", "") or _load_sql_for_archive(filename)
    source_file = data.get("source_file", "") or _infer_source_file(filename)

    parsed_data = {
        "serviceName": service_name,
        "catalogName": catalog_name,
        "clusterName": cluster_name,
        "serviceType": data.get("serviceType", "hive"),
        "totalRangerPolicies": data.get("totalRangerPolicies", len(policy_items)),
        "results": policy_items,
        "warnings": [],
        "identities": [],
        "kerberosIssues": [],
        "stats": data.get("stats", {}),
    }

    return {
        "metadata": {
            "timestamp": data.get("timestamp", ""),
            "service_name": service_name,
            "catalog_name": catalog_name,
            "cluster_name": cluster_name,
            "notes": data.get("notes", ""),
            "source_file": source_file,
        },
        "parsed_data": parsed_data,
        "policy_items": policy_items,
        "identity_map": identity_map,
        "generated_sql": generated_sql,
    }


def _sanitize_filename(name: str, max_len: int = 40) -> str:
    """Sanitize service name for use as filename."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name.lower())
    return safe[:max_len]


def save_session(parsed_data: dict[str, Any], policy_items: list[Any],
                 identity_map: dict[str, str], catalog_name: str,
                 generated_sql: str, notes: str = "", label: str = "",
                 add_timestamp: bool = True, source_file: str = "") -> str:
    """Save current session to JSON archive. Returns filename.

    label:         slug used as the filename base.
    add_timestamp: when False the filename is exactly <label>.json (for sample archives).
    source_file:   original input filename stored in metadata for reference.
    """
    if not parsed_data:
        raise ValueError("No policies loaded to archive.")

    timestamp = datetime.utcnow().isoformat()
    service_name = parsed_data.get("serviceName", "ranger_export")
    safe_name = _sanitize_filename(service_name)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if label:
        base = _sanitize_filename(label, max_len=80)
        filename = f"{base}.json" if not add_timestamp else f"{base}_{ts}.json"
    else:
        filename = f"{safe_name}_{ts}.json"
    filepath = HISTORY_DIR / filename

    archive = {
        "metadata": {
            "timestamp": timestamp,
            "service_name": service_name,
            "cluster_name": parsed_data.get("clusterName", "unknown"),
            "catalog_name": catalog_name,
            "source_file": source_file or label or service_name,
            "notes": notes,
        },
        "parsed_data": parsed_data,
        "policy_items": policy_items,
        "identity_map": identity_map,
        "generated_sql": generated_sql,
    }
    
    with open(filepath, "w") as f:
        json.dump(archive, f, indent=2, default=str)
    
    return filename


def load_session(filename: str) -> dict[str, Any]:
    """Load a session from archive."""
    filepath = HISTORY_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(f"Archive not found: {filename}")

    with open(filepath, "r") as f:
        archive = json.load(f)

    return _normalize_archive(archive, filename)


def list_archives() -> list[dict[str, Any]]:
    """List all archived sessions with metadata and preview content."""
    archives = []
    for filepath in sorted(HISTORY_DIR.glob("*.json"), reverse=True):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            normalized = _normalize_archive(data, filepath.name)
            archives.append({
                "filename": filepath.name,
                "metadata": normalized["metadata"],
                "filepath": str(filepath),
                "size_kb": filepath.stat().st_size / 1024,
                "parsed_data": normalized["parsed_data"],
                "policy_items": normalized["policy_items"],
                "identity_map": normalized["identity_map"],
                "generated_sql": normalized["generated_sql"],
            })
        except (json.JSONDecodeError, OSError):
            continue
    return archives


def delete_archive(filename: str) -> None:
    """Delete an archived session."""
    filepath = HISTORY_DIR / filename
    if filepath.exists():
        filepath.unlink()


def export_session_as_zip(filename: str) -> bytes:
    """Export a session (JSON + SQL + metadata) as a downloadable package."""
    import io
    import zipfile
    
    archive = load_session(filename)
    metadata = archive["metadata"]
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Metadata
        zf.writestr("METADATA.json", json.dumps(metadata, indent=2))
        # Original export
        zf.writestr("ranger_export.json", json.dumps(archive["parsed_data"], indent=2))
        # Generated SQL
        zf.writestr("generated_migration.sql", archive.get("generated_sql", ""))
        # Policy items
        zf.writestr("policy_items.json", json.dumps(archive["policy_items"], indent=2))
        # Identity mappings
        zf.writestr("identity_map.json", json.dumps(archive["identity_map"], indent=2))
    
    zip_buffer.seek(0)
    return zip_buffer.getvalue()
