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
    
    return archive


def list_archives() -> list[dict[str, Any]]:
    """List all archived sessions with metadata and preview content."""
    archives = []
    for filepath in sorted(HISTORY_DIR.glob("*.json"), reverse=True):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            archives.append({
                "filename": filepath.name,
                "metadata": data.get("metadata", {}),
                "filepath": str(filepath),
                "size_kb": filepath.stat().st_size / 1024,
                "policy_items": data.get("policy_items", []),
                "identity_map": data.get("identity_map", {}),
                "generated_sql": data.get("generated_sql", ""),
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
