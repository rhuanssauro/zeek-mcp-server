"""Pure Python parser for Zeek TSV log files.

Zeek logs use a TSV format with metadata lines prefixed by '#'.
The #fields line defines column names. The #types line defines types.
Data lines are tab-separated values aligned to those fields.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any


def parse_zeek_log(log_path: str, limit: int = 0) -> list[dict[str, str]]:
    """Parse a single Zeek TSV log file into a list of dicts.

    Args:
        log_path: Path to the Zeek log file.
        limit: Max rows to return (0 = all).

    Returns:
        List of dicts keyed by field name.
    """
    path = Path(log_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    fields: list[str] = []
    rows: list[dict[str, str]] = []

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue

            values = line.split("\t")
            row = {}
            for i, field in enumerate(fields):
                row[field] = values[i] if i < len(values) else "-"
            rows.append(row)

            if limit and len(rows) >= limit:
                break

    return rows


def parse_all_logs(directory: str) -> dict[str, list[dict[str, str]]]:
    """Parse every .log file in a directory.

    Args:
        directory: Path to directory containing Zeek log files.

    Returns:
        Dict mapping log filename to parsed rows.
    """
    results: dict[str, list[dict[str, str]]] = {}
    dir_path = Path(directory)

    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    for log_file in sorted(dir_path.glob("*.log")):
        try:
            rows = parse_zeek_log(str(log_file))
            results[log_file.name] = rows
        except Exception:
            results[log_file.name] = []

    return results


def get_log_summary(directory: str) -> dict[str, Any]:
    """Produce a summary of all log files in a directory.

    Args:
        directory: Path to directory containing Zeek log files.

    Returns:
        Dict with file_count, files list (name, rows, size_bytes), total_rows.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    files_info: list[dict[str, Any]] = []
    total_rows = 0

    for log_file in sorted(dir_path.glob("*.log")):
        row_count = 0
        try:
            with open(log_file, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not line.startswith("#") and line.strip():
                        row_count += 1
        except Exception:
            pass

        total_rows += row_count
        files_info.append(
            {
                "name": log_file.name,
                "rows": row_count,
                "size_bytes": os.path.getsize(log_file),
            }
        )

    return {
        "file_count": len(files_info),
        "files": files_info,
        "total_rows": total_rows,
    }


def filter_log(
    log_path: str,
    field: str,
    value: str,
    limit: int = 100,
) -> list[dict[str, str]]:
    """Filter a Zeek log by a field value.

    Args:
        log_path: Path to the Zeek log file.
        field: Field name to filter on.
        value: Value to match (case-insensitive substring).
        limit: Max matching rows to return.

    Returns:
        Filtered list of row dicts.
    """
    rows = parse_zeek_log(log_path)
    value_lower = value.lower()
    matched = []

    for row in rows:
        if field not in row:
            continue
        if value_lower in row[field].lower():
            matched.append(row)
            if len(matched) >= limit:
                break

    return matched


def get_connections_summary(conn_log_path: str) -> dict[str, Any]:
    """Summarize conn.log: top talkers, protocols, ports, durations.

    Args:
        conn_log_path: Path to conn.log.

    Returns:
        Dict with top_sources, top_destinations, top_services,
        protocol_counts, total_connections, total_bytes.
    """
    rows = parse_zeek_log(conn_log_path)

    src_counter: Counter[str] = Counter()
    dst_counter: Counter[str] = Counter()
    service_counter: Counter[str] = Counter()
    proto_counter: Counter[str] = Counter()
    total_orig_bytes = 0
    total_resp_bytes = 0

    for row in rows:
        src = row.get("id.orig_h", "-")
        dst = row.get("id.resp_h", "-")
        service = row.get("service", "-")
        proto = row.get("proto", "-")

        src_counter[src] += 1
        dst_counter[dst] += 1
        if service != "-":
            service_counter[service] += 1
        proto_counter[proto] += 1

        try:
            total_orig_bytes += int(row.get("orig_bytes", "0"))
        except ValueError:
            pass
        try:
            total_resp_bytes += int(row.get("resp_bytes", "0"))
        except ValueError:
            pass

    return {
        "total_connections": len(rows),
        "total_orig_bytes": total_orig_bytes,
        "total_resp_bytes": total_resp_bytes,
        "total_bytes": total_orig_bytes + total_resp_bytes,
        "top_sources": dict(src_counter.most_common(10)),
        "top_destinations": dict(dst_counter.most_common(10)),
        "top_services": dict(service_counter.most_common(10)),
        "protocol_counts": dict(proto_counter.most_common()),
    }
