#!/usr/bin/env python3
"""Zeek MCP Server - PCAP analysis and network security monitoring.

Provides MCP tools for analyzing PCAP files with Zeek, parsing generated logs,
running custom detection scripts, and summarizing network connections.
Designed for Docker deployment with isolated analysis directories per run.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("ZeekMCPServer")

mcp = FastMCP("Zeek Network Security Monitoring")

PCAP_DIR = Path(os.getenv("ZEEK_PCAP_DIR", "/app/pcaps"))
OUTPUT_DIR = Path(os.getenv("ZEEK_OUTPUT_DIR", "/app/output"))
SCRIPTS_DIR = Path(os.getenv("ZEEK_SCRIPTS_DIR", "/app/scripts"))
MAX_PCAP_SIZE = int(os.getenv("ZEEK_MAX_PCAP_MB", "500")) * 1024 * 1024
SUBPROCESS_TIMEOUT = int(os.getenv("ZEEK_TIMEOUT", "300"))


def _safe_path(base: Path, user_path: str) -> Path:
    """Resolve a user-supplied path and ensure it stays within base directory."""
    resolved = (base / user_path).resolve()
    base_resolved = base.resolve()
    if not str(resolved).startswith(str(base_resolved)):
        raise ValueError(f"Path traversal blocked: {user_path}")
    return resolved


def _json_ok(data: Any) -> str:
    return json.dumps({"status": "ok", "data": data}, indent=2, default=str)


def _json_err(error: str) -> str:
    return json.dumps({"status": "error", "error": error})


async def _run_zeek(args: list[str], cwd: str) -> tuple[int, str, str]:
    """Run Zeek as an async subprocess with timeout."""
    proc = await asyncio.create_subprocess_exec(
        "zeek", *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=SUBPROCESS_TIMEOUT,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return -1, "", f"Zeek timed out after {SUBPROCESS_TIMEOUT}s"

    return (
        proc.returncode or 0,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


# Import parser functions
from zeek_parser import (
    filter_log,
    get_connections_summary,
    get_log_summary,
    parse_zeek_log,
)


@mcp.tool()
async def zeek_analyze_pcap(
    pcap_filename: str,
    extra_scripts: str = "",
) -> str:
    """Analyze a PCAP file with Zeek and produce structured logs.

    Each analysis creates an isolated output directory to prevent log clobbering.
    Returns the analysis ID and list of generated log files.

    Args:
        pcap_filename: Name of PCAP file in the pcaps/ directory (e.g., "capture.pcap").
        extra_scripts: Optional space-separated Zeek scripts to load (e.g., "local protocols/ssl/validate-certs").
    """
    try:
        pcap_path = _safe_path(PCAP_DIR, pcap_filename)
    except ValueError as e:
        return _json_err(str(e))

    if not pcap_path.is_file():
        available = [f.name for f in PCAP_DIR.glob("*.pcap*") if f.is_file()]
        return _json_err(
            f"PCAP not found: {pcap_filename}. "
            f"Available: {available or 'none - place PCAPs in pcaps/ directory'}"
        )

    file_size = pcap_path.stat().st_size
    if file_size > MAX_PCAP_SIZE:
        return _json_err(
            f"PCAP too large: {file_size / 1024 / 1024:.1f}MB "
            f"(max {MAX_PCAP_SIZE / 1024 / 1024:.0f}MB)"
        )

    analysis_id = str(uuid.uuid4())[:8]
    run_dir = OUTPUT_DIR / analysis_id
    run_dir.mkdir(parents=True, exist_ok=True)

    args = ["-r", str(pcap_path)]
    if extra_scripts:
        args.extend(extra_scripts.split())

    logger.info(f"Analyzing {pcap_filename} -> {run_dir} (id: {analysis_id})")
    returncode, stdout, stderr = await _run_zeek(args, str(run_dir))

    log_files = sorted(f.name for f in run_dir.glob("*.log"))

    if returncode != 0 and not log_files:
        return _json_err(f"Zeek failed (rc={returncode}): {stderr[:500]}")

    summary = get_log_summary(str(run_dir))

    return _json_ok({
        "analysis_id": analysis_id,
        "pcap": pcap_filename,
        "pcap_size_bytes": file_size,
        "log_files": log_files,
        "summary": summary,
        "zeek_stderr": stderr[:300] if stderr else "",
    })


@mcp.tool()
async def zeek_query_log(
    analysis_id: str,
    log_name: str,
    filter_field: str = "",
    filter_value: str = "",
    limit: int = 50,
) -> str:
    """Parse and optionally filter a Zeek log file from a previous analysis.

    Args:
        analysis_id: Analysis ID returned by zeek_analyze_pcap.
        log_name: Log file name (e.g., "conn.log", "dns.log", "http.log").
        filter_field: Optional field name to filter on (e.g., "id.resp_h", "query").
        filter_value: Value to match (case-insensitive substring).
        limit: Maximum rows to return (default 50).
    """
    try:
        log_path = _safe_path(OUTPUT_DIR / analysis_id, log_name)
    except ValueError as e:
        return _json_err(str(e))

    if not log_path.is_file():
        run_dir = OUTPUT_DIR / analysis_id
        if not run_dir.is_dir():
            return _json_err(f"Analysis ID not found: {analysis_id}")
        available = [f.name for f in run_dir.glob("*.log")]
        return _json_err(f"Log not found: {log_name}. Available: {available}")

    try:
        if filter_field and filter_value:
            rows = filter_log(str(log_path), filter_field, filter_value, limit)
        else:
            rows = parse_zeek_log(str(log_path), limit)
    except Exception as e:
        return _json_err(f"Parse error: {e}")

    return _json_ok({
        "analysis_id": analysis_id,
        "log": log_name,
        "row_count": len(rows),
        "rows": rows,
    })


@mcp.tool()
async def zeek_list_logs(analysis_id: str) -> str:
    """List all generated log files from a previous analysis.

    Args:
        analysis_id: Analysis ID returned by zeek_analyze_pcap.
    """
    try:
        run_dir = _safe_path(OUTPUT_DIR, analysis_id)
    except ValueError as e:
        return _json_err(str(e))

    if not run_dir.is_dir():
        analyses = [d.name for d in OUTPUT_DIR.iterdir() if d.is_dir()]
        return _json_err(
            f"Analysis not found: {analysis_id}. "
            f"Available analyses: {analyses or 'none'}"
        )

    try:
        summary = get_log_summary(str(run_dir))
    except Exception as e:
        return _json_err(f"Error reading logs: {e}")

    return _json_ok({
        "analysis_id": analysis_id,
        "summary": summary,
    })


@mcp.tool()
async def zeek_status() -> str:
    """Get Zeek version, available custom scripts, and output directory disk usage."""
    returncode, stdout, stderr = await _run_zeek(["--version"], "/tmp")
    version = stdout.strip() or stderr.strip()

    custom_scripts: list[str] = []
    if SCRIPTS_DIR.is_dir():
        custom_scripts = sorted(
            f.name for f in SCRIPTS_DIR.glob("*.zeek") if f.is_file()
        )

    analyses: list[dict[str, Any]] = []
    total_size = 0
    if OUTPUT_DIR.is_dir():
        for d in sorted(OUTPUT_DIR.iterdir()):
            if d.is_dir():
                dir_size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
                log_count = len(list(d.glob("*.log")))
                analyses.append({
                    "id": d.name,
                    "log_count": log_count,
                    "size_bytes": dir_size,
                })
                total_size += dir_size

    available_pcaps: list[dict[str, Any]] = []
    if PCAP_DIR.is_dir():
        for f in sorted(PCAP_DIR.glob("*")):
            if f.is_file() and f.suffix in (".pcap", ".pcapng", ".cap"):
                available_pcaps.append({
                    "name": f.name,
                    "size_bytes": f.stat().st_size,
                })

    return _json_ok({
        "zeek_version": version,
        "custom_scripts": custom_scripts,
        "pcap_directory": str(PCAP_DIR),
        "available_pcaps": available_pcaps,
        "analyses": analyses,
        "output_disk_usage_bytes": total_size,
        "max_pcap_size_mb": MAX_PCAP_SIZE // (1024 * 1024),
        "subprocess_timeout_sec": SUBPROCESS_TIMEOUT,
    })


@mcp.tool()
async def zeek_run_script(
    pcap_filename: str,
    script_name: str,
) -> str:
    """Run a custom Zeek script against a PCAP file.

    Custom scripts are mounted in the scripts/ directory.

    Args:
        pcap_filename: Name of PCAP file in the pcaps/ directory.
        script_name: Name of the .zeek script in scripts/ (e.g., "bgp-hijack-detect.zeek").
    """
    try:
        pcap_path = _safe_path(PCAP_DIR, pcap_filename)
        script_path = _safe_path(SCRIPTS_DIR, script_name)
    except ValueError as e:
        return _json_err(str(e))

    if not pcap_path.is_file():
        return _json_err(f"PCAP not found: {pcap_filename}")

    if not script_path.is_file():
        available = [f.name for f in SCRIPTS_DIR.glob("*.zeek")]
        return _json_err(
            f"Script not found: {script_name}. Available: {available or 'none'}"
        )

    analysis_id = f"script-{str(uuid.uuid4())[:8]}"
    run_dir = OUTPUT_DIR / analysis_id
    run_dir.mkdir(parents=True, exist_ok=True)

    args = ["-r", str(pcap_path), str(script_path)]
    logger.info(f"Running script {script_name} on {pcap_filename} -> {run_dir}")
    returncode, stdout, stderr = await _run_zeek(args, str(run_dir))

    log_files = sorted(f.name for f in run_dir.glob("*.log"))
    notice_file = run_dir / "notice.log"
    notices: list[dict[str, str]] = []
    if notice_file.is_file():
        try:
            notices = parse_zeek_log(str(notice_file))
        except Exception:
            pass

    return _json_ok({
        "analysis_id": analysis_id,
        "script": script_name,
        "pcap": pcap_filename,
        "return_code": returncode,
        "log_files": log_files,
        "notices": notices,
        "stdout": stdout[:500] if stdout else "",
        "stderr": stderr[:500] if stderr else "",
    })


@mcp.tool()
async def zeek_get_connections(
    analysis_id: str,
) -> str:
    """Get connection summary from conn.log: top talkers, protocols, byte counts.

    Args:
        analysis_id: Analysis ID returned by zeek_analyze_pcap.
    """
    conn_log = OUTPUT_DIR / analysis_id / "conn.log"

    if not conn_log.is_file():
        run_dir = OUTPUT_DIR / analysis_id
        if not run_dir.is_dir():
            return _json_err(f"Analysis not found: {analysis_id}")
        return _json_err(
            f"conn.log not found in analysis {analysis_id}. "
            f"Available logs: {[f.name for f in run_dir.glob('*.log')]}"
        )

    try:
        summary = get_connections_summary(str(conn_log))
    except Exception as e:
        return _json_err(f"Error parsing conn.log: {e}")

    return _json_ok({
        "analysis_id": analysis_id,
        "connections": summary,
    })


@mcp.tool()
async def zeek_detect_anomalies(
    pcap_filename: str,
) -> str:
    """Run all custom detection scripts (BGP hijack, OSPF anomaly, DNS exfiltration) against a PCAP.

    Runs each available custom .zeek script in the scripts/ directory against the PCAP
    and aggregates results. Notices from notice.log indicate detected anomalies.

    Args:
        pcap_filename: Name of PCAP file in the pcaps/ directory.
    """
    try:
        pcap_path = _safe_path(PCAP_DIR, pcap_filename)
    except ValueError as e:
        return _json_err(str(e))

    if not pcap_path.is_file():
        return _json_err(f"PCAP not found: {pcap_filename}")

    custom_scripts = sorted(SCRIPTS_DIR.glob("*.zeek")) if SCRIPTS_DIR.is_dir() else []
    if not custom_scripts:
        return _json_err("No custom detection scripts found in scripts/ directory")

    analysis_id = f"detect-{str(uuid.uuid4())[:8]}"
    all_results: list[dict[str, Any]] = []
    all_notices: list[dict[str, str]] = []

    for script in custom_scripts:
        run_dir = OUTPUT_DIR / analysis_id / script.stem
        run_dir.mkdir(parents=True, exist_ok=True)

        args = ["-r", str(pcap_path), str(script)]
        logger.info(f"Detection: {script.name} on {pcap_filename}")
        returncode, stdout, stderr = await _run_zeek(args, str(run_dir))

        log_files = sorted(f.name for f in run_dir.glob("*.log"))
        notices: list[dict[str, str]] = []
        notice_file = run_dir / "notice.log"
        if notice_file.is_file():
            try:
                notices = parse_zeek_log(str(notice_file))
                all_notices.extend(notices)
            except Exception:
                pass

        all_results.append({
            "script": script.name,
            "return_code": returncode,
            "log_files": log_files,
            "notice_count": len(notices),
            "notices": notices,
            "stderr": stderr[:200] if stderr else "",
        })

    anomaly_detected = len(all_notices) > 0

    return _json_ok({
        "analysis_id": analysis_id,
        "pcap": pcap_filename,
        "scripts_run": len(all_results),
        "anomaly_detected": anomaly_detected,
        "total_notices": len(all_notices),
        "results": all_results,
    })


if __name__ == "__main__":
    logger.info("Starting Zeek MCP Server...")
    mcp.run()
