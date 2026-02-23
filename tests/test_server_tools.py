"""Tests for MCP server tool handlers.

Follows the tplink-mcp gold standard: patch external dependencies, test
success paths and error paths for every tool, verify JSON response structure.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from server import (
    _json_err,
    _json_ok,
    mcp,
    zeek_analyze_pcap,
    zeek_detect_anomalies,
    zeek_get_connections,
    zeek_list_logs,
    zeek_query_log,
    zeek_run_script,
    zeek_status,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load(raw: str) -> dict:
    """Parse a JSON tool response into a dict."""
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Server instantiation
# ---------------------------------------------------------------------------


class TestServerInstantiation:
    def test_mcp_server_created(self):
        """MCP server is instantiated with correct name."""
        assert mcp.name == "Zeek Network Security Monitoring"

    def test_tool_count(self):
        """All 7 tools are registered."""
        tools = mcp._tool_manager._tools
        assert len(tools) == 7
        expected_names = {
            "zeek_analyze_pcap",
            "zeek_query_log",
            "zeek_list_logs",
            "zeek_status",
            "zeek_run_script",
            "zeek_get_connections",
            "zeek_detect_anomalies",
        }
        assert set(tools.keys()) == expected_names


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


class TestJsonHelpers:
    def test_json_ok_structure(self):
        result = _load(_json_ok({"key": "value"}))
        assert result["status"] == "ok"
        assert result["data"]["key"] == "value"

    def test_json_err_structure(self):
        result = _load(_json_err("something went wrong"))
        assert result["status"] == "error"
        assert result["error"] == "something went wrong"


# ---------------------------------------------------------------------------
# zeek_analyze_pcap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAnalyzePcap:
    async def test_success(self, mock_dirs, mock_run_zeek, pcap_dir, output_dir):
        """Successful PCAP analysis returns expected structure."""

        # Make _run_zeek create a fake conn.log in the run dir
        async def _side_effect(args, cwd):
            cwd_path = Path(cwd)
            (cwd_path / "conn.log").write_text("#fields\tts\n1234\n")
            return (0, "", "")

        mock_run_zeek.side_effect = _side_effect

        result = _load(await zeek_analyze_pcap("test.pcap"))
        assert result["status"] == "ok"
        data = result["data"]
        assert "analysis_id" in data
        assert data["pcap"] == "test.pcap"
        assert "conn.log" in data["log_files"]

    async def test_pcap_not_found(self, mock_dirs):
        """Missing PCAP returns error with available list."""
        result = _load(await zeek_analyze_pcap("nonexistent.pcap"))
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()

    async def test_pcap_too_large(self, tmp_path, scripts_dir, output_dir, monkeypatch):
        """Oversized PCAP is rejected."""
        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir(parents=True)
        big_pcap = pcap_dir / "huge.pcap"
        # Create a file that reports as oversized
        big_pcap.write_bytes(b"\x00" * 100)

        monkeypatch.setattr("server.PCAP_DIR", pcap_dir)
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)
        monkeypatch.setattr("server.SCRIPTS_DIR", scripts_dir)
        monkeypatch.setattr("server.MAX_PCAP_SIZE", 50)  # 50 bytes limit
        monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 10)

        result = _load(await zeek_analyze_pcap("huge.pcap"))
        assert result["status"] == "error"
        assert "too large" in result["error"].lower()

    async def test_path_traversal_blocked(self, mock_dirs):
        """Path traversal attempt is rejected."""
        result = _load(await zeek_analyze_pcap("../../etc/passwd"))
        assert result["status"] == "error"
        assert "traversal" in result["error"].lower() or "not found" in result["error"].lower()

    async def test_zeek_failure_no_logs(self, mock_dirs, mock_run_zeek):
        """Zeek failure with no log output returns error."""
        mock_run_zeek.return_value = (1, "", "zeek: parse error")

        result = _load(await zeek_analyze_pcap("test.pcap"))
        assert result["status"] == "error"
        assert "failed" in result["error"].lower()

    async def test_extra_scripts_passed(self, mock_dirs, mock_run_zeek, output_dir):
        """Extra scripts are split and appended to Zeek args."""

        async def _side_effect(args, cwd):
            cwd_path = Path(cwd)
            (cwd_path / "conn.log").write_text("#fields\tts\n1234\n")
            return (0, "", "")

        mock_run_zeek.side_effect = _side_effect

        result = _load(await zeek_analyze_pcap("test.pcap", extra_scripts="local custom"))
        assert result["status"] == "ok"

        # Verify the args passed to _run_zeek included extra scripts
        call_args = mock_run_zeek.call_args[0][0]
        assert "local" in call_args
        assert "custom" in call_args


# ---------------------------------------------------------------------------
# zeek_query_log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestQueryLog:
    async def test_parse_log_success(self, analysis_dir, monkeypatch):
        """Parsing a valid log returns rows."""
        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_query_log("abc12345", "conn.log"))
        assert result["status"] == "ok"
        assert result["data"]["row_count"] == 3
        assert result["data"]["log"] == "conn.log"

    async def test_filter_log(self, analysis_dir, monkeypatch):
        """Filtering by field returns matching rows only."""
        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(
            await zeek_query_log(
                "abc12345", "dns.log", filter_field="query", filter_value="malware"
            )
        )
        assert result["status"] == "ok"
        assert result["data"]["row_count"] == 1
        assert result["data"]["rows"][0]["query"] == "malware.bad"

    async def test_log_not_found(self, analysis_dir, monkeypatch):
        """Missing log file returns error with available logs."""
        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_query_log("abc12345", "missing.log"))
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()
        assert "available" in result["error"].lower()

    async def test_analysis_not_found(self, output_dir, monkeypatch):
        """Invalid analysis ID returns error."""
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_query_log("nonexistent", "conn.log"))
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()

    async def test_limit_parameter(self, analysis_dir, monkeypatch):
        """Limit parameter restricts returned rows."""
        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_query_log("abc12345", "conn.log", limit=1))
        assert result["status"] == "ok"
        assert result["data"]["row_count"] == 1

    async def test_path_traversal_blocked(self, analysis_dir, monkeypatch):
        """Path traversal in log_name is blocked."""
        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_query_log("abc12345", "../../etc/passwd"))
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# zeek_list_logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestListLogs:
    async def test_list_success(self, analysis_dir, monkeypatch):
        """Listing logs returns summary with file counts."""
        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_list_logs("abc12345"))
        assert result["status"] == "ok"
        summary = result["data"]["summary"]
        assert summary["file_count"] == 3
        assert summary["total_rows"] > 0

    async def test_analysis_not_found(self, output_dir, monkeypatch):
        """Invalid analysis ID returns error."""
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_list_logs("nonexistent"))
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()

    async def test_path_traversal_blocked(self, output_dir, monkeypatch):
        """Path traversal in analysis_id is blocked."""
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_list_logs("../../etc"))
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# zeek_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStatus:
    async def test_success(self, mock_dirs, mock_run_zeek, pcap_dir, scripts_dir, output_dir):
        """Status tool returns expected structure."""
        mock_run_zeek.return_value = (0, "zeek version 6.0.0\n", "")

        result = _load(await zeek_status())
        assert result["status"] == "ok"
        data = result["data"]
        assert "zeek version" in data["zeek_version"].lower()
        assert "custom_scripts" in data
        assert "available_pcaps" in data
        assert "analyses" in data
        assert data["max_pcap_size_mb"] == 500
        assert data["subprocess_timeout_sec"] == 10

    async def test_with_existing_analyses(
        self, mock_dirs, mock_run_zeek, pcap_dir, scripts_dir, output_dir
    ):
        """Status includes existing analysis directories."""
        mock_run_zeek.return_value = (0, "zeek version 6.0.0\n", "")

        # Create a fake analysis
        analysis = output_dir / "abc12345"
        analysis.mkdir()
        (analysis / "conn.log").write_text("some data\n")

        result = _load(await zeek_status())
        assert result["status"] == "ok"
        assert len(result["data"]["analyses"]) == 1
        assert result["data"]["analyses"][0]["id"] == "abc12345"

    async def test_lists_custom_scripts(self, mock_dirs, mock_run_zeek, scripts_dir):
        """Status lists .zeek scripts in scripts directory."""
        mock_run_zeek.return_value = (0, "zeek version 6.0.0\n", "")

        result = _load(await zeek_status())
        scripts = result["data"]["custom_scripts"]
        assert "bgp-hijack-detect.zeek" in scripts
        assert "dns-exfil-detect.zeek" in scripts

    async def test_lists_available_pcaps(self, mock_dirs, mock_run_zeek, pcap_dir):
        """Status lists PCAP files in pcap directory."""
        mock_run_zeek.return_value = (0, "zeek version 6.0.0\n", "")

        result = _load(await zeek_status())
        pcap_names = [p["name"] for p in result["data"]["available_pcaps"]]
        assert "test.pcap" in pcap_names


# ---------------------------------------------------------------------------
# zeek_run_script
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRunScript:
    async def test_success(self, mock_dirs, mock_run_zeek, output_dir):
        """Running a custom script returns expected structure."""

        async def _side_effect(args, cwd):
            cwd_path = Path(cwd)
            (cwd_path / "notice.log").write_text("#fields\tnote\tmsg\nBGP::Hijack\tTest notice\n")
            return (0, "", "")

        mock_run_zeek.side_effect = _side_effect

        result = _load(await zeek_run_script("test.pcap", "bgp-hijack-detect.zeek"))
        assert result["status"] == "ok"
        data = result["data"]
        assert data["script"] == "bgp-hijack-detect.zeek"
        assert data["pcap"] == "test.pcap"
        assert data["return_code"] == 0

    async def test_pcap_not_found(self, mock_dirs):
        """Missing PCAP returns error."""
        result = _load(await zeek_run_script("missing.pcap", "bgp-hijack-detect.zeek"))
        assert result["status"] == "error"
        assert "pcap not found" in result["error"].lower()

    async def test_script_not_found(self, mock_dirs):
        """Missing script returns error with available list."""
        result = _load(await zeek_run_script("test.pcap", "nonexistent.zeek"))
        assert result["status"] == "error"
        assert "script not found" in result["error"].lower()

    async def test_pcap_path_traversal(self, mock_dirs):
        """Path traversal in pcap_filename is blocked."""
        result = _load(await zeek_run_script("../../etc/passwd", "bgp-hijack-detect.zeek"))
        assert result["status"] == "error"

    async def test_script_path_traversal(self, mock_dirs):
        """Path traversal in script_name is blocked."""
        result = _load(await zeek_run_script("test.pcap", "../../etc/passwd"))
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# zeek_get_connections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetConnections:
    async def test_success(self, analysis_dir, monkeypatch):
        """Connection summary returns top talkers, protocols, bytes."""
        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_get_connections("abc12345"))
        assert result["status"] == "ok"
        conn = result["data"]["connections"]
        assert conn["total_connections"] == 3
        assert conn["total_bytes"] > 0
        assert "192.168.1.10" in conn["top_sources"]
        assert "10.0.0.1" in conn["top_destinations"]

    async def test_no_conn_log(self, tmp_path, monkeypatch):
        """Missing conn.log returns error."""
        output_dir = tmp_path / "output"
        analysis = output_dir / "noconn01"
        analysis.mkdir(parents=True)
        (analysis / "dns.log").write_text("placeholder\n")
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_get_connections("noconn01"))
        assert result["status"] == "error"
        assert "conn.log not found" in result["error"]

    async def test_analysis_not_found(self, output_dir, monkeypatch):
        """Invalid analysis ID returns error."""
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        result = _load(await zeek_get_connections("nonexistent"))
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()


# ---------------------------------------------------------------------------
# zeek_detect_anomalies
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDetectAnomalies:
    async def test_success_with_notices(self, mock_dirs, mock_run_zeek, output_dir):
        """Detection with notices reports anomaly_detected=True."""
        from tests.conftest import NOTICE_LOG_CONTENT

        async def _side_effect(args, cwd):
            cwd_path = Path(cwd)
            (cwd_path / "notice.log").write_text(NOTICE_LOG_CONTENT)
            return (0, "", "")

        mock_run_zeek.side_effect = _side_effect

        result = _load(await zeek_detect_anomalies("test.pcap"))
        assert result["status"] == "ok"
        data = result["data"]
        assert data["anomaly_detected"] is True
        assert data["total_notices"] > 0
        assert data["scripts_run"] == 2  # two scripts in scripts_dir fixture

    async def test_success_no_notices(self, mock_dirs, mock_run_zeek):
        """Detection with no notices reports anomaly_detected=False."""
        mock_run_zeek.return_value = (0, "", "")

        result = _load(await zeek_detect_anomalies("test.pcap"))
        assert result["status"] == "ok"
        data = result["data"]
        assert data["anomaly_detected"] is False
        assert data["total_notices"] == 0

    async def test_pcap_not_found(self, mock_dirs):
        """Missing PCAP returns error."""
        result = _load(await zeek_detect_anomalies("missing.pcap"))
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()

    async def test_no_scripts_available(self, tmp_path, pcap_dir, output_dir, monkeypatch):
        """No custom scripts in scripts/ returns error."""
        empty_scripts = tmp_path / "empty_scripts"
        empty_scripts.mkdir()
        monkeypatch.setattr("server.PCAP_DIR", pcap_dir)
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)
        monkeypatch.setattr("server.SCRIPTS_DIR", empty_scripts)
        monkeypatch.setattr("server.MAX_PCAP_SIZE", 500 * 1024 * 1024)
        monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 10)

        result = _load(await zeek_detect_anomalies("test.pcap"))
        assert result["status"] == "error"
        assert "no custom detection scripts" in result["error"].lower()

    async def test_path_traversal_blocked(self, mock_dirs):
        """Path traversal in pcap_filename is blocked."""
        result = _load(await zeek_detect_anomalies("../../etc/passwd"))
        assert result["status"] == "error"
