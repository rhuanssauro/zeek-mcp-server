"""Tests for input validation and security boundaries.

Covers path traversal prevention, PCAP size limits, subprocess timeout handling,
and invalid input rejection in the server module.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server import _safe_path


# ---------------------------------------------------------------------------
# _safe_path — path traversal prevention
# ---------------------------------------------------------------------------


class TestSafePath:
    def test_valid_simple_filename(self, tmp_path: Path):
        """Simple filename resolves within base directory."""
        (tmp_path / "test.pcap").touch()
        result = _safe_path(tmp_path, "test.pcap")
        assert result == (tmp_path / "test.pcap").resolve()

    def test_valid_subdirectory(self, tmp_path: Path):
        """Filename in subdirectory resolves within base."""
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "file.log").touch()
        result = _safe_path(tmp_path, "sub/file.log")
        assert result == (sub / "file.log").resolve()

    def test_rejects_parent_traversal(self, tmp_path: Path):
        """../  traversal is rejected."""
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            _safe_path(tmp_path, "../etc/passwd")

    def test_rejects_deep_traversal(self, tmp_path: Path):
        """Multiple levels of traversal are rejected."""
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            _safe_path(tmp_path, "../../../etc/shadow")

    def test_rejects_absolute_path(self, tmp_path: Path):
        """Absolute path that escapes base is rejected."""
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            _safe_path(tmp_path, "/etc/passwd")

    def test_rejects_dot_dot_in_middle(self, tmp_path: Path):
        """Traversal in middle of path is rejected."""
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            _safe_path(tmp_path, "subdir/../../etc/passwd")

    def test_normalizes_redundant_slashes(self, tmp_path: Path):
        """Redundant slashes are resolved without escaping base."""
        (tmp_path / "file.log").touch()
        result = _safe_path(tmp_path, "./file.log")
        assert result == (tmp_path / "file.log").resolve()

    def test_allows_dotfile(self, tmp_path: Path):
        """Dotfiles (hidden files) within base are allowed."""
        (tmp_path / ".hidden").touch()
        result = _safe_path(tmp_path, ".hidden")
        assert result == (tmp_path / ".hidden").resolve()


# ---------------------------------------------------------------------------
# PCAP size limit enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPcapSizeLimits:
    async def test_accepts_file_under_limit(self, tmp_path, monkeypatch):
        """PCAP under size limit proceeds to analysis."""
        from server import zeek_analyze_pcap

        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        small = pcap_dir / "small.pcap"
        small.write_bytes(b"\x00" * 100)

        monkeypatch.setattr("server.PCAP_DIR", pcap_dir)
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)
        monkeypatch.setattr("server.SCRIPTS_DIR", scripts_dir)
        monkeypatch.setattr("server.MAX_PCAP_SIZE", 1024)  # 1KB limit
        monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 10)

        with patch("server._run_zeek", new_callable=AsyncMock) as mock_zeek:
            mock_zeek.return_value = (0, "", "")
            import json

            result = json.loads(await zeek_analyze_pcap("small.pcap"))
            assert result["status"] == "ok"

    async def test_rejects_file_over_limit(self, tmp_path, monkeypatch):
        """PCAP over size limit is rejected with descriptive error."""
        from server import zeek_analyze_pcap

        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        big = pcap_dir / "big.pcap"
        big.write_bytes(b"\x00" * 2000)

        monkeypatch.setattr("server.PCAP_DIR", pcap_dir)
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)
        monkeypatch.setattr("server.SCRIPTS_DIR", scripts_dir)
        monkeypatch.setattr("server.MAX_PCAP_SIZE", 1024)  # 1KB limit
        monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 10)

        import json

        result = json.loads(await zeek_analyze_pcap("big.pcap"))
        assert result["status"] == "error"
        assert "too large" in result["error"].lower()

    async def test_exact_boundary_accepted(self, tmp_path, monkeypatch):
        """PCAP at exactly the size limit is accepted."""
        from server import zeek_analyze_pcap

        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        exact = pcap_dir / "exact.pcap"
        exact.write_bytes(b"\x00" * 1024)

        monkeypatch.setattr("server.PCAP_DIR", pcap_dir)
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)
        monkeypatch.setattr("server.SCRIPTS_DIR", scripts_dir)
        monkeypatch.setattr("server.MAX_PCAP_SIZE", 1024)
        monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 10)

        with patch("server._run_zeek", new_callable=AsyncMock) as mock_zeek:
            mock_zeek.return_value = (0, "", "")
            import json

            result = json.loads(await zeek_analyze_pcap("exact.pcap"))
            assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# Subprocess timeout handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSubprocessTimeout:
    async def test_run_zeek_timeout(self, monkeypatch):
        """_run_zeek returns error tuple on timeout."""
        from server import _run_zeek

        monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 0.001)

        call_count = 0

        async def slow_then_fast():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                await asyncio.sleep(10)
            return (b"", b"")

        mock_proc = AsyncMock()
        mock_proc.communicate = slow_then_fast
        mock_proc.kill = MagicMock()
        mock_proc.returncode = -1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            returncode, stdout, stderr = await _run_zeek(["--version"], "/tmp")
            assert returncode == -1
            assert "timed out" in stderr.lower()

    async def test_run_zeek_success(self, monkeypatch):
        """_run_zeek returns success tuple for quick commands."""
        from server import _run_zeek

        monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 10)

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"zeek version 6.0\n", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(b"zeek version 6.0\n", b"")):
                returncode, stdout, stderr = await _run_zeek(["--version"], "/tmp")
                assert returncode == 0


# ---------------------------------------------------------------------------
# Invalid input rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestInvalidInputRejection:
    async def test_empty_pcap_filename(self, mock_dirs):
        """Empty PCAP filename is handled gracefully."""
        from server import zeek_analyze_pcap

        import json

        result = json.loads(await zeek_analyze_pcap(""))
        assert result["status"] == "error"

    async def test_empty_analysis_id(self, output_dir, monkeypatch):
        """Empty analysis ID is handled gracefully."""
        from server import zeek_query_log

        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        import json

        result = json.loads(await zeek_query_log("", "conn.log"))
        assert result["status"] == "error"

    async def test_empty_log_name(self, analysis_dir, monkeypatch):
        """Empty log name is handled gracefully."""
        from server import zeek_query_log

        output_dir = analysis_dir.parent
        monkeypatch.setattr("server.OUTPUT_DIR", output_dir)

        import json

        result = json.loads(await zeek_query_log("abc12345", ""))
        assert result["status"] == "error"

    async def test_special_characters_in_filename(self, mock_dirs):
        """Special characters in filenames are handled safely."""
        from server import zeek_analyze_pcap

        import json

        result = json.loads(await zeek_analyze_pcap("test;rm -rf /.pcap"))
        assert result["status"] == "error"

    async def test_null_bytes_in_path(self, mock_dirs):
        """Null bytes in path components are rejected."""
        from server import zeek_analyze_pcap

        import json

        result = json.loads(await zeek_analyze_pcap("test\x00.pcap"))
        assert result["status"] == "error"
