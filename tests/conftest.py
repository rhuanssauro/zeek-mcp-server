"""Shared test fixtures for zeek-mcp-server tests."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Sample Zeek log content
# ---------------------------------------------------------------------------

CONN_LOG_CONTENT = textwrap.dedent("""\
    #separator \\x09
    #set_separator\t,
    #empty_field\t(empty)
    #unset_field\t-
    #path\tconn
    #open\t2024-01-15-12-00-00
    #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory
    #types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring
    1705312800.000000\tCabc123\t192.168.1.10\t54321\t10.0.0.1\t80\ttcp\thttp\t1.234\t500\t1500\tSF\tShAdDafF
    1705312801.000000\tCdef456\t192.168.1.10\t54322\t10.0.0.2\t443\ttcp\tssl\t2.345\t800\t2400\tSF\tShAdDafF
    1705312802.000000\tCghi789\t192.168.1.20\t12345\t10.0.0.1\t53\tudp\tdns\t0.001\t40\t120\tSF\tDd
    #close\t2024-01-15-12-05-00
""")

DNS_LOG_CONTENT = textwrap.dedent("""\
    #separator \\x09
    #set_separator\t,
    #empty_field\t(empty)
    #unset_field\t-
    #path\tdns
    #open\t2024-01-15-12-00-00
    #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\trcode_name
    #types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tstring\tstring
    1705312802.000000\tCghi789\t192.168.1.20\t12345\t10.0.0.1\t53\tudp\texample.com\tA\tNOERROR
    1705312803.000000\tCjkl012\t192.168.1.20\t12346\t10.0.0.1\t53\tudp\tmalware.bad\tA\tNXDOMAIN
    #close\t2024-01-15-12-05-00
""")

HTTP_LOG_CONTENT = textwrap.dedent("""\
    #separator \\x09
    #set_separator\t,
    #empty_field\t(empty)
    #unset_field\t-
    #path\thttp
    #open\t2024-01-15-12-00-00
    #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\tstatus_code
    #types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tcount
    1705312800.000000\tCabc123\t192.168.1.10\t54321\t10.0.0.1\t80\tGET\texample.com\t/index.html\t200
    #close\t2024-01-15-12-05-00
""")

NOTICE_LOG_CONTENT = textwrap.dedent("""\
    #separator \\x09
    #set_separator\t,
    #empty_field\t(empty)
    #unset_field\t-
    #path\tnotice
    #open\t2024-01-15-12-00-00
    #fields\tts\tnote\tmsg\tsrc\tdst
    #types\ttime\tenum\tstring\taddr\taddr
    1705312805.000000\tBGP::HijackDetected\tSuspicious BGP announcement\t192.168.1.100\t10.0.0.50
    #close\t2024-01-15-12-05-00
""")

EMPTY_LOG_CONTENT = textwrap.dedent("""\
    #separator \\x09
    #set_separator\t,
    #empty_field\t(empty)
    #unset_field\t-
    #path\tempty
    #open\t2024-01-15-12-00-00
    #fields\tts\tuid\tdata
    #types\ttime\tstring\tstring
    #close\t2024-01-15-12-05-00
""")


# ---------------------------------------------------------------------------
# Filesystem fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def analysis_dir(tmp_path: Path) -> Path:
    """Create a mock analysis output directory with sample Zeek logs."""
    analysis_id = "abc12345"
    run_dir = tmp_path / "output" / analysis_id
    run_dir.mkdir(parents=True)

    (run_dir / "conn.log").write_text(CONN_LOG_CONTENT)
    (run_dir / "dns.log").write_text(DNS_LOG_CONTENT)
    (run_dir / "http.log").write_text(HTTP_LOG_CONTENT)

    return run_dir


@pytest.fixture()
def analysis_dir_with_notices(tmp_path: Path) -> Path:
    """Create a mock analysis directory that includes notice.log."""
    analysis_id = "notice01"
    run_dir = tmp_path / "output" / analysis_id
    run_dir.mkdir(parents=True)

    (run_dir / "conn.log").write_text(CONN_LOG_CONTENT)
    (run_dir / "notice.log").write_text(NOTICE_LOG_CONTENT)

    return run_dir


@pytest.fixture()
def empty_analysis_dir(tmp_path: Path) -> Path:
    """Create an analysis directory with a log that has no data rows."""
    analysis_id = "empty001"
    run_dir = tmp_path / "output" / analysis_id
    run_dir.mkdir(parents=True)

    (run_dir / "empty.log").write_text(EMPTY_LOG_CONTENT)

    return run_dir


@pytest.fixture()
def pcap_dir(tmp_path: Path) -> Path:
    """Create a mock PCAP directory with a small fake PCAP file."""
    pcap_path = tmp_path / "pcaps"
    pcap_path.mkdir(parents=True)

    # Create a minimal fake PCAP file (not a real PCAP, just file existence)
    fake_pcap = pcap_path / "test.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)  # magic bytes + padding

    return pcap_path


@pytest.fixture()
def large_pcap(tmp_path: Path) -> Path:
    """Create a PCAP file that exceeds the size limit."""
    pcap_path = tmp_path / "pcaps"
    pcap_path.mkdir(parents=True)

    oversized = pcap_path / "huge.pcap"
    # Write just enough to be detectable as over-limit; actual content does not matter
    oversized.write_bytes(b"\x00" * (501 * 1024 * 1024))

    return pcap_path


@pytest.fixture()
def scripts_dir(tmp_path: Path) -> Path:
    """Create a mock Zeek scripts directory."""
    scripts_path = tmp_path / "scripts"
    scripts_path.mkdir(parents=True)

    (scripts_path / "bgp-hijack-detect.zeek").write_text("# stub zeek script\n")
    (scripts_path / "dns-exfil-detect.zeek").write_text("# stub zeek script\n")

    return scripts_path


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    """Provide a clean output directory path."""
    out = tmp_path / "output"
    out.mkdir(parents=True)
    return out


# ---------------------------------------------------------------------------
# Environment / module-level patching helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_dirs(tmp_path: Path, pcap_dir: Path, scripts_dir: Path, output_dir: Path, monkeypatch):
    """Patch server-level directory constants to use temp paths.

    Returns the tmp_path for convenience.
    """
    monkeypatch.setattr("server.PCAP_DIR", pcap_dir)
    monkeypatch.setattr("server.OUTPUT_DIR", output_dir)
    monkeypatch.setattr("server.SCRIPTS_DIR", scripts_dir)
    monkeypatch.setattr("server.MAX_PCAP_SIZE", 500 * 1024 * 1024)
    monkeypatch.setattr("server.SUBPROCESS_TIMEOUT", 10)

    return tmp_path


@pytest.fixture()
def mock_run_zeek():
    """Patch _run_zeek to avoid invoking Zeek binary.

    Default return: success with empty output.
    """
    with patch("server._run_zeek", new_callable=AsyncMock) as mock:
        mock.return_value = (0, "", "")
        yield mock
