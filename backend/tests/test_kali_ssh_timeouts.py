"""Tests for KaliSSH per-tool Kali-side timeout enforcement."""
from __future__ import annotations
import pytest
from backend.tools.backends.kali_ssh import KaliConnectionManager, COMMAND_TIMEOUT


class TestKaliSideTimeouts:
    def test_command_timeout_is_at_least_3600(self):
        """Python-side COMMAND_TIMEOUT must be 3600s (last resort only)."""
        assert COMMAND_TIMEOUT >= 3600

    def test_nmap_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("nmap", {"target": "10.0.0.1", "flags": "-sV"})
        assert cmd.startswith("timeout 180"), f"nmap must have 'timeout 180' prefix, got: {cmd}"

    def test_nikto_command_has_maxtime_flag(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("nikto", {"target": "10.0.0.1", "flags": ""})
        assert "-maxtime 90" in cmd, f"nikto must have -maxtime 90 flag, got: {cmd}"

    def test_nuclei_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("nuclei", {"target": "10.0.0.1", "flags": "-t cves/"})
        assert cmd.startswith("timeout 60"), f"nuclei must have 'timeout 60' prefix, got: {cmd}"

    def test_masscan_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("masscan", {"target": "10.0.0.1", "flags": "-p1-65535 --rate=1000"})
        assert cmd.startswith("timeout 120"), f"masscan must have 'timeout 120' prefix, got: {cmd}"

    def test_sqlmap_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("sqlmap", {"target": "http://10.0.0.1", "flags": "--batch"})
        assert cmd.startswith("timeout 180"), f"sqlmap must have 'timeout 180' prefix, got: {cmd}"

    def test_dalfox_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("dalfox", {"target": "http://10.0.0.1", "flags": ""})
        assert cmd.startswith("timeout 60"), f"dalfox must have 'timeout 60' prefix, got: {cmd}"

    def test_ffuf_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("ffuf", {"target": "http://10.0.0.1/FUZZ", "flags": "-w /wordlist"})
        assert cmd.startswith("timeout 90"), f"ffuf must have 'timeout 90' prefix, got: {cmd}"

    def test_whatweb_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("whatweb", {"target": "10.0.0.1", "flags": ""})
        assert cmd.startswith("timeout 30"), f"whatweb must have 'timeout 30' prefix, got: {cmd}"

    def test_whois_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("whois", {"target": "example.com"})
        assert "timeout 15" in cmd, f"whois must have timeout 15, got: {cmd}"

    def test_crt_sh_curl_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("crt_sh", {"target": "example.com"})
        assert "timeout 15" in cmd, f"crt_sh curl must have timeout 15, got: {cmd}"

    def test_wpscan_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("wpscan", {"target": "http://10.0.0.1", "flags": ""})
        assert cmd.startswith("timeout 90"), f"wpscan must have 'timeout 90' prefix, got: {cmd}"
