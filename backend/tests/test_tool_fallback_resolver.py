"""Tests for ToolFallbackResolver — 6-step resolution chain."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, patch
from backend.core.tool_fallback import FallbackResolution, ToolFallbackResolver


@pytest.fixture
def resolver():
    return ToolFallbackResolver()


class TestAlternativeTable:
    @pytest.mark.asyncio
    async def test_sublist3r_falls_back_to_amass(self, resolver):
        res = await resolver.resolve("sublist3r", {"target": "example.com"}, "not found")
        assert res.alternative_tool == "amass"
        assert res.alternative_input == {"target": "example.com"}

    @pytest.mark.asyncio
    async def test_dalfox_falls_back_to_nuclei(self, resolver):
        res = await resolver.resolve("dalfox", {"target": "http://example.com"}, "not found")
        assert res.alternative_tool == "nuclei"

    @pytest.mark.asyncio
    async def test_masscan_falls_back_to_nmap(self, resolver):
        res = await resolver.resolve("masscan", {"target": "10.0.0.1"}, "not found")
        assert res.alternative_tool == "nmap"

    @pytest.mark.asyncio
    async def test_already_tried_alternative_is_skipped(self, resolver):
        """If amass was already tried, skip it and try next alternative."""
        res = await resolver.resolve(
            "sublist3r", {"target": "example.com"}, "not found",
            tried_tools={"amass"},
        )
        # amass tried, should fall back to dnsrecon
        assert res.alternative_tool == "dnsrecon"

    @pytest.mark.asyncio
    async def test_tool_with_no_alternative_returns_skip(self, resolver):
        """Tool with no alternative and no kali_mgr for install → skip."""
        res = await resolver.resolve("crt_sh", {"target": "example.com"}, "not found")
        assert res.alternative_tool is None
        assert res.skip is True


class TestPatternFixes:
    @pytest.mark.asyncio
    async def test_masscan_missing_rate_gets_fixed(self, resolver):
        """masscan command without --rate should get --rate=500 appended."""
        res = await resolver.resolve(
            "masscan", {"target": "10.0.0.1", "flags": "-p1-65535"}, "failed",
            error_type="command_error",
        )
        assert res.alternative_tool == "nmap" or (
            res.corrected_flags is not None and "--rate" in res.corrected_flags
        )

    @pytest.mark.asyncio
    async def test_nuclei_missing_template_gets_fixed(self, resolver):
        """nuclei without -t flag should get -t cves/ added."""
        res = await resolver.resolve(
            "nuclei", {"target": "10.0.0.1", "flags": ""}, "no templates",
            error_type="command_error",
        )
        assert res.corrected_flags is not None and "cves/" in res.corrected_flags


class TestAutoInstall:
    @pytest.mark.asyncio
    async def test_auto_install_attempted_when_no_alternative(self):
        """When no alternative exists, auto-install is attempted via kali_mgr."""
        mock_kali = AsyncMock()
        mock_kali.execute = AsyncMock(return_value={
            "status": "success", "stdout": "Setting up tool...", "exit_code": 0,
        })
        resolver = ToolFallbackResolver(kali_mgr=mock_kali)
        res = await resolver.resolve("crt_sh", {"target": "example.com"}, "not found")
        # crt_sh has no alternatives — should attempt install
        mock_kali.execute.assert_called_once()
        call_args = mock_kali.execute.call_args
        assert call_args[1].get("tool_name") == "_install" or "apt" in str(call_args)

    @pytest.mark.asyncio
    async def test_install_failure_returns_skip(self):
        """Failed auto-install returns skip=True."""
        mock_kali = AsyncMock()
        mock_kali.execute = AsyncMock(return_value={
            "status": "error", "stdout": "", "exit_code": 1,
        })
        resolver = ToolFallbackResolver(kali_mgr=mock_kali)
        res = await resolver.resolve("crt_sh", {"target": "example.com"}, "not found")
        assert res.skip is True


class TestFallbackResolution:
    def test_resolution_dataclass_defaults(self):
        res = FallbackResolution()
        assert res.alternative_tool is None
        assert res.install_succeeded is False
        assert res.skip is False
        assert res.corrected_flags is None
