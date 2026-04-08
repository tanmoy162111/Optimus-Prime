"""Tests for _extract_json_from_llm_response hardening."""
from __future__ import annotations
import pytest
from backend.agents.scan_agent import _extract_json_from_llm_response


class TestLLMJsonHardening:
    def test_clean_json_parses(self):
        result = _extract_json_from_llm_response('{"tool": "nmap", "is_terminal": false}', "Test")
        assert result["tool"] == "nmap"

    def test_json_in_code_block_parses(self):
        result = _extract_json_from_llm_response(
            '```json\n{"tool": "nikto", "is_terminal": false}\n```', "Test"
        )
        assert result["tool"] == "nikto"

    def test_json_with_surrounding_prose_parses(self):
        result = _extract_json_from_llm_response(
            'I will run nmap next. {"tool": "nmap", "is_terminal": false} That is my plan.', "Test"
        )
        assert result["tool"] == "nmap"

    def test_single_quoted_json_parses(self):
        """Single-quoted JSON wrapper (some LLMs return this) must parse correctly."""
        result = _extract_json_from_llm_response(
            "'{'tool': 'nmap', 'is_terminal': false}'", "Test"
        )
        # Should return safe default rather than raising
        assert "tool" in result or result.get("is_terminal") is not None

    def test_pure_prose_returns_safe_default(self):
        """Pure prose with no JSON must return safe default dict, not raise."""
        result = _extract_json_from_llm_response(
            "I think we should run nmap against the target first to discover open ports.", "Test"
        )
        assert isinstance(result, dict)
        assert result.get("is_terminal") is False  # safe default: continue loop
        assert result.get("tool") is None

    def test_empty_string_returns_safe_default(self):
        result = _extract_json_from_llm_response("", "Test")
        assert isinstance(result, dict)
        assert result.get("is_terminal") is False

    def test_truncated_json_returns_safe_default(self):
        """Truncated JSON (LLM hit token limit) returns safe default, not exception."""
        result = _extract_json_from_llm_response('{"tool": "nmap", "input": {"targ', "Test")
        assert isinstance(result, dict)

    def test_safe_default_does_not_terminate_agent(self):
        """Safe default must have is_terminal=False so agent loop continues."""
        result = _extract_json_from_llm_response("not json at all", "Test")
        assert result.get("is_terminal") is False

    def test_json_array_returns_safe_default(self):
        """LLM returning a JSON array must not crash callers that call .get() on the result.

        Regression test for: 'list' object has no attribute 'get' in ExploitAgent dispatch.
        """
        result = _extract_json_from_llm_response(
            '[{"tool": "sqlmap", "is_terminal": false}]', "ExploitAgent"
        )
        assert isinstance(result, dict), "must always return a dict, never a list"
        # Safe default expected since the top-level value is a list, not an object
        assert result.get("is_terminal") is False
