"""Tests for VerificationLoop._classify_result() classification logic."""
from __future__ import annotations
import pytest
from backend.core.models import FindingClassification
from backend.verification.verification_loop import VerificationLoop


@pytest.fixture
def vl():
    return VerificationLoop()


SAMPLE_FINDING = {"finding_id": "f-001", "target": "10.0.0.1", "port": 80, "severity": "medium"}


class TestClassifyResult:
    def test_ssh_connection_error_is_manual_review(self, vl):
        result = {"status": "error", "error": "Connection refused: SSH unreachable", "output": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.MANUAL_REVIEW

    def test_tool_not_found_error_is_manual_review(self, vl):
        result = {"status": "error", "error": "Tool 'nmap_verify' not found on Kali", "output": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.MANUAL_REVIEW

    def test_timeout_error_is_manual_review(self, vl):
        result = {"status": "error", "error": "Command timed out after 60s", "output": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.MANUAL_REVIEW

    def test_tool_ran_no_output_is_false_positive(self, vl):
        result = {"status": "success", "output": "", "error": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.FALSE_POSITIVE

    def test_tool_ran_with_port_open_is_confirmed(self, vl):
        result = {"status": "success", "output": "80/tcp open http", "error": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.CONFIRMED

    def test_tool_ran_with_http_response_is_confirmed(self, vl):
        result = {"status": "success", "output": "HTTP/1.1 200 OK\nServer: Apache", "error": ""}
        cls = vl._classify_result({"target": "10.0.0.1", "tool": "nikto"}, result)
        assert cls == FindingClassification.CONFIRMED

    def test_tool_ran_with_any_output_is_confirmed(self, vl):
        result = {"status": "success", "output": "some output that is longer than 10 characters", "error": ""}
        cls = vl._classify_result({"target": "10.0.0.1"}, result)
        assert cls == FindingClassification.CONFIRMED
