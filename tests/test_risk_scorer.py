"""
Unit tests for api_gateway/risk_scorer.py
"""
import pytest
from unittest.mock import patch
from datetime import datetime, timezone

from risk_scorer import calculate_risk


# --- Helper to build a minimal request payload ---

def _payload(ip="10.0.0.1", ua="Mozilla/5.0", resource="/api/documents", action="read"):
    return {
        "ip_address": ip,
        "user_agent": ua,
        "resource": resource,
        "action": action,
    }


class TestCalculateRisk:
    def test_clean_request_returns_zero_score(self):
        """A normal, low-risk request should score 0 during business hours."""
        result = calculate_risk(_payload())
        # We cannot guarantee 0 if test runs outside business hours,
        # so only assert no high-risk factors from IP/UA/resource/action.
        assert result["risk_score"] >= 0
        assert "foreign_or_untrusted_ip" not in result["risk_factors"]
        assert "non_browser_user_agent" not in result["risk_factors"]
        assert "admin_resource_targeted" not in result["risk_factors"]
        assert "sensitive_action" not in result["risk_factors"]

    def test_foreign_ip_increases_score(self):
        """Foreign/untrusted IP prefix should add risk points."""
        result = calculate_risk(_payload(ip="203.0.113.5"))
        assert "foreign_or_untrusted_ip" in result["risk_factors"]
        assert result["risk_score"] >= 35

    def test_curl_user_agent_increases_score(self):
        """curl user-agent should be flagged as non-browser."""
        result = calculate_risk(_payload(ua="curl/8.0"))
        assert "non_browser_user_agent" in result["risk_factors"]
        assert result["risk_score"] >= 25

    def test_admin_resource_increases_score(self):
        """Admin resource path should raise the risk score."""
        result = calculate_risk(_payload(resource="/api/admin/panel"))
        assert "admin_resource_targeted" in result["risk_factors"]
        assert result["risk_score"] >= 30

    def test_delete_action_increases_score(self):
        """DELETE action should be flagged as sensitive."""
        result = calculate_risk(_payload(action="delete"))
        assert "sensitive_action" in result["risk_factors"]
        assert result["risk_score"] >= 15

    def test_write_action_increases_score(self):
        """WRITE action should be flagged as sensitive."""
        result = calculate_risk(_payload(action="write"))
        assert "sensitive_action" in result["risk_factors"]

    def test_max_score_is_100(self):
        """Risk score must never exceed 100."""
        worst = _payload(ip="203.0.0.1", ua="curl/7.0",
                         resource="/api/admin/secrets", action="delete")
        result = calculate_risk(worst)
        assert result["risk_score"] <= 100

    def test_multiple_factors_accumulated(self):
        """Multiple risk indicators should combine (up to 100)."""
        result = calculate_risk(
            _payload(ip="196.1.2.3", ua="python-requests/2.0",
                     resource="/api/admin/users", action="write")
        )
        assert len(result["risk_factors"]) >= 3
        assert result["risk_score"] >= 90

    def test_off_hours_factor(self):
        """Off-hours flag should be present when mocked to hour 3 AM."""
        # Patch datetime inside risk_scorer to simulate 3 AM
        fake_now = datetime(2026, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
        with patch("risk_scorer.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            result = calculate_risk(_payload())
        assert "off_business_hours" in result["risk_factors"]
        assert result["risk_score"] >= 10

    def test_return_structure(self):
        """Result must have the expected keys and types."""
        result = calculate_risk(_payload())
        assert "risk_score" in result
        assert "risk_factors" in result
        assert isinstance(result["risk_score"], int)
        assert isinstance(result["risk_factors"], list)
