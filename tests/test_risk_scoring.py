"""
Risk factor tests for ZTForensics – 18 tests.
Covers IP reputation, user agent analysis, time-of-day, geolocation,
action severity, resource sensitivity, brute-force detection, and more.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from unittest.mock import patch
from datetime import datetime, timezone


class TestIPReputation:
    def test_suspicious_ip_high_score(self):
        from risk_scoring import RiskScorer, _SUSPICIOUS_IPS
        rs = RiskScorer()
        ip = next(iter(_SUSPICIOUS_IPS))
        score = rs.calculate_risk({"ip_address": ip, "user_agent": "Mozilla",
                                   "resource": "docs", "action": "READ", "user_id": "u"})
        assert score >= 0.3

    def test_loopback_ip_low_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.calculate_risk({"ip_address": "127.0.0.1", "user_agent": "Mozilla",
                                   "resource": "docs", "action": "READ", "user_id": "u"})
        # loopback returns 0.0 for IP factor — score should be minimal
        assert score < 0.3

    def test_ipv6_loopback_low_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.calculate_risk({"ip_address": "::1", "user_agent": "Mozilla",
                                   "resource": "docs", "action": "READ", "user_id": "u"})
        assert score < 0.3

    def test_generic_public_ip_modest_score(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs._ip_reputation("203.0.113.5")
        assert score == 0.05


class TestUserAgentAnalysis:
    def test_python_requests_agent(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.calculate_risk({"ip_address": "8.8.8.8", "user_agent": "python-requests/2.28",
                                   "resource": "docs", "action": "READ", "user_id": "u"})
        assert score >= 0.2

    def test_wget_agent_suspicious(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score_wget   = rs.calculate_risk({"ip_address": "8.8.8.8", "user_agent": "Wget/1.21",
                                          "resource": "docs", "action": "READ", "user_id": "u"})
        score_normal = rs.calculate_risk({"ip_address": "8.8.8.8", "user_agent": "Mozilla/5.0",
                                          "resource": "docs", "action": "READ", "user_id": "u2"})
        assert score_wget > score_normal

    def test_libwww_agent_suspicious(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        factor = rs._user_agent_risk("libwww-perl/6.0")
        assert factor == 0.2

    def test_normal_browser_zero_factor(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        factor = rs._user_agent_risk("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        assert factor == 0.0


class TestTimeOfDayRisk:
    def test_early_morning_high_risk(self):
        """Hours 0-5 UTC should return 0.2 risk factor."""
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        mock_time = datetime(2026, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
        with patch("risk_scoring.datetime") as mock_dt:
            mock_dt.now.return_value = mock_time
            factor = rs._time_of_day_risk()
        assert factor == 0.2

    def test_working_hours_zero_risk(self):
        """Hours 6-23 UTC should return 0.0 risk factor."""
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        mock_time = datetime(2026, 1, 1, 14, 0, 0, tzinfo=timezone.utc)
        with patch("risk_scoring.datetime") as mock_dt:
            mock_dt.now.return_value = mock_time
            factor = rs._time_of_day_risk()
        assert factor == 0.0


class TestGeolocationDeviation:
    def test_high_risk_country_cn(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._geolocation_risk("CN") == 0.3

    def test_high_risk_country_ru(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._geolocation_risk("RU") == 0.3

    def test_high_risk_country_kp(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._geolocation_risk("KP") == 0.3

    def test_high_risk_country_ir(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._geolocation_risk("IR") == 0.3

    def test_safe_country_zero_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._geolocation_risk("DE") == 0.0

    def test_empty_country_zero_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._geolocation_risk("") == 0.0


class TestActionAndResourceSeverity:
    def test_admin_action_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._action_type_risk("ADMIN") == 0.15

    def test_update_action_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._action_type_risk("UPDATE") == 0.15

    def test_write_action_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._action_type_risk("WRITE") == 0.15

    def test_read_action_no_extra_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._action_type_risk("READ") == 0.0

    def test_secret_resource_high_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._resource_sensitivity("secret_key_store") == 0.2

    def test_config_resource_high_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._resource_sensitivity("config/db") == 0.2

    def test_public_resource_zero_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs._resource_sensitivity("public/docs") == 0.0


class TestBruteForceDetection:
    def test_single_failure_moderate_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        uid = "_brute_1_unique"
        rs.record_failure(uid)
        factor = rs._repeated_failures(uid)
        assert factor == 0.1

    def test_three_failures_high_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        uid = "_brute_3_unique"
        for _ in range(3):
            rs.record_failure(uid)
        factor = rs._repeated_failures(uid)
        assert factor == 0.3

    def test_no_failure_zero_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        factor = rs._repeated_failures("brand_new_user_xyz")
        assert factor == 0.0
