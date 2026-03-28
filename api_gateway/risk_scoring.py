"""
Risk scoring module for ZTForensics API Gateway.
Evaluates the risk level of an access request based on multiple factors.
"""
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# IPs with a known-bad reputation
_SUSPICIOUS_IPS: set[str] = {
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
}

# High-risk country codes
_HIGH_RISK_COUNTRIES: set[str] = {"CN", "RU", "KP", "IR"}

# Suspicious user-agent substrings (lower-cased)
_SUSPICIOUS_AGENTS: tuple[str, ...] = ("curl", "python-requests", "wget", "libwww")

# Resources that warrant extra scrutiny
_SENSITIVE_RESOURCES: tuple[str, ...] = ("admin", "root", "sensitive", "secret", "config")

# Actions considered high-risk
_HIGH_RISK_ACTIONS: set[str] = {"DELETE", "WRITE", "ADMIN", "UPDATE"}

# In-memory counter for repeated failures per user
_failure_counts: dict[str, int] = {}


class RiskScorer:
    """Calculates a normalised risk score (0.0 – 1.0) for an access request."""

    def calculate_risk(self, request_data: dict[str, Any]) -> float:
        """Compute a risk score for the provided request.

        Args:
            request_data: Dict that may contain keys:
                ``ip_address``, ``user_agent``, ``resource``, ``action``,
                ``user_id``, ``country``, ``decision`` (previous outcome).

        Returns:
            Float in [0.0, 1.0] where higher means riskier.
        """
        score = 0.0

        score += self._ip_reputation(request_data.get("ip_address", ""))
        score += self._user_agent_risk(request_data.get("user_agent", ""))
        score += self._time_of_day_risk()
        score += self._resource_sensitivity(request_data.get("resource", ""))
        score += self._action_type_risk(request_data.get("action", ""))
        score += self._repeated_failures(request_data.get("user_id", ""))
        score += self._geolocation_risk(request_data.get("country", ""))

        normalised = min(max(round(score, 2), 0.0), 1.0)
        logger.debug("Calculated risk score: %.2f for user=%s", normalised, request_data.get("user_id"))
        return normalised

    # ------------------------------------------------------------------
    # Individual factor methods
    # ------------------------------------------------------------------

    def _ip_reputation(self, ip: str) -> float:
        if ip in _SUSPICIOUS_IPS:
            return 0.3
        # Loopback / link-local addresses are low risk
        if ip.startswith("127.") or ip == "::1":
            return 0.0
        return 0.05

    def _user_agent_risk(self, ua: str) -> float:
        ua_lower = ua.lower()
        if any(s in ua_lower for s in _SUSPICIOUS_AGENTS):
            return 0.2
        return 0.0

    def _time_of_day_risk(self) -> float:
        hour = datetime.utcnow().hour
        if 0 <= hour < 6:
            return 0.2
        return 0.0

    def _resource_sensitivity(self, resource: str) -> float:
        resource_lower = resource.lower()
        if any(s in resource_lower for s in _SENSITIVE_RESOURCES):
            return 0.2
        return 0.0

    def _action_type_risk(self, action: str) -> float:
        if action.upper() in _HIGH_RISK_ACTIONS:
            return 0.15
        return 0.0

    def _repeated_failures(self, user_id: str) -> float:
        count = _failure_counts.get(user_id, 0)
        if count >= 3:
            return 0.3
        if count >= 1:
            return 0.1
        return 0.0

    def _geolocation_risk(self, country: str) -> float:
        if country.upper() in _HIGH_RISK_COUNTRIES:
            return 0.3
        return 0.0

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def record_failure(self, user_id: str) -> None:
        """Increment the failure counter for *user_id*."""
        _failure_counts[user_id] = _failure_counts.get(user_id, 0) + 1

    @staticmethod
    def get_risk_label(score: float) -> str:
        """Map a numeric risk score to a human-readable label.

        Args:
            score: Value in [0.0, 1.0].

        Returns:
            One of "LOW", "MEDIUM", "HIGH", "CRITICAL".
        """
        if score < 0.25:
            return "LOW"
        if score < 0.50:
            return "MEDIUM"
        if score < 0.75:
            return "HIGH"
        return "CRITICAL"
