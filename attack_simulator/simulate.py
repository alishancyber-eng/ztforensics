#!/usr/bin/env python3
"""
ZTForensics Attack Simulator
============================
Generates realistic attack scenarios by sending HTTP requests to the
ZTForensics API Gateway to populate the evidence store with demo data.

Usage:
    python attack_simulator/simulate.py [--api-url URL]

Scenarios:
    1. Brute Force       — 10 failed login attempts from the same IP
    2. Privilege Escalation — employee accessing admin resources
    3. Off-Hours Access  — access at 3 AM from a foreign IP
    4. Resource Hopping  — rapid access to many different sensitive resources
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("ERROR: 'requests' library is required. Install with: pip install requests")

DEFAULT_API_URL = "http://localhost:8000"

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"


def _post_access(api_url: str, user: str, role: str, resource: str,
                 action: str, ip: str, ua: str) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer user:{user};role:{role}",
    }
    body = {"resource": resource, "action": action,
            "ip_address": ip, "user_agent": ua}
    resp = requests.post(f"{api_url}/access", headers=headers,
                         json=body, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _print_result(result: dict):
    decision = result.get("decision", "?")
    risk = result.get("risk_score", 0)
    color = GREEN if decision == "ALLOW" else RED
    print(
        f"  {color}[{decision}]{RESET} "
        f"risk={risk:3d}  "
        f"user={result.get('user', '?'):<12} "
        f"resource={result.get('resource', '?'):<28} "
        f"reason={result.get('reason', '?')}"
    )


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scenario_brute_force(api_url: str):
    """10 rapid deny attempts from same attacker IP."""
    print(f"\n{BOLD}{YELLOW}=== Scenario 1: Brute Force (10 attempts) ==={RESET}")
    attacker_ip = "196.10.20.30"
    for i in range(10):
        result = _post_access(
            api_url,
            user=f"unknown_user_{i}",
            role="employee",
            resource="/api/admin/login",
            action="write",
            ip=attacker_ip,
            ua="python-requests/2.31",
        )
        _print_result(result)
        time.sleep(0.1)
    print(f"  {CYAN}→ Created 10 evidence records from brute-force attack IP {attacker_ip}{RESET}")


def scenario_privilege_escalation(api_url: str):
    """Employee trying to access admin-only resources."""
    print(f"\n{BOLD}{YELLOW}=== Scenario 2: Privilege Escalation ==={RESET}")
    targets = [
        ("/api/admin/users",   "read"),
        ("/api/admin/secrets", "read"),
        ("/api/admin/config",  "write"),
        ("/api/admin/audit",   "delete"),
        ("/api/admin/tokens",  "write"),
    ]
    for resource, action in targets:
        result = _post_access(
            api_url,
            user="ali",
            role="employee",
            resource=resource,
            action=action,
            ip="10.0.1.55",
            ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        )
        _print_result(result)
        time.sleep(0.1)
    print(f"  {CYAN}→ Employee 'ali' attempted to access 5 admin resources — all denied{RESET}")


def scenario_off_hours_access(api_url: str):
    """Legitimate-looking user accessing from foreign IP at night."""
    print(f"\n{BOLD}{YELLOW}=== Scenario 3: Off-Hours Access (foreign IP) ==={RESET}")
    records = [
        ("ali",     "employee", "/api/documents",     "read",   "203.0.113.99"),
        ("ali",     "employee", "/api/payroll",        "read",   "203.0.113.99"),
        ("ali",     "employee", "/api/hr/records",     "read",   "203.0.113.99"),
        ("charlie", "employee", "/api/finance/export", "read",   "196.44.55.66"),
        ("charlie", "employee", "/api/finance/export", "delete", "196.44.55.66"),
    ]
    for user, role, resource, action, ip in records:
        result = _post_access(
            api_url,
            user=user,
            role=role,
            resource=resource,
            action=action,
            ip=ip,
            ua="curl/8.1.0",
        )
        _print_result(result)
        time.sleep(0.1)
    print(f"  {CYAN}→ Suspicious night-time access from foreign IPs recorded{RESET}")


def scenario_resource_hopping(api_url: str):
    """Single user rapidly accessing many different sensitive resources."""
    print(f"\n{BOLD}{YELLOW}=== Scenario 4: Resource Hopping ==={RESET}")
    resources = [
        ("/api/users/list",      "read"),
        ("/api/payroll/reports", "read"),
        ("/api/hr/employees",    "read"),
        ("/api/legal/contracts", "read"),
        ("/api/finance/budget",  "read"),
        ("/api/secrets/keys",    "read"),
        ("/api/logs/access",     "read"),
    ]
    for resource, action in resources:
        result = _post_access(
            api_url,
            user="mallory",
            role="employee",
            resource=resource,
            action=action,
            ip="10.0.0.88",
            ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        )
        _print_result(result)
        time.sleep(0.1)
    print(f"  {CYAN}→ User 'mallory' hopped through {len(resources)} resources in rapid succession{RESET}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def check_health(api_url: str) -> bool:
    try:
        resp = requests.get(f"{api_url}/health", timeout=5)
        data = resp.json()
        return data.get("status") == "ok" and data.get("db_ready", False)
    except Exception:
        return False


def print_summary(api_url: str):
    try:
        resp = requests.get(f"{api_url}/forensics/summary", timeout=5)
        summary = resp.json()
        print(f"\n{BOLD}{CYAN}=== Evidence Summary After Attack Simulation ==={RESET}")
        print(f"  Total records  : {summary.get('total_requests', '?')}")
        print(f"  Allowed        : {summary.get('allowed', '?')}")
        print(f"  Denied         : {summary.get('denied', '?')}")
        print(f"  High-risk      : {summary.get('high_risk_count', '?')}")
        print(f"  Allow rate     : {summary.get('allow_percentage', '?')}%")
    except Exception as e:
        print(f"  {RED}Could not fetch summary: {e}{RESET}")


def print_anomalies(api_url: str):
    try:
        resp = requests.get(f"{api_url}/forensics/anomalies", timeout=5)
        data = resp.json()
        anomalies = data.get("anomalies", [])
        print(f"\n{BOLD}{YELLOW}=== Detected Anomalies ==={RESET}")
        if anomalies:
            for a in anomalies:
                sev_color = RED if a["severity"] == "HIGH" else YELLOW
                subject = a.get("user") or a.get("ip_address", "?")
                print(
                    f"  {sev_color}[{a['severity']}]{RESET} "
                    f"type={a['type']:<35} "
                    f"subject={subject:<15} "
                    f"count={a['count']}  "
                    f"confidence={a['confidence']:.0%}"
                )
        else:
            print(f"  {GREEN}No anomalies detected.{RESET}")
    except Exception as e:
        print(f"  {RED}Could not fetch anomalies: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="ZTForensics Attack Simulator — generate forensic demo data"
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"Base URL of the ZTForensics API Gateway (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--scenario",
        choices=["all", "brute-force", "privilege", "off-hours", "hopping"],
        default="all",
        help="Which scenario to run (default: all)",
    )
    args = parser.parse_args()
    api_url = args.api_url.rstrip("/")

    print(f"{BOLD}ZTForensics Attack Simulator{RESET}")
    print(f"Target API: {api_url}")
    print(f"Started:    {datetime.now(timezone.utc).isoformat()}")

    # Health check
    if not check_health(api_url):
        print(f"{RED}ERROR: API gateway is not healthy at {api_url}{RESET}")
        print("Make sure the stack is running: docker compose up -d")
        sys.exit(1)
    print(f"{GREEN}✓ API gateway is healthy{RESET}")

    scenarios = {
        "brute-force": scenario_brute_force,
        "privilege":   scenario_privilege_escalation,
        "off-hours":   scenario_off_hours_access,
        "hopping":     scenario_resource_hopping,
    }

    if args.scenario == "all":
        for fn in scenarios.values():
            fn(api_url)
    else:
        scenarios[args.scenario](api_url)

    print_summary(api_url)
    print_anomalies(api_url)
    print(f"\n{BOLD}{GREEN}✓ Attack simulation complete!{RESET}")
    print(f"  View dashboard:        http://localhost:5000")
    print(f"  Download evidence ZIP: http://localhost:8000/forensics/export")
    print(f"  Download PDF report:   http://localhost:8000/forensics/export-pdf\n")


if __name__ == "__main__":
    main()
