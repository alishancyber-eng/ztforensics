import time
import requests
import json

# Configuration
BASE_URL = "http://localhost:8000"
AUTH_URL = f"{BASE_URL}/auth/token"
ACCESS_URL = f"{BASE_URL}/access"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# List of suspicious activity to simulate
MALICIOUS_USERS = [
    {"username": "attacker01", "resource": "sensitive-data", "action": "read", "ip_address": "192.168.1.4"},
    {"username": "attacker02", "resource": "confidential-report", "action": "write", "ip_address": "192.168.1.10"},
    {"username": "attacker03", "resource": "admin-console", "action": "delete", "ip_address": "192.168.1.20"},
]

def get_access_token() -> str:
    """
    Retrieve the access token from the authentication endpoint.
    Returns:
        str: The access token if successful, None otherwise.
    """
    payload = {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(AUTH_URL, json=payload)
        response.raise_for_status()
        token = response.json().get("access_token")
        print(f"✅ Access token fetched successfully: [TOKEN HIDDEN]")
        return token

    except Exception as e:
        print(f"❌ Failed to get access token: {e}")
        return None


def simulate_suspicious_requests(access_token: str):
    """
    Simulate suspicious activity by sending fake high-risk access requests,
    which could later appear as anomalies in the audit logs.
    Args:
        access_token (str): The JWT access token for authorization.
    """
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    for user in MALICIOUS_USERS:
        # Include the high-risk score to force a "Deny" decision
        request_payload = {
            "user_id": user["username"],
            "resource": user["resource"],
            "action": user["action"],
            "ip_address": user["ip_address"],
            "user_agent": "SuspiciousUserAgent/1.0",
            "metadata": {
                "risk_score": 0.9  # High risk, which violates the policy threshold
            },
        }

        print(f"Simulating attack: User [{user['username']}], Resource: [{user['resource']}] using IP [{user['ip_address']}]...")
        
        try:
            response = requests.post(ACCESS_URL, json=request_payload, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if result["decision"] == "deny":
                    print(f"🚫 Denied: Decision = {result['decision']}, Risk Score = {result['risk_score']}, Reason = {result['reason']}")
                else:
                    print(f"✅ Allowed: Decision = {result['decision']}, Risk Score = {result['risk_score']}, Reason = {result['reason']}")
            else:
                print(f"❌ Request failed with status code: {response.status_code}.")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Adding a delay to avoid spamming the server
        time.sleep(2)


def main():
    print("\nFetching admin access token...")
    token = get_access_token()
    
    if token:
        print("\nSimulating suspicious activity...")
        simulate_suspicious_requests(token)
        print("\n✅ Suspicious activity simulation complete! Check the dashboard for logs.")
    else:
        print("\n❌ Simulation could not run as token was not retrieved.")


if __name__ == "__main__":
    main()