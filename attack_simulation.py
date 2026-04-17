import time
import requests
import json

# Configuration
BASE_URL = "http://localhost:8000"
AUTH_URL = f"{BASE_URL}/auth/token"
ACCESS_URL = f"{BASE_URL}/access"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Configuration for attack simulation
MALICIOUS_USERS = [
    {"username": "attacker01", "resource": "sensitive-data", "action": "read", "ip_address": "192.168.1.5"},
    {"username": "attacker02", "resource": "user-data", "action": "write", "ip_address": "192.168.1.13"},
    {"username": "attacker03", "resource": "admin-panel", "action": "delete", "ip_address": "192.168.1.21"},
]

def get_access_token():
    """Fetch the auth token for the admin user."""
    try:
        payload = {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        headers = {"Content-Type": "application/json"}
        response = requests.post(AUTH_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching access token: {e}")
        raise

def simulate_attack(access_token):
    """Simulate multiple malicious access requests to identify anomalies."""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    for user in MALICIOUS_USERS:
        request_payload = {
            "user_id": user["username"],
            "resource": user["resource"],
            "action": user["action"],
            "ip_address": user["ip_address"],
            "user_agent": "FakeUserAgent/1.0",
        }
        try:
            print(f"\nSimulating access for user: {user['username']} to {user['resource']}...")
            
            response = requests.post(ACCESS_URL, json=request_payload, headers=headers)
            
            if response.status_code == 200:
                res = response.json()
                print(f"✅ Decision: {res['decision']} | Risk Score: {res['risk_score']} | Reason: {res['reason']}")
            else:
                print(f"❌ Access denied for {user['username']}: HTTP {response.status_code}")
            
            # Simulate delay between requests
            time.sleep(2)
        except Exception as e:
            print(f"Error during attack simulation for {user['username']}: {str(e)}")

if __name__ == "__main__":
    print("\nFetching admin access token...")
    token = get_access_token()
    print("✅ Access token fetched successfully!")
    
    print("\nSimulating attack...")
    simulate_attack(token)
    print("\n✅ Attack simulation completed. Check the dashboard/audit logs for results!")