"""
Flask Dashboard UI for ZTForensics.

Runs on port 5000 and fetches data from the FastAPI Gateway (port 8000).
"""

import os

import requests
from flask import Flask, render_template

app = Flask(__name__)

# Internal Docker network URL for the FastAPI service
API_BASE = os.environ.get("API_BASE_URL", "http://api-gateway:8000")
# Public URL used in browser-facing links (e.g. download buttons)
API_PUBLIC_URL = os.environ.get("API_PUBLIC_URL", "http://localhost:8000")


def _api_get(path: str, params: dict = None) -> dict:
    """Safe wrapper around requests.get with a timeout and error handling."""
    try:
        resp = requests.get(f"{API_BASE}{path}", params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}


@app.route("/")
@app.route("/dashboard")
def index():
    summary = _api_get("/forensics/summary-public")  
    chain = _api_get("/forensics/verify-chain")
    timeline = _api_get("/forensics/timeline", params={"interval": "hour"})
    return render_template(
        "index.html",
        summary=summary,
        chain=chain,
        timeline=timeline.get("timeline", []),
    )


@app.route("/dashboard/timeline")
def timeline_page():
    hour_data = _api_get("/forensics/timeline", params={"interval": "hour"})
    day_data = _api_get("/forensics/timeline", params={"interval": "day"})
    return render_template(
        "timeline.html",
        hour_timeline=hour_data.get("timeline", []),
        day_timeline=day_data.get("timeline", []),
    )


@app.route("/dashboard/anomalies")
def anomalies_page():
    data = _api_get("/forensics/anomalies")
    return render_template(
        "anomalies.html",
        anomalies=data.get("anomalies", []),
        total=data.get("total", 0),
    )


@app.route("/dashboard/verify")
def verify_page():
    chain = _api_get("/forensics/verify-chain")
    return render_template("verify.html", chain=chain)


@app.route("/dashboard/evidence")
def evidence_page():
    summary = _api_get("/forensics/summary-public")  # ← CHANGED from /forensics/summary
    return render_template("evidence.html", summary=summary, api_public_url=API_PUBLIC_URL)


@app.route("/admin")
def admin_panel():
    """Admin control panel for managing users, policies, locations, devices"""
    return render_template("admin.html")


@app.route("/demo")
def demo_page():
    """Live demo showing access control scenarios"""
    return render_template("demo.html")


@app.route("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "ok", "service": "dashboard"}


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)