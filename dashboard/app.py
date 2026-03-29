"""
Flask Dashboard UI for ZTForensics.

Runs on port 5000 and fetches data from the FastAPI Gateway (port 8000).
"""

import os
from typing import Any

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Internal Docker network URL for the FastAPI service
API_BASE = os.environ.get("API_BASE_URL", "http://ztf-api:8000")
# Public URL used in browser-facing links (e.g. download buttons)
API_PUBLIC_URL = os.environ.get("API_PUBLIC_URL", "http://localhost:8000")


def _extract_bearer_token() -> str | None:
    """
    Extract bearer token from:
    1) Authorization header (Bearer ...)
    2) X-Access-Token header
    3) access_token query param
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    x_token = request.headers.get("X-Access-Token", "").strip()
    if x_token:
        return x_token

    q_token = request.args.get("access_token", "").strip()
    if q_token:
        return q_token

    return None


def _api_get(path: str, params: dict | None = None, auth_required: bool = False) -> dict[str, Any]:
    """Safe wrapper around requests.get with timeout and optional auth forwarding."""
    try:
        headers: dict[str, str] = {}
        token = _extract_bearer_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = requests.get(
            f"{API_BASE}{path}",
            params=params,
            headers=headers,
            timeout=8,
        )

        if auth_required and resp.status_code in (401, 403):
            return {
                "ok": False,
                "auth_required": True,
                "status_code": resp.status_code,
                "error": "Authentication required or insufficient role for this endpoint.",
            }

        resp.raise_for_status()
        return resp.json()

    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}


@app.route("/api/stats")
def api_stats():
    """Frontend polling endpoint used by dashboard auto-refresh."""
    data = _api_get("/forensics/summary-public")
    return jsonify(data)


@app.route("/")
@app.route("/dashboard")
def index():
    summary = _api_get("/forensics/summary-public")
    return render_template("index.html", summary=summary)


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
    chain = _api_get("/forensics/verify-chain", auth_required=True)
    return render_template("verify.html", chain=chain, api_public_url=API_PUBLIC_URL)


@app.route("/dashboard/evidence")
def evidence_page():
    summary = _api_get("/forensics/summary-public")
    token = _extract_bearer_token()
    return render_template(
        "evidence.html",
        summary=summary,
        api_public_url=API_PUBLIC_URL,
        access_token=token or "",
    )


@app.route("/admin")
def admin_panel():
    """Admin control panel."""
    token = _extract_bearer_token()
    status = _api_get("/admin/status", auth_required=True)
    return render_template(
        "admin.html",
        api_public_url=API_PUBLIC_URL,
        admin_status=status,
        access_token=token or "",
    )


@app.route("/dashboard/config")
def config_page():
    cfg = _api_get("/config/current", auth_required=True)
    return render_template(
        "config.html",
        config_data=cfg,
        api_public_url=API_PUBLIC_URL,
        access_token=_extract_bearer_token() or "",
    )


@app.route("/demo")
def demo_page():
    return render_template("demo.html")


@app.route("/health")
def health_check():
    return {"status": "ok", "service": "dashboard"}


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)