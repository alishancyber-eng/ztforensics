"""
ZTForensics Dashboard – Flask web application.
"""
import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_GATEWAY_URL: str = os.getenv("API_GATEWAY_URL", "http://localhost:8000")

app = Flask(__name__)


def _get(path: str, fallback: Any = None) -> Any:
    """Make a GET request to the API gateway.

    Args:
        path: URL path (e.g. ``/health``).
        fallback: Value to return when the gateway is unreachable.

    Returns:
        Parsed JSON response or *fallback*.
    """
    try:
        resp = requests.get(f"{API_GATEWAY_URL}{path}", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("API gateway unavailable for %s: %s", path, exc)
        return fallback


@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    """Proxy the forensic summary from the API gateway."""
    data = _get(
        "/forensics/summary",
        fallback={
            "total_requests": 0,
            "allowed": 0,
            "denied": 0,
            "high_risk_events": 0,
            "recent_logs": [],
            "error": "API gateway unavailable",
        },
    )
    return jsonify(data)


@app.route("/api/health")
def api_health():
    """Proxy the health check from the API gateway."""
    data = _get(
        "/health",
        fallback={
            "status": "unavailable",
            "services": {"database": "down", "blockchain": "down", "storage": "down"},
            "error": "API gateway unavailable",
        },
    )
    return jsonify(data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
