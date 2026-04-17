"""
Flask Dashboard UI for ZTForensics.

Runs on port 5000 and fetches data from the FastAPI Gateway (port 8000).
OIDC login integrated with Keycloak (Authorization Code Flow).
"""

import base64
import json
import os
import secrets
import urllib.parse
from datetime import timedelta
from typing import Any, Optional

import requests
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # True in HTTPS production
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)

app.secret_key = os.environ.get("DASHBOARD_SECRET_KEY", "change-this-in-production")

API_BASE = os.environ.get("API_BASE_URL", "http://ztf-api:8000")
API_PUBLIC_URL = os.environ.get("API_PUBLIC_URL", "http://localhost:8000")

KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", "http://localhost:8080")  # browser-facing
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://ztf-keycloak:8080")  # container-facing
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "forensics")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_DASHBOARD_CLIENT_ID", "ztf-dashboard")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_DASHBOARD_CLIENT_SECRET", "")
DASHBOARD_BASE_URL = os.environ.get("DASHBOARD_BASE_URL", "http://localhost:5000")

OIDC_AUTH_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
OIDC_LOGOUT_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"

OIDC_TOKEN_URL = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
OIDC_USERINFO_URL = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"


def _extract_bearer_token_from_request() -> Optional[str]:
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


def _get_effective_token() -> Optional[str]:
    req_token = _extract_bearer_token_from_request()
    if req_token:
        return req_token
    return session.get("access_token")


def _is_authenticated() -> bool:
    return bool(session.get("access_token"))


def _is_admin() -> bool:
    roles = session.get("roles", []) or []
    return "admin" in roles


def _require_login():
    if not _is_authenticated():
        return redirect(url_for("auth_login"))
    return None


def _refresh_access_token_if_needed() -> bool:
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        return False
    try:
        payload = {
            "grant_type": "refresh_token",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "refresh_token": refresh_token,
        }
        resp = requests.post(OIDC_TOKEN_URL, data=payload, timeout=10)
        if resp.status_code != 200:
            return False

        token_data = resp.json()
        new_access = token_data.get("access_token")
        if not new_access:
            return False

        session["access_token"] = new_access
        if token_data.get("refresh_token"):
            session["refresh_token"] = token_data["refresh_token"]
        return True
    except requests.RequestException:
        return False


def _auth_fail_response(resp: requests.Response) -> tuple[dict[str, Any], int]:
    try_data = resp.json() if resp.content else {}
    detail_text = str(try_data.get("detail", "")).lower()

    if resp.status_code == 401 and "expired" in detail_text:
        session.pop("access_token", None)
        session.pop("refresh_token", None)
        return {
            "ok": False,
            "auth_required": True,
            "reauth": True,
            "status_code": 401,
            "error": "Session expired. Please login again.",
            "detail": try_data.get("detail", "Token expired"),
        }, 401

    return {
        "ok": False,
        "auth_required": True,
        "status_code": resp.status_code,
        "error": "Authentication required or insufficient role for this endpoint.",
        "detail": try_data.get("detail", resp.text[:300] if resp.text else ""),
    }, resp.status_code


def _api_get(path: str, params: dict | None = None, auth_required: bool = False) -> tuple[dict[str, Any], int]:
    try:
        token = _get_effective_token()
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = requests.get(f"{API_BASE}{path}", params=params, headers=headers, timeout=15)

        if auth_required and resp.status_code in (401, 403):
            # retry once only when expired + refresh succeeds
            if resp.status_code == 401:
                try_data = resp.json() if resp.content else {}
                detail = str(try_data.get("detail", "")).lower()
                if "expired" in detail and _refresh_access_token_if_needed():
                    token2 = session.get("access_token")
                    headers2 = {"Authorization": f"Bearer {token2}"} if token2 else {}
                    resp = requests.get(f"{API_BASE}{path}", params=params, headers=headers2, timeout=15)

            if resp.status_code in (401, 403):
                return _auth_fail_response(resp)

        if resp.status_code >= 400:
            return {
                "ok": False,
                "status_code": resp.status_code,
                "error": resp.text[:500] if resp.text else "Upstream error",
            }, resp.status_code

        return resp.json(), resp.status_code

    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}, 500


def _api_post(path: str, payload: dict[str, Any], auth_required: bool = True) -> tuple[dict[str, Any], int]:
    try:
        token = _get_effective_token()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = requests.post(f"{API_BASE}{path}", json=payload, headers=headers, timeout=15)

        if auth_required and resp.status_code in (401, 403):
            if resp.status_code == 401:
                try_data = resp.json() if resp.content else {}
                detail = str(try_data.get("detail", "")).lower()
                if "expired" in detail and _refresh_access_token_if_needed():
                    token2 = session.get("access_token")
                    headers2 = {"Content-Type": "application/json"}
                    if token2:
                        headers2["Authorization"] = f"Bearer {token2}"
                    resp = requests.post(f"{API_BASE}{path}", json=payload, headers=headers2, timeout=15)

            if resp.status_code in (401, 403):
                return _auth_fail_response(resp)

        data = resp.json() if resp.content else {}
        return data, resp.status_code

    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}, 500


@app.context_processor
def inject_auth_state():
    roles = session.get("roles", []) or []
    return {
        "session_authenticated": _is_authenticated(),
        "session_username": session.get("preferred_username"),
        "session_roles": roles,
        "session_is_admin": ("admin" in roles),
    }


@app.route("/auth/login")
def auth_login():
    state = secrets.token_urlsafe(24)
    session["oidc_state"] = state

    redirect_uri = f"{DASHBOARD_BASE_URL}/auth/callback"
    params = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
    }
    url = f"{OIDC_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return redirect(url)


@app.route("/auth/callback")
def auth_callback():
    try:
        code = request.args.get("code")
        state = request.args.get("state")

        expected_state = session.get("oidc_state")
        if not code or not state or state != expected_state:
            return "Invalid OIDC callback state.", 400

        session.pop("oidc_state", None)

        redirect_uri = f"{DASHBOARD_BASE_URL}/auth/callback"
        token_payload = {
            "grant_type": "authorization_code",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        token_resp = requests.post(OIDC_TOKEN_URL, data=token_payload, timeout=10)
        if token_resp.status_code != 200:
            return f"Token exchange failed: {token_resp.text}", 401

        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        if not access_token:
            return "Missing access token in OIDC response.", 401

        preferred_username = ""
        email = ""
        roles: list[str] = []

        ui_resp = requests.get(
            OIDC_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if ui_resp.status_code == 200:
            userinfo = ui_resp.json()
            preferred_username = userinfo.get("preferred_username", "")
            email = userinfo.get("email", "")
            roles = userinfo.get("realm_access", {}).get("roles", []) or []

        if not roles or not preferred_username:
            parts = access_token.split(".")
            if len(parts) >= 2:
                try:
                    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode())
                    roles = roles or (payload.get("realm_access", {}).get("roles", []) or [])
                    if not preferred_username:
                        preferred_username = payload.get("preferred_username", "")
                    if not email:
                        email = payload.get("email", "")
                except Exception:
                    pass

        session.permanent = True
        session["access_token"] = access_token
        session["refresh_token"] = refresh_token
        session["preferred_username"] = preferred_username
        session["email"] = email
        session["roles"] = roles

        return redirect(url_for("index"))

    except Exception as exc:
        return f"OIDC callback error: {str(exc)}", 500


@app.route("/auth/logout")
def auth_logout():
    session.clear()
    post_logout_redirect_uri = f"{DASHBOARD_BASE_URL}/"
    params = {
        "post_logout_redirect_uri": post_logout_redirect_uri,
        "client_id": KEYCLOAK_CLIENT_ID,
    }
    logout_url = f"{OIDC_LOGOUT_URL}?{urllib.parse.urlencode(params)}"
    return redirect(logout_url)


@app.post("/session/token")
def save_session_token():
    body = request.get_json(silent=True) or {}
    token = (body.get("access_token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "access_token is required"}), 400
    session["access_token"] = token
    return jsonify({"ok": True})


@app.post("/session/token/clear")
def clear_session_token():
    session.pop("access_token", None)
    session.pop("refresh_token", None)
    session.pop("preferred_username", None)
    session.pop("email", None)
    session.pop("roles", None)
    return jsonify({"ok": True})


@app.get("/session/token/status")
def token_status():
    token = session.get("access_token")
    return jsonify(
        {
            "ok": True,
            "has_token": bool(token),
            "username": session.get("preferred_username"),
            "roles": session.get("roles", []),
        }
    )


@app.route("/api/stats")
def api_stats():
    data, code = _api_get("/forensics/summary-public")
    return jsonify(data), code


@app.route("/")
@app.route("/dashboard")
def index():
    summary, _ = _api_get("/forensics/summary-public")
    return render_template("index.html", summary=summary)


@app.route("/dashboard/timeline")
def timeline_page():
    hour_data, _ = _api_get("/forensics/timeline", params={"interval": "hour"})
    day_data, _ = _api_get("/forensics/timeline", params={"interval": "day"})
    return render_template(
        "timeline.html",
        hour_timeline=hour_data.get("timeline", []),
        day_timeline=day_data.get("timeline", []),
    )


@app.route("/dashboard/anomalies")
def anomalies_page():
    data, _ = _api_get("/forensics/anomalies")
    return render_template(
        "anomalies.html",
        anomalies=data.get("anomalies", []),
        total=data.get("total", 0),
    )


@app.route("/dashboard/verify")
def verify_page():
    require = _require_login()
    if require:
        return require
    chain, _ = _api_get("/forensics/verify-chain", auth_required=True)
    return render_template("verify.html", chain=chain, api_public_url=API_PUBLIC_URL)


@app.route("/dashboard/evidence")
def evidence_page():
    require = _require_login()
    if require:
        return require
    summary, _ = _api_get("/forensics/summary-public")
    return render_template("evidence.html", summary=summary, api_public_url=API_PUBLIC_URL)


@app.get("/dashboard/evidence/download")
def evidence_download_proxy():
    token = _get_effective_token()
    if not token:
        return jsonify({"ok": False, "auth_required": True, "error": "Login required"}), 401

    kind = (request.args.get("kind") or "json").lower()
    path = "/forensics/export-pdf" if kind == "pdf" else "/forensics/export"

    headers = {"Authorization": f"Bearer {token}"}
    try:
        upstream = requests.get(f"{API_BASE}{path}", headers=headers, timeout=20)
        if upstream.status_code in (401, 403):
            try_data = upstream.json() if upstream.content else {}
            detail = str(try_data.get("detail", "")).lower()
            if upstream.status_code == 401 and "expired" in detail and _refresh_access_token_if_needed():
                token2 = session.get("access_token")
                upstream = requests.get(
                    f"{API_BASE}{path}",
                    headers={"Authorization": f"Bearer {token2}"},
                    timeout=20,
                )

        if upstream.status_code in (401, 403):
            data, code = _auth_fail_response(upstream)
            return jsonify(data), code

        if upstream.status_code >= 400:
            return (upstream.text, upstream.status_code, {"Content-Type": "text/plain; charset=utf-8"})

        content_type = upstream.headers.get("Content-Type", "application/octet-stream")
        filename = "ztforensics-report.pdf" if kind == "pdf" else "ztforensics-export.json"
        return (
            upstream.content,
            200,
            {
                "Content-Type": content_type,
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# -----------------------------
# Admin proxy endpoints
# -----------------------------

@app.post("/dashboard/admin/users")
def dash_admin_create_user():
    payload = request.get_json(silent=True) or {}
    data, code = _api_post("/admin/users", payload, auth_required=True)
    return jsonify(data), code


@app.get("/dashboard/admin/users")
def dash_admin_list_users():
    data, code = _api_get("/admin/users", auth_required=True)
    return jsonify(data), code


@app.post("/dashboard/admin/policies")
def dash_admin_create_policy():
    payload = request.get_json(silent=True) or {}
    data, code = _api_post("/admin/policies", payload, auth_required=True)
    return jsonify(data), code


@app.get("/dashboard/admin/policies")
def dash_admin_list_policies():
    data, code = _api_get("/admin/policies", auth_required=True)
    return jsonify(data), code


@app.post("/dashboard/admin/whitelist/location")
def dash_admin_whitelist_location():
    payload = request.get_json(silent=True) or {}
    data, code = _api_post("/admin/whitelist/location", payload, auth_required=True)
    return jsonify(data), code


@app.get("/dashboard/admin/whitelist/locations")
def dash_admin_list_whitelist_locations():
    data, code = _api_get("/admin/whitelist/locations", auth_required=True)
    return jsonify(data), code


@app.post("/dashboard/admin/whitelist/device")
def dash_admin_whitelist_device():
    payload = request.get_json(silent=True) or {}
    data, code = _api_post("/admin/whitelist/device", payload, auth_required=True)
    return jsonify(data), code


@app.get("/dashboard/admin/whitelist/devices")
def dash_admin_list_whitelist_devices():
    data, code = _api_get("/admin/whitelist/devices", auth_required=True)
    return jsonify(data), code


@app.post("/dashboard/admin/whitelist/temporary")
def dash_admin_temp_whitelist():
    payload = request.get_json(silent=True) or {}
    data, code = _api_post("/admin/whitelist/temporary", payload, auth_required=True)
    return jsonify(data), code


@app.get("/dashboard/admin/security/alerts")
def dash_admin_security_alerts():
    limit = request.args.get("limit", "100")
    data, code = _api_get("/security/alerts", params={"limit": limit}, auth_required=True)
    return jsonify(data), code


@app.get("/dashboard/admin/audit")
def dash_admin_audit():
    limit = request.args.get("limit", "100")
    data, code = _api_get("/admin/audit", params={"limit": limit}, auth_required=True)
    return jsonify(data), code


@app.route("/admin")
def admin_panel():
    require = _require_login()
    if require:
        return require
    if not _is_admin():
        return "Forbidden: admin role required", 403

    status, _ = _api_get("/admin/status", auth_required=True)
    return render_template("admin.html", api_public_url=API_PUBLIC_URL, admin_status=status)


@app.route("/dashboard/config")
def config_page():
    require = _require_login()
    if require:
        return require

    cfg, _ = _api_get("/config/current", auth_required=True)
    return render_template("config.html", config_data=cfg, api_public_url=API_PUBLIC_URL)


@app.route("/demo")
def demo_page():
    return render_template("demo.html")


@app.route("/health")
def health_check():
    return {"status": "ok", "service": "dashboard"}


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)