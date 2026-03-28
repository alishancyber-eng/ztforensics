"""
prestart_checks.py – Pre-flight checks run before application startup.

Verifies that all dependent services are accessible, checks minimum
resource requirements, and generates a startup report.

Usage:
    python prestart_checks.py

Exit codes:
    0 – all checks passed (or only warnings)
    1 – one or more checks failed
"""
from __future__ import annotations

import os
import socket
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ----------------------------------------------------------------
# Load .env if available
# ----------------------------------------------------------------
_env_file = Path(__file__).resolve().parent / ".env"
if _env_file.is_file():
    with _env_file.open() as _fh:
        for _line in _fh:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line:
                continue
            _k, _, _v = _line.partition("=")
            _v = _v.split(" #")[0].strip().strip('"').strip("'")
            os.environ.setdefault(_k.strip(), _v)

# ----------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------
KEYCLOAK_URL    = os.environ.get("KEYCLOAK_SERVER_URL", "http://localhost:8080")
DATABASE_URL    = os.environ.get("DATABASE_URL", "")
OPA_URL         = os.environ.get("OPA_URL", "http://localhost:8181")
MINIO_ENDPOINT  = os.environ.get("MINIO_ENDPOINT", "localhost:9000")

# How many seconds to wait when testing connectivity
TIMEOUT_SECS = 5

# ----------------------------------------------------------------
# Report accumulator
# ----------------------------------------------------------------
_results: list[dict] = []


def _record(name: str, status: str, detail: str = "") -> None:
    _results.append({"check": name, "status": status, "detail": detail})
    icon = {"PASS": "✓", "FAIL": "✗", "WARN": "!"}.get(status, "?")
    line = f"  [{icon}] {name}"
    if detail:
        line += f" – {detail}"
    print(line)


# ----------------------------------------------------------------
# Individual checks
# ----------------------------------------------------------------
def _http_get(url: str, timeout: int = TIMEOUT_SECS) -> tuple[bool, str]:
    try:
        resp = urllib.request.urlopen(url, timeout=timeout)  # noqa: S310
        return True, f"HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _tcp_connect(host: str, port: int, timeout: int = TIMEOUT_SECS) -> tuple[bool, str]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True, f"{host}:{port} open"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def check_keycloak() -> None:
    ok, detail = _http_get(f"{KEYCLOAK_URL}/health/ready")
    if ok:
        _record("Keycloak", "PASS", detail)
    else:
        _record("Keycloak", "FAIL", f"{KEYCLOAK_URL}/health/ready – {detail}")


def check_database() -> None:
    if not DATABASE_URL:
        _record("Database", "WARN", "DATABASE_URL not set")
        return
    if DATABASE_URL.startswith("sqlite"):
        _record("Database", "PASS", "SQLite (no connectivity check needed)")
        return
    try:
        import sqlalchemy  # type: ignore[import-untyped]

        engine = sqlalchemy.create_engine(
            DATABASE_URL,
            connect_args={"connect_timeout": TIMEOUT_SECS},
            pool_pre_ping=True,
        )
        start = time.monotonic()
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
        elapsed = int((time.monotonic() - start) * 1000)
        _record("Database", "PASS", f"Connected in {elapsed} ms")
    except ImportError:
        _record("Database", "WARN", "sqlalchemy not installed")
    except Exception as exc:  # noqa: BLE001
        _record("Database", "FAIL", str(exc))


def check_opa() -> None:
    ok, detail = _http_get(f"{OPA_URL}/health")
    if ok:
        _record("OPA", "PASS", detail)
    else:
        _record("OPA", "FAIL", f"{OPA_URL}/health – {detail}")


def check_minio() -> None:
    host = MINIO_ENDPOINT.rsplit(":", 1)[0]
    port_str = MINIO_ENDPOINT.rsplit(":", 1)[-1] if ":" in MINIO_ENDPOINT else "9000"
    try:
        port = int(port_str)
    except ValueError:
        _record("MinIO", "WARN", f"Cannot parse port from MINIO_ENDPOINT={MINIO_ENDPOINT}")
        return

    ok, detail = _tcp_connect(host, port)
    if ok:
        # Also verify HTTP health
        ok2, d2 = _http_get(f"http://{MINIO_ENDPOINT}/minio/health/live")
        if ok2:
            _record("MinIO", "PASS", d2)
        else:
            _record("MinIO", "WARN", f"Port open but health endpoint returned: {d2}")
    else:
        _record("MinIO", "FAIL", detail)


def check_env_vars() -> None:
    required = [
        "KEYCLOAK_SERVER_URL",
        "KEYCLOAK_REALM",
        "KEYCLOAK_CLIENT_ID",
        "KEYCLOAK_CLIENT_SECRET",
        "DATABASE_URL",
        "MINIO_ENDPOINT",
        "OPA_URL",
        "SECRET_KEY",
    ]
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        _record("Environment variables", "FAIL", f"Missing: {', '.join(missing)}")
    else:
        _record("Environment variables", "PASS", "All required variables set")


def check_version_compat() -> None:
    version = sys.version_info
    if version >= (3, 10):
        _record("Python version", "PASS", f"{version.major}.{version.minor}.{version.micro}")
    else:
        _record("Python version", "FAIL",
                f"{version.major}.{version.minor} – Python 3.10+ is required")


def check_resources() -> None:
    try:
        import shutil

        total, _used, free = shutil.disk_usage("/")
        free_gb = free / (1024 ** 3)
        if free_gb >= 1.0:
            _record("Disk space", "PASS", f"{free_gb:.1f} GB free")
        else:
            _record("Disk space", "WARN", f"Only {free_gb:.2f} GB free – consider freeing space")
    except Exception:  # noqa: BLE001
        _record("Disk space", "WARN", "Could not check disk space")


# ----------------------------------------------------------------
# Main
# ----------------------------------------------------------------
def main() -> int:
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print()
    print("=" * 60)
    print(f" ZTForensics Pre-Start Checks  ({started_at})")
    print("=" * 60)

    check_version_compat()
    check_env_vars()
    check_keycloak()
    check_database()
    check_opa()
    check_minio()
    check_resources()

    # Summary
    fails  = [r for r in _results if r["status"] == "FAIL"]
    warns  = [r for r in _results if r["status"] == "WARN"]
    passed = [r for r in _results if r["status"] == "PASS"]

    print()
    print("=" * 60)
    print(f" Results: {len(passed)} passed, {len(warns)} warning(s), {len(fails)} failed")
    print("=" * 60)

    if fails:
        print("\n✗ Pre-start checks FAILED. Fix the above errors before starting.")
        for f in fails:
            print(f"  – {f['check']}: {f['detail']}")
        return 1

    if warns:
        print("\n! Pre-start checks passed with warnings.")
    else:
        print("\n✓ All pre-start checks passed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
