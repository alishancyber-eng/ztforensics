#!/usr/bin/env python3
"""
validate_env.py – Validate ZTForensics environment configuration.

Usage:
    python scripts/validate_env.py [--env-file <path>]

Checks:
  - All required environment variables are set
  - URL formats are valid
  - Port availability (local machine)
  - Database connectivity
  - Service accessibility (Keycloak, OPA, MinIO, API Gateway)
  - Warns about non-production settings
  - Suggests fixes for common issues
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import urllib.parse
from pathlib import Path


# ----------------------------------------------------------------
# Load .env file if requested / available
# ----------------------------------------------------------------
def load_env_file(path: str) -> None:
    """Load key=value pairs from *path* into os.environ."""
    p = Path(path)
    if not p.is_file():
        return
    with p.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            # Strip inline comments
            val = val.split(" #")[0].strip().strip('"').strip("'")
            os.environ.setdefault(key.strip(), val)


# ----------------------------------------------------------------
# Validation helpers
# ----------------------------------------------------------------
PASS_LABEL = "\033[32m[PASS]\033[0m"
FAIL_LABEL = "\033[31m[FAIL]\033[0m"
WARN_LABEL = "\033[33m[WARN]\033[0m"
INFO_LABEL = "\033[36m[INFO]\033[0m"


class ValidationReport:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.infos: list[str] = []

    def ok(self, msg: str) -> None:
        print(f"  {PASS_LABEL} {msg}")

    def fail(self, msg: str, suggestion: str = "") -> None:
        print(f"  {FAIL_LABEL} {msg}")
        if suggestion:
            print(f"         → {suggestion}")
        self.errors.append(msg)

    def warn(self, msg: str, suggestion: str = "") -> None:
        print(f"  {WARN_LABEL} {msg}")
        if suggestion:
            print(f"         → {suggestion}")
        self.warnings.append(msg)

    def info(self, msg: str) -> None:
        print(f"  {INFO_LABEL} {msg}")
        self.infos.append(msg)


report = ValidationReport()


# ----------------------------------------------------------------
# Required variable definitions
# ----------------------------------------------------------------
REQUIRED_VARS: list[tuple[str, str]] = [
    ("KEYCLOAK_SERVER_URL",    "Keycloak server URL"),
    ("KEYCLOAK_REALM",         "Keycloak realm name"),
    ("KEYCLOAK_CLIENT_ID",     "Keycloak client ID"),
    ("KEYCLOAK_CLIENT_SECRET", "Keycloak client secret"),
    ("DATABASE_URL",           "PostgreSQL connection string"),
    ("MINIO_ENDPOINT",         "MinIO endpoint (host:port)"),
    ("MINIO_ACCESS_KEY",       "MinIO access key"),
    ("MINIO_SECRET_KEY",       "MinIO secret key"),
    ("OPA_URL",                "Open Policy Agent URL"),
    ("SECRET_KEY",             "Application secret key"),
]

URL_VARS: list[str] = [
    "KEYCLOAK_SERVER_URL",
    "OPA_URL",
    "API_GATEWAY_URL",
]

SENSITIVE_DEFAULTS: dict[str, str] = {
    "SECRET_KEY":             "your-secret-key-change-in-production",
    "KEYCLOAK_CLIENT_SECRET": "3spkr3Fjhf9HcXivHWMRFqKdLehSoKLC",
    "KEYCLOAK_ADMIN_PASSWORD": "admin123",
    "MINIO_SECRET_KEY":       "minioadmin123",
}


# ----------------------------------------------------------------
# Checks
# ----------------------------------------------------------------
def check_required_vars() -> None:
    print("\n▶  Required environment variables")
    for var, description in REQUIRED_VARS:
        val = os.environ.get(var)
        if not val:
            report.fail(
                f"{var} is not set ({description})",
                f"Add {var}=<value> to your .env file.",
            )
        else:
            report.ok(f"{var} is set")


def check_url_formats() -> None:
    print("\n▶  URL format validation")
    for var in URL_VARS:
        val = os.environ.get(var)
        if not val:
            continue
        parsed = urllib.parse.urlparse(val)
        if parsed.scheme not in ("http", "https"):
            report.fail(
                f"{var}='{val}' has invalid scheme '{parsed.scheme}'",
                "Use http:// or https://",
            )
        elif not parsed.netloc:
            report.fail(
                f"{var}='{val}' is missing a host",
                "Example: http://localhost:8080",
            )
        else:
            report.ok(f"{var} URL format is valid")


def check_port_availability() -> None:
    print("\n▶  Port availability (local machine)")
    ports_to_check = [
        (int(os.environ.get("API_GATEWAY_PORT", "8000")), "API Gateway"),
        (int(os.environ.get("DASHBOARD_PORT",    "5000")), "Dashboard"),
        (8080, "Keycloak"),
        (8181, "OPA"),
        (5432, "PostgreSQL"),
        (9000, "MinIO"),
    ]
    for port, name in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        if result == 0:
            report.ok(f"Port {port} ({name}) is open")
        else:
            report.warn(
                f"Port {port} ({name}) is not reachable",
                f"Start the {name} service or check if it is running on a different port.",
            )


def check_database_connectivity() -> None:
    print("\n▶  Database connectivity")
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        report.warn("DATABASE_URL not set – skipping database check.")
        return
    if db_url.startswith("sqlite"):
        report.info("SQLite URL detected – skipping live connectivity check.")
        return
    try:
        import sqlalchemy  # type: ignore[import-untyped]

        engine = sqlalchemy.create_engine(
            db_url,
            connect_args={"connect_timeout": 5},
            pool_pre_ping=True,
        )
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
        report.ok("Database connection successful")
    except ImportError:
        report.warn("sqlalchemy not installed – skipping database connectivity check.")
    except Exception as exc:  # noqa: BLE001
        report.fail(
            f"Database connection failed: {exc}",
            "Verify DATABASE_URL and that the PostgreSQL container is running.",
        )


def check_service_accessibility() -> None:
    print("\n▶  Service accessibility (HTTP)")
    try:
        import urllib.request

        services = [
            (os.environ.get("KEYCLOAK_SERVER_URL", "http://localhost:8080") + "/health/ready",
             "Keycloak /health/ready"),
            (os.environ.get("OPA_URL", "http://localhost:8181") + "/health",
             "OPA /health"),
            (os.environ.get("API_GATEWAY_URL", "http://localhost:8000") + "/health",
             "API Gateway /health"),
        ]
        for url, name in services:
            try:
                req = urllib.request.urlopen(url, timeout=5)  # noqa: S310
                status = req.status
                if status < 400:
                    report.ok(f"{name} → HTTP {status}")
                else:
                    report.warn(f"{name} → HTTP {status}")
            except Exception as exc:  # noqa: BLE001
                report.warn(
                    f"{name} not reachable: {exc}",
                    f"Start the corresponding Docker service.",
                )
    except Exception as exc:  # noqa: BLE001
        report.warn(f"Service accessibility check failed: {exc}")


def check_production_warnings() -> None:
    print("\n▶  Security / production warnings")
    debug = os.environ.get("DEBUG", "False")
    if debug.lower() in ("true", "1", "yes"):
        report.warn(
            "DEBUG=True – not safe for production",
            "Set DEBUG=False in your production .env file.",
        )
    else:
        report.ok("DEBUG is disabled")

    cors = os.environ.get("CORS_ORIGINS", "")
    if cors.strip() == "*":
        report.warn(
            "CORS_ORIGINS=* allows all origins – not safe for production",
            "Set CORS_ORIGINS to specific origins, e.g. https://app.example.com",
        )
    else:
        report.ok("CORS_ORIGINS is restricted")

    for var, default_val in SENSITIVE_DEFAULTS.items():
        current = os.environ.get(var, "")
        if current == default_val:
            report.warn(
                f"{var} is still set to the default example value",
                f"Change {var} to a unique, strong value before production deployment.",
            )
        elif current:
            report.ok(f"{var} has been customised")


# ----------------------------------------------------------------
# Main
# ----------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ZTForensics environment configuration")
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to the .env file to load (default: .env)",
    )
    args = parser.parse_args()

    # Change to repo root so relative .env paths work
    repo_root = Path(__file__).resolve().parent.parent
    os.chdir(repo_root)

    env_file = Path(args.env_file)
    if env_file.is_file():
        load_env_file(str(env_file))
        print(f"\n{INFO_LABEL} Loaded environment from {env_file}")
    else:
        print(f"\n{WARN_LABEL} .env file not found at '{env_file}' – using current environment")

    print("\n" + "=" * 60)
    print(" ZTForensics Environment Validation")
    print("=" * 60)

    check_required_vars()
    check_url_formats()
    check_port_availability()
    check_database_connectivity()
    check_service_accessibility()
    check_production_warnings()

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f" Summary: {len(report.errors)} error(s), {len(report.warnings)} warning(s)")
    print("=" * 60)

    if report.errors:
        print(f"\n{FAIL_LABEL} Validation FAILED – fix the errors above before deploying.")
        sys.exit(1)
    elif report.warnings:
        print(f"\n{WARN_LABEL} Validation passed with warnings.")
    else:
        print(f"\n{PASS_LABEL} All checks passed!")


if __name__ == "__main__":
    main()
