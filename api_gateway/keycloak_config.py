"""
Keycloak configuration and JWKS public-key caching for JWT validation.
"""
import logging
import os
import time
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

KEYCLOAK_SERVER_URL: str = os.getenv("KEYCLOAK_SERVER_URL", "http://localhost:8080")
KEYCLOAK_REALM: str = os.getenv("KEYCLOAK_REALM", "forensics")
KEYCLOAK_CLIENT_ID: str = os.getenv("KEYCLOAK_CLIENT_ID", "api-gateway")
KEYCLOAK_CLIENT_SECRET: str = os.getenv("KEYCLOAK_CLIENT_SECRET", "")

# Derived URLs
REALM_URL: str = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}"
JWKS_URL: str = f"{REALM_URL}/protocol/openid-connect/certs"
TOKEN_URL: str = f"{REALM_URL}/protocol/openid-connect/token"
ISSUER: str = REALM_URL

# Cache TTL in seconds (10 minutes)
_JWKS_CACHE_TTL: int = 600
_jwks_cache: Optional[dict] = None
_jwks_cache_ts: float = 0.0


def get_jwks_uri() -> str:
    """Return the JWKS endpoint URL."""
    return JWKS_URL


def get_token_url() -> str:
    """Return the token endpoint URL."""
    return TOKEN_URL


def get_issuer() -> str:
    """Return the expected token issuer."""
    return ISSUER


def get_client_id() -> str:
    """Return the configured client ID."""
    return KEYCLOAK_CLIENT_ID


def get_client_secret() -> str:
    """Return the configured client secret."""
    return KEYCLOAK_CLIENT_SECRET


async def fetch_jwks() -> dict:
    """Fetch JWKS from Keycloak, using an in-process cache.

    The cache is refreshed after ``_JWKS_CACHE_TTL`` seconds.
    """
    global _jwks_cache, _jwks_cache_ts

    now = time.monotonic()
    if _jwks_cache is not None and (now - _jwks_cache_ts) < _JWKS_CACHE_TTL:
        return _jwks_cache

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(JWKS_URL)
            resp.raise_for_status()
            _jwks_cache = resp.json()
            _jwks_cache_ts = now
            logger.debug("JWKS refreshed from %s", JWKS_URL)
            return _jwks_cache
    except Exception as exc:
        logger.error("Failed to fetch JWKS from %s: %s", JWKS_URL, exc)
        if _jwks_cache is not None:
            logger.warning("Using stale JWKS cache due to fetch failure.")
            return _jwks_cache
        raise


def invalidate_jwks_cache() -> None:
    """Invalidate the JWKS cache (useful for testing)."""
    global _jwks_cache, _jwks_cache_ts
    _jwks_cache = None
    _jwks_cache_ts = 0.0
