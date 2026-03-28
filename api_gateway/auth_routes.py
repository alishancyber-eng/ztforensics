"""
Authentication routes: token issuance, refresh, and verification.

Endpoints:
- ``POST /auth/token``   – Exchange username/password for JWT tokens.
- ``POST /auth/refresh`` – Exchange a refresh token for new tokens.
- ``GET  /auth/verify``  – Verify whether the caller's JWT is still valid.
"""

import logging
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from auth_middleware import InvalidClaimError, InvalidTokenError, _decode_token, _extract_user_context, get_current_user
from keycloak_config import get_client_id, get_client_secret, get_token_url
from schemas import RefreshRequest, TokenRequest, TokenResponse, UserContext, VerifyResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# POST /auth/token
# ---------------------------------------------------------------------------


@router.post("/token", response_model=TokenResponse, summary="Get JWT token")
async def get_token(body: TokenRequest) -> TokenResponse:
    """Exchange a Keycloak username and password for access/refresh tokens.

    Returns HTTP 401 when credentials are invalid.
    """
    payload: dict[str, str] = {
        "client_id": get_client_id(),
        "client_secret": get_client_secret(),
        "username": body.username,
        "password": body.password,
        "grant_type": "password",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                get_token_url(),
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.RequestError as exc:
        logger.error("Keycloak unreachable: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from exc

    if resp.status_code == 401:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not resp.is_success:
        logger.error("Keycloak token error %s: %s", resp.status_code, resp.text)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to obtain token from authentication service.",
        )

    data: dict[str, Any] = resp.json()
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data["refresh_token"],
        token_type=data.get("token_type", "Bearer"),
        expires_in=int(data.get("expires_in", 300)),
    )


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------


@router.post("/refresh", response_model=TokenResponse, summary="Refresh JWT token")
async def refresh_token(body: RefreshRequest) -> TokenResponse:
    """Exchange a refresh token for a new access/refresh token pair.

    Returns HTTP 401 when the refresh token is expired or invalid.
    """
    payload: dict[str, str] = {
        "client_id": get_client_id(),
        "client_secret": get_client_secret(),
        "refresh_token": body.refresh_token,
        "grant_type": "refresh_token",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                get_token_url(),
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.RequestError as exc:
        logger.error("Keycloak unreachable: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from exc

    if resp.status_code == 400:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid or has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not resp.is_success:
        logger.error("Keycloak refresh error %s: %s", resp.status_code, resp.text)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to refresh token from authentication service.",
        )

    data: dict[str, Any] = resp.json()
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data["refresh_token"],
        token_type=data.get("token_type", "Bearer"),
        expires_in=int(data.get("expires_in", 300)),
    )


# ---------------------------------------------------------------------------
# GET /auth/verify
# ---------------------------------------------------------------------------


@router.get("/verify", response_model=VerifyResponse, summary="Verify JWT token")
async def verify_token(user: Optional[UserContext] = Depends(get_current_user)) -> VerifyResponse:
    """Verify whether the caller's JWT token is valid.

    Returns ``{"valid": true, ...}`` with user claims on success, or raises
    HTTP 401 (handled by the ``get_current_user`` dependency) on failure.
    """
    return VerifyResponse(
        valid=True,
        user_id=user.user_id if user else None,
        email=user.email if user else None,
        role=user.role if user else None,
        expires_at=user.exp if user else None,
    )
