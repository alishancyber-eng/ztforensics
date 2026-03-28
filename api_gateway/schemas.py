"""
Pydantic schemas for JWT authentication endpoints.
"""
from typing import Optional

from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    """Request body for POST /auth/token."""

    username: str = Field(..., min_length=1, description="Keycloak username")
    password: str = Field(..., min_length=1, description="User password")


class RefreshRequest(BaseModel):
    """Request body for POST /auth/refresh."""

    refresh_token: str = Field(..., min_length=1, description="Refresh token")


class TokenResponse(BaseModel):
    """Token response returned by /auth/token and /auth/refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class VerifyResponse(BaseModel):
    """Response returned by GET /auth/verify."""

    valid: bool
    user_id: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    expires_at: Optional[int] = None


class UserContext(BaseModel):
    """Decoded user context injected into protected routes."""

    user_id: str
    email: Optional[str] = None
    role: Optional[str] = None
    roles: list[str] = []
    exp: Optional[int] = None
    sub: Optional[str] = None
