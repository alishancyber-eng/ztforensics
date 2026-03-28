"""
JWT authentication middleware, dependency helpers, and RBAC decorators.

Validates Keycloak-issued JWT tokens and provides:
- ``get_current_user`` – FastAPI dependency returning a :class:`UserContext`.
- ``@require_auth`` – decorator that enforces a valid JWT.
- ``@require_role(*roles)`` – decorator that enforces role membership.
- ``@require_scope(*scopes)`` – decorator that enforces scope membership.

Custom exceptions
-----------------
- :exc:`InvalidTokenError` – token missing, malformed, or expired.
- :exc:`InvalidClaimError` – required claim absent or wrong value.
- :exc:`InsufficientPermissions` – user lacks the required role/scope.
"""

import functools
import logging
from typing import Any, Callable, Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from keycloak_config import fetch_jwks, get_client_id, get_issuer
from schemas import UserContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class InvalidTokenError(Exception):
    """Raised when the JWT is missing, malformed, or expired."""


class InvalidClaimError(Exception):
    """Raised when a required JWT claim is absent or has an unexpected value."""


class InsufficientPermissions(Exception):
    """Raised when the authenticated user lacks the required role or scope."""


# ---------------------------------------------------------------------------
# Bearer scheme (auto-extracts the Authorization header)
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Core validation helper
# ---------------------------------------------------------------------------


async def _decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a Keycloak JWT.

    Steps:
    1. Fetch JWKS from Keycloak (cached).
    2. Decode and verify the token signature.
    3. Validate ``iss``, ``aud`` (optional), and ``exp`` claims.

    Raises :exc:`InvalidTokenError` on any failure.
    """
    try:
        jwks_data = await fetch_jwks()
    except Exception as exc:
        raise InvalidTokenError(f"Unable to fetch JWKS: {exc}") from exc

    try:
        jwks_set = jwt.PyJWKSet.from_dict(jwks_data)
        if not jwks_set.keys:
            raise InvalidTokenError("JWKS contains no signing keys.")
        signing_key = jwks_set.keys[0]
    except InvalidTokenError:
        raise
    except Exception as exc:
        raise InvalidTokenError(f"Invalid JWKS data: {exc}") from exc

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=get_issuer(),
            options={
                "verify_aud": False,   # Keycloak tokens may set aud=account
                "verify_exp": True,
            },
        )
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise InvalidTokenError("Token has expired.") from exc
    except jwt.InvalidIssuerError as exc:
        raise InvalidTokenError("Token issuer is invalid.") from exc
    except jwt.DecodeError as exc:
        raise InvalidTokenError(f"Token decode error: {exc}") from exc
    except Exception as exc:
        raise InvalidTokenError(f"Token validation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Claim extraction helper
# ---------------------------------------------------------------------------


def _extract_user_context(payload: dict[str, Any]) -> UserContext:
    """Build a :class:`UserContext` from a decoded JWT payload.

    Raises :exc:`InvalidClaimError` when the ``sub`` claim is absent.
    """
    sub: Optional[str] = payload.get("sub")
    if not sub:
        raise InvalidClaimError("JWT missing required 'sub' claim.")

    preferred_username: str = payload.get("preferred_username") or sub
    email: Optional[str] = payload.get("email")
    exp: Optional[int] = payload.get("exp")

    # Roles are nested under realm_access.roles in Keycloak tokens
    realm_access: dict = payload.get("realm_access", {})
    roles: list[str] = realm_access.get("roles", [])
    # Pick the first non-default role as the primary role, fallback to the
    # first role available, or None.
    _default_roles = {"default-roles-forensics", "offline_access", "uma_authorization"}
    custom_roles = [r for r in roles if r not in _default_roles]
    role: Optional[str] = custom_roles[0] if custom_roles else None

    return UserContext(
        user_id=preferred_username,
        sub=sub,
        email=email,
        role=role,
        roles=roles,
        exp=exp,
    )


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> UserContext:
    """FastAPI dependency that validates the JWT and returns user context.

    Raises HTTP 401 when the token is missing or invalid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = await _decode_token(credentials.credentials)
        return _extract_user_context(payload)
    except (InvalidTokenError, InvalidClaimError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------


def require_auth(func: Callable) -> Callable:
    """Endpoint decorator: requires a valid JWT token.

    The decorated endpoint *must* accept ``user: UserContext = Depends(get_current_user)``.
    This decorator is provided for explicit self-documentation; in practice, adding
    ``Depends(get_current_user)`` to the signature is equivalent.
    """
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        return await func(*args, **kwargs)

    # Ensure FastAPI picks up the dependency by injecting it into the signature
    # when the caller hasn't explicitly listed it.
    import inspect
    sig = inspect.signature(func)
    if "user" not in sig.parameters:
        # Append a 'user' parameter with the Depends default
        new_params = list(sig.parameters.values()) + [
            inspect.Parameter(
                "user",
                kind=inspect.Parameter.KEYWORD_ONLY,
                default=Depends(get_current_user),
                annotation=UserContext,
            )
        ]
        wrapper.__signature__ = sig.replace(parameters=new_params)  # type: ignore[attr-defined]

    return wrapper


def require_role(*roles: str) -> Callable:
    """Endpoint decorator factory: requires one of the given roles.

    Usage::

        @app.get("/admin")
        @require_role("admin", "superuser")
        async def admin_endpoint(user: UserContext = Depends(get_current_user)):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            user: Optional[UserContext] = kwargs.get("user")
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authorization header missing.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if not set(roles).intersection(set(user.roles)):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role not authorized. Required one of: {list(roles)}.",
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_scope(*scopes: str) -> Callable:
    """Endpoint decorator factory: requires one of the given scopes.

    Scopes are read from the ``scope`` claim (space-separated string) in the JWT.

    Usage::

        @app.get("/read")
        @require_scope("profile", "email")
        async def read_endpoint(user: UserContext = Depends(get_current_user)):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # The raw payload is not stored on UserContext, so scopes must be
            # checked by the caller.  This decorator is a best-effort guard that
            # verifies the 'scope' kwarg when supplied by a custom dependency.
            request: Optional[Request] = kwargs.get("request")
            scope_claim: str = ""
            if request is not None:
                scope_claim = getattr(request.state, "token_scope", "")

            token_scopes = set(scope_claim.split()) if scope_claim else set()
            required = set(scopes)
            if not required.intersection(token_scopes) and required:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required scope(s) {list(required)} not present in token.",
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
