"""
JWT authentication middleware, dependency helpers, and RBAC decorators.
"""

import functools
import inspect
import logging
import os
from typing import Any, Callable, Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from keycloak_config import fetch_jwks, get_client_id, get_issuer
from schemas import UserContext

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)

VERIFY_AUDIENCE = os.environ.get("KEYCLOAK_VERIFY_AUD", "false").lower() == "true"
VERIFY_ISSUER = os.environ.get("KEYCLOAK_VERIFY_ISS", "true").lower() == "true"
EXPECTED_AUDIENCE = os.environ.get("KEYCLOAK_AUDIENCE", get_client_id())


class InvalidTokenError(Exception):
    pass


class InvalidClaimError(Exception):
    pass


async def _decode_token(token: str) -> dict[str, Any]:
    try:
        jwks_data = await fetch_jwks()
        unverified_header = jwt.get_unverified_header(token)
        token_kid = unverified_header.get("kid")
        if not token_kid:
            raise InvalidTokenError("Token missing 'kid' header.")
    except Exception as exc:
        raise InvalidTokenError(f"Token/JWKS pre-validation failed: {exc}") from exc

    try:
        jwks_set = jwt.PyJWKSet.from_dict(jwks_data)
        signing_key_obj = None
        for k in jwks_set.keys:
            kid = getattr(k, "key_id", None)
            if kid is None and hasattr(k, "_jwk_data"):
                kid = k._jwk_data.get("kid")
            if kid == token_kid:
                signing_key_obj = k
                break
        if signing_key_obj is None:
            raise InvalidTokenError(f"No matching JWK found for kid '{token_kid}'.")
    except Exception as exc:
        raise InvalidTokenError(f"Invalid JWKS data: {exc}") from exc

    options = {
        "verify_aud": VERIFY_AUDIENCE,
        "verify_exp": True,
        "verify_iss": VERIFY_ISSUER,
    }

    decode_kwargs: dict[str, Any] = {
        "algorithms": ["RS256"],
        "options": options,
    }

    if VERIFY_ISSUER:
        decode_kwargs["issuer"] = get_issuer()
    if VERIFY_AUDIENCE:
        decode_kwargs["audience"] = EXPECTED_AUDIENCE

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            signing_key_obj.key,
            **decode_kwargs,
        )
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise InvalidTokenError("Token has expired.") from exc
    except jwt.InvalidIssuerError as exc:
        raise InvalidTokenError("Token issuer is invalid.") from exc
    except jwt.InvalidAudienceError as exc:
        raise InvalidTokenError("Token audience is invalid.") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(f"Token validation failed: {exc}") from exc
    except Exception as exc:
        raise InvalidTokenError(f"Token decode failed: {exc}") from exc


def _extract_roles(payload: dict[str, Any]) -> list[str]:
    roles: list[str] = []

    realm_roles = ((payload.get("realm_access") or {}).get("roles") or [])
    if isinstance(realm_roles, list):
        roles.extend([str(r) for r in realm_roles])

    resource_access = payload.get("resource_access") or {}
    if isinstance(resource_access, dict):
        for _, block in resource_access.items():
            client_roles = (block or {}).get("roles") or []
            if isinstance(client_roles, list):
                roles.extend([str(r) for r in client_roles])

    seen = set()
    deduped = []
    for r in roles:
        if r not in seen:
            seen.add(r)
            deduped.append(r)
    return deduped


def _extract_user_context(payload: dict[str, Any]) -> UserContext:
    sub: Optional[str] = payload.get("sub")
    if not sub:
        raise InvalidClaimError("JWT missing required 'sub' claim.")

    preferred_username: str = payload.get("preferred_username") or sub
    email: Optional[str] = payload.get("email")
    exp: Optional[int] = payload.get("exp")
    roles = _extract_roles(payload)

    role = None
    for r in roles:
        if r.lower() not in {"default-roles-forensics", "offline_access", "uma_authorization"}:
            role = r
            break

    return UserContext(
        user_id=preferred_username,
        sub=sub,
        email=email,
        role=role,
        roles=roles,
        exp=exp,
    )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> UserContext:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = await _decode_token(credentials.credentials)
        request.state.token_scope = payload.get("scope", "") or ""
        return _extract_user_context(payload)
    except (InvalidTokenError, InvalidClaimError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_auth(func: Callable) -> Callable:
    is_async = inspect.iscoroutinefunction(func)

    @functools.wraps(func)
    async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
        return await func(*args, **kwargs)

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    wrapper: Callable = async_wrapper if is_async else sync_wrapper

    sig = inspect.signature(func)
    if "user" not in sig.parameters:
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