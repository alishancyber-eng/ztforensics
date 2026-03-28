"""
Tests for JWT authentication middleware, decorators, and auth routes.

Covers:
- JWT token decode and claim extraction
- Token expiration handling
- Missing/invalid tokens → 401
- Role-based access control → 403
- Custom exceptions: InvalidTokenError, InvalidClaimError, InsufficientPermissions
- Auth route endpoints (/auth/token, /auth/refresh, /auth/verify)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import importlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers – generate test JWTs with RSA keys
# ---------------------------------------------------------------------------

def _make_rsa_keys():
    """Generate a fresh RSA key pair for test token signing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def _make_token(payload: dict, private_key) -> str:
    """Sign *payload* with *private_key* and return a JWT string."""
    import jwt
    return jwt.encode(payload, private_key, algorithm="RS256")


def _build_jwks(public_key) -> dict:
    """Return a JWKS dict for the given public key."""
    import base64

    pub_numbers = public_key.public_numbers()

    def _int_to_base64url(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        b = n.to_bytes(length, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "test-key-1",
                "n": _int_to_base64url(pub_numbers.n),
                "e": _int_to_base64url(pub_numbers.e),
            }
        ]
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rsa_keys():
    private_key, public_key = _make_rsa_keys()
    return private_key, public_key


@pytest.fixture(scope="module")
def jwks(rsa_keys):
    _, public_key = rsa_keys
    return _build_jwks(public_key)


@pytest.fixture(scope="module")
def valid_payload():
    now = int(time.time())
    return {
        "sub": "e97ec0ef-4e7b-4e7d-ab80-b14b298173c9",
        "preferred_username": "testuser",
        "email": "testuser@example.com",
        "realm_access": {
            "roles": ["default-roles-forensics", "offline_access", "investigator"]
        },
        "scope": "profile email",
        "iat": now,
        "exp": now + 300,
        "iss": "http://localhost:8080/realms/forensics",
    }


@pytest.fixture(scope="module")
def valid_token(rsa_keys, valid_payload):
    private_key, _ = rsa_keys
    return _make_token(valid_payload, private_key)


# ---------------------------------------------------------------------------
# Test: custom exceptions exist and are importable
# ---------------------------------------------------------------------------

class TestCustomExceptions:
    def test_invalid_token_error_importable(self):
        from auth_middleware import InvalidTokenError
        assert issubclass(InvalidTokenError, Exception)

    def test_invalid_claim_error_importable(self):
        from auth_middleware import InvalidClaimError
        assert issubclass(InvalidClaimError, Exception)

    def test_insufficient_permissions_importable(self):
        from auth_middleware import InsufficientPermissions
        assert issubclass(InsufficientPermissions, Exception)

    def test_invalid_token_error_raise(self):
        from auth_middleware import InvalidTokenError
        with pytest.raises(InvalidTokenError, match="bad token"):
            raise InvalidTokenError("bad token")

    def test_invalid_claim_error_raise(self):
        from auth_middleware import InvalidClaimError
        with pytest.raises(InvalidClaimError, match="missing sub"):
            raise InvalidClaimError("missing sub")

    def test_insufficient_permissions_raise(self):
        from auth_middleware import InsufficientPermissions
        with pytest.raises(InsufficientPermissions, match="not allowed"):
            raise InsufficientPermissions("not allowed")


# ---------------------------------------------------------------------------
# Test: _extract_user_context
# ---------------------------------------------------------------------------

class TestExtractUserContext:
    def test_extracts_username(self, valid_payload):
        from auth_middleware import _extract_user_context
        ctx = _extract_user_context(valid_payload)
        assert ctx.user_id == "testuser"

    def test_extracts_email(self, valid_payload):
        from auth_middleware import _extract_user_context
        ctx = _extract_user_context(valid_payload)
        assert ctx.email == "testuser@example.com"

    def test_extracts_sub(self, valid_payload):
        from auth_middleware import _extract_user_context
        ctx = _extract_user_context(valid_payload)
        assert ctx.sub == "e97ec0ef-4e7b-4e7d-ab80-b14b298173c9"

    def test_extracts_role_custom(self, valid_payload):
        from auth_middleware import _extract_user_context
        ctx = _extract_user_context(valid_payload)
        assert ctx.role == "investigator"

    def test_extracts_exp(self, valid_payload):
        from auth_middleware import _extract_user_context
        ctx = _extract_user_context(valid_payload)
        assert isinstance(ctx.exp, int)

    def test_missing_sub_raises(self):
        from auth_middleware import _extract_user_context, InvalidClaimError
        with pytest.raises(InvalidClaimError):
            _extract_user_context({})

    def test_falls_back_to_sub_when_no_preferred_username(self):
        from auth_middleware import _extract_user_context
        payload = {
            "sub": "some-uuid",
            "exp": int(time.time()) + 300,
        }
        ctx = _extract_user_context(payload)
        assert ctx.user_id == "some-uuid"

    def test_no_role_when_only_default_roles(self):
        from auth_middleware import _extract_user_context
        payload = {
            "sub": "uuid",
            "preferred_username": "u",
            "realm_access": {
                "roles": ["default-roles-forensics", "offline_access", "uma_authorization"]
            },
        }
        ctx = _extract_user_context(payload)
        assert ctx.role is None

    def test_role_is_none_when_realm_access_missing(self):
        from auth_middleware import _extract_user_context
        ctx = _extract_user_context({"sub": "uuid", "preferred_username": "u"})
        assert ctx.role is None


# ---------------------------------------------------------------------------
# Test: _decode_token with mocked JWKS
# ---------------------------------------------------------------------------

class TestDecodeToken:
    @pytest.mark.asyncio
    async def test_valid_token_decoded(self, valid_token, jwks, valid_payload):
        from auth_middleware import _decode_token
        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, return_value=jwks):
            with patch("auth_middleware.get_issuer", return_value=valid_payload["iss"]):
                payload = await _decode_token(valid_token)
                assert payload["preferred_username"] == "testuser"

    @pytest.mark.asyncio
    async def test_expired_token_raises(self, rsa_keys, jwks):
        from auth_middleware import _decode_token, InvalidTokenError
        private_key, _ = rsa_keys
        expired_payload = {
            "sub": "uuid",
            "iss": "http://localhost:8080/realms/forensics",
            "iat": int(time.time()) - 600,
            "exp": int(time.time()) - 300,
        }
        expired_token = _make_token(expired_payload, private_key)

        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, return_value=jwks):
            with patch("auth_middleware.get_issuer", return_value=expired_payload["iss"]):
                with pytest.raises(InvalidTokenError, match="expired"):
                    await _decode_token(expired_token)

    @pytest.mark.asyncio
    async def test_invalid_token_raises(self, jwks, valid_payload):
        from auth_middleware import _decode_token, InvalidTokenError
        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, return_value=jwks):
            with patch("auth_middleware.get_issuer", return_value=valid_payload["iss"]):
                with pytest.raises(InvalidTokenError):
                    await _decode_token("not.a.valid.token")

    @pytest.mark.asyncio
    async def test_jwks_fetch_failure_raises(self):
        from auth_middleware import _decode_token, InvalidTokenError
        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, side_effect=Exception("network error")):
            with pytest.raises(InvalidTokenError, match="Unable to fetch JWKS"):
                await _decode_token("any.token.here")

    @pytest.mark.asyncio
    async def test_wrong_issuer_raises(self, valid_token, jwks):
        from auth_middleware import _decode_token, InvalidTokenError
        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, return_value=jwks):
            with patch("auth_middleware.get_issuer", return_value="http://wrong-issuer/realms/other"):
                with pytest.raises(InvalidTokenError):
                    await _decode_token(valid_token)


# ---------------------------------------------------------------------------
# Test: get_current_user dependency (via TestClient)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def auth_client(jwks, valid_payload):
    """Create a minimal TestClient for testing get_current_user."""
    with patch("storage.Minio"):
        from sqlalchemy import create_engine as real_ce
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from database import Base

        engine = real_ce(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=engine)
        TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        import database
        database.engine = engine
        database.SessionLocal = TestSession

        import main as app_module
        importlib.reload(app_module)

        from fastapi.testclient import TestClient
        return TestClient(app_module.app, raise_server_exceptions=False)


class TestGetCurrentUser:
    def test_missing_auth_header_returns_401(self, auth_client):
        resp = auth_client.get("/forensics/summary")
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, auth_client, jwks, valid_payload):
        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, return_value=jwks):
            with patch("auth_middleware.get_issuer", return_value=valid_payload["iss"]):
                resp = auth_client.get(
                    "/forensics/summary",
                    headers={"Authorization": "Bearer not.a.valid.token"},
                )
        assert resp.status_code == 401

    def test_valid_token_grants_access(self, auth_client, valid_token, jwks, valid_payload):
        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, return_value=jwks):
            with patch("auth_middleware.get_issuer", return_value=valid_payload["iss"]):
                resp = auth_client.get(
                    "/forensics/summary",
                    headers={"Authorization": f"Bearer {valid_token}"},
                )
        assert resp.status_code == 200

    def test_verify_chain_requires_auth(self, auth_client):
        resp = auth_client.get("/forensics/verify-chain")
        assert resp.status_code == 401

    def test_export_requires_auth(self, auth_client):
        resp = auth_client.get("/forensics/export")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test: auth routes (/auth/token, /auth/refresh, /auth/verify)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def auth_route_client():
    with patch("storage.Minio"):
        from sqlalchemy import create_engine as real_ce
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from database import Base

        engine = real_ce(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=engine)
        TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        import database
        database.engine = engine
        database.SessionLocal = TestSession

        import main as app_module
        importlib.reload(app_module)

        from fastapi.testclient import TestClient
        return TestClient(app_module.app, raise_server_exceptions=False)


class TestAuthRoutes:
    def test_token_endpoint_exists(self, auth_route_client):
        """POST /auth/token should return 4xx (no Keycloak in test), not 404/405."""
        with patch("auth_routes.httpx.AsyncClient") as mock_ac:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_resp.is_success = False
            mock_ac.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
            resp = auth_route_client.post(
                "/auth/token",
                json={"username": "u", "password": "p"},
            )
        assert resp.status_code != 404
        assert resp.status_code != 405

    def test_token_invalid_credentials_returns_401(self, auth_route_client):
        with patch("auth_routes.httpx.AsyncClient") as mock_ac:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_resp.is_success = False
            mock_ac.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
            resp = auth_route_client.post(
                "/auth/token",
                json={"username": "bad", "password": "wrong"},
            )
        assert resp.status_code == 401

    def test_token_valid_credentials_returns_200(self, auth_route_client):
        keycloak_response = {
            "access_token": "eyJhbGciOiJSUzI1NiJ9.test.sig",
            "refresh_token": "refresh-token-value",
            "token_type": "Bearer",
            "expires_in": 300,
        }
        with patch("auth_routes.httpx.AsyncClient") as mock_ac:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.is_success = True
            mock_resp.json.return_value = keycloak_response
            mock_ac.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
            resp = auth_route_client.post(
                "/auth/token",
                json={"username": "testuser", "password": "Test@123"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 300

    def test_refresh_invalid_token_returns_401(self, auth_route_client):
        with patch("auth_routes.httpx.AsyncClient") as mock_ac:
            mock_resp = MagicMock()
            mock_resp.status_code = 400
            mock_resp.is_success = False
            mock_ac.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
            resp = auth_route_client.post(
                "/auth/refresh",
                json={"refresh_token": "expired-token"},
            )
        assert resp.status_code == 401

    def test_refresh_valid_token_returns_200(self, auth_route_client):
        keycloak_response = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "token_type": "Bearer",
            "expires_in": 300,
        }
        with patch("auth_routes.httpx.AsyncClient") as mock_ac:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.is_success = True
            mock_resp.json.return_value = keycloak_response
            mock_ac.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
            resp = auth_route_client.post(
                "/auth/refresh",
                json={"refresh_token": "valid-refresh-token"},
            )
        assert resp.status_code == 200
        assert resp.json()["access_token"] == "new-access-token"

    def test_verify_without_token_returns_401(self, auth_route_client):
        resp = auth_route_client.get("/auth/verify")
        assert resp.status_code == 401

    def test_verify_with_valid_token_returns_valid_true(
        self, auth_route_client, valid_token, jwks, valid_payload
    ):
        with patch("auth_middleware.fetch_jwks", new_callable=AsyncMock, return_value=jwks):
            with patch("auth_middleware.get_issuer", return_value=valid_payload["iss"]):
                resp = auth_route_client.get(
                    "/auth/verify",
                    headers={"Authorization": f"Bearer {valid_token}"},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["user_id"] == "testuser"
        assert data["email"] == "testuser@example.com"

    def test_token_missing_username_returns_422(self, auth_route_client):
        resp = auth_route_client.post("/auth/token", json={"password": "p"})
        assert resp.status_code == 422

    def test_token_missing_password_returns_422(self, auth_route_client):
        resp = auth_route_client.post("/auth/token", json={"username": "u"})
        assert resp.status_code == 422

    def test_token_keycloak_unavailable_returns_503(self, auth_route_client):
        import httpx as real_httpx
        with patch("auth_routes.httpx.AsyncClient") as mock_ac:
            mock_ac.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=real_httpx.RequestError("connection refused")
            )
            resp = auth_route_client.post(
                "/auth/token",
                json={"username": "u", "password": "p"},
            )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Test: keycloak_config module
# ---------------------------------------------------------------------------

class TestKeycloakConfig:
    def test_realm_url_built_correctly(self):
        import keycloak_config
        assert "forensics" in keycloak_config.REALM_URL

    def test_jwks_url_contains_certs(self):
        import keycloak_config
        assert "certs" in keycloak_config.JWKS_URL

    def test_token_url_contains_token(self):
        import keycloak_config
        assert "token" in keycloak_config.TOKEN_URL

    def test_invalidate_cache(self):
        import keycloak_config
        keycloak_config._jwks_cache = {"keys": []}
        keycloak_config.invalidate_jwks_cache()
        assert keycloak_config._jwks_cache is None

    @pytest.mark.asyncio
    async def test_fetch_jwks_uses_cache(self, jwks):
        import keycloak_config
        keycloak_config.invalidate_jwks_cache()
        with patch("keycloak_config.httpx.AsyncClient") as mock_ac:
            mock_resp = MagicMock()
            mock_resp.json.return_value = jwks
            mock_resp.raise_for_status = MagicMock()
            mock_ac.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_resp)
            result1 = await keycloak_config.fetch_jwks()
            result2 = await keycloak_config.fetch_jwks()
            # Second call should use the cache, not make another HTTP request
            assert mock_ac.return_value.__aenter__.return_value.get.call_count == 1
            assert result1 == result2

    @pytest.mark.asyncio
    async def test_fetch_jwks_raises_when_no_cache_and_error(self):
        import keycloak_config
        keycloak_config.invalidate_jwks_cache()
        with patch("keycloak_config.httpx.AsyncClient") as mock_ac:
            mock_ac.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("network error")
            )
            with pytest.raises(Exception, match="network error"):
                await keycloak_config.fetch_jwks()
