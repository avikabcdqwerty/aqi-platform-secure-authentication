import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from src.main import app
from src.config.settings import get_settings
from src.middleware.auth_middleware import AuthMiddleware
from src.auth.token_validator import TokenValidator, InvalidTokenError, ExpiredTokenError, RevokedTokenError
from src.auth.oauth2_introspector import OAuth2Introspector, OAuth2IntrospectionError

client = TestClient(app)

# Fixtures and helpers

@pytest.fixture
def valid_jwt_token():
    # This should be a valid JWT for testing; here we use a dummy string
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJyZXNlYXJjaGVyIiwiZXhwIjo0NzAwMDAwMDAwLCJzY29wZSI6WyJhY2Nlc3MiXX0.signature"

@pytest.fixture
def expired_jwt_token():
    # Dummy expired JWT
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJyZXNlYXJjaGVyIiwiZXhwIjoxMDAwLCJzY29wZSI6WyJhY2Nlc3MiXX0.signature"

@pytest.fixture
def malformed_token():
    return "not.a.jwt"

@pytest.fixture
def valid_oauth2_token():
    return "oauth2_valid_token"

@pytest.fixture
def insufficient_role_jwt_token():
    # JWT with role not allowed
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMiIsInJvbGUiOiJndWVzdCIsImV4cCI6NDcwMDAwMDAwMCwic2NvcGUiOlsiYWNjZXNzIl19.signature"

# Mock TokenValidator and OAuth2Introspector for deterministic tests

@pytest.fixture(autouse=True)
def patch_token_validator_and_oauth2(monkeypatch):
    # Patch TokenValidator
    monkeypatch.setattr(TokenValidator, "is_jwt", lambda self, token: "." in token)
    monkeypatch.setattr(TokenValidator, "validate", lambda self, token: {
        "sub": "user1",
        "role": "researcher",
        "exp": 4700000000,
        "scope": ["access"]
    } if "expired" not in token and "insufficient" not in token else (
        pytest.raises(ExpiredTokenError) if "expired" in token else pytest.raises(InvalidTokenError)
    ))
    # Patch for insufficient role
    def validate_role(self, token):
        if "insufficient" in token:
            return {"sub": "user2", "role": "guest", "exp": 4700000000, "scope": ["access"]}
        if "expired" in token:
            raise ExpiredTokenError("Token has expired")
        if "malformed" in token:
            raise InvalidTokenError("Malformed token")
        return {"sub": "user1", "role": "researcher", "exp": 4700000000, "scope": ["access"]}
    monkeypatch.setattr(TokenValidator, "validate", validate_role)

    # Patch OAuth2Introspector
    async def introspect(self, token):
        if token == "oauth2_valid_token":
            return {"sub": "user_oauth", "role": "researcher", "exp": 4700000000, "scope": ["access"], "active": True}
        if token == "oauth2_expired_token":
            raise OAuth2IntrospectionError("Token has expired")
        if token == "oauth2_insufficient_role":
            return {"sub": "user_oauth", "role": "guest", "exp": 4700000000, "scope": ["access"], "active": True}
        raise OAuth2IntrospectionError("Invalid token")
    monkeypatch.setattr(OAuth2Introspector, "introspect", introspect)

# Test cases

def test_unauthenticated_access():
    """Unauthenticated users receive 401 Unauthorized."""
    response = client.get("/api/aqi")
    assert response.status_code == 401
    assert "Unauthorized" in response.json()["error"]

def test_authenticated_jwt_access(valid_jwt_token):
    """Authenticated users with valid JWT are granted access."""
    response = client.get("/api/aqi", headers={"Authorization": f"Bearer {valid_jwt_token}"})
    assert response.status_code == 200
    assert response.json()["user"] == "user1"
    assert response.json()["role"] == "researcher"

def test_expired_jwt_access(expired_jwt_token):
    """Users with expired JWT receive clear error."""
    response = client.get("/api/aqi", headers={"Authorization": f"Bearer {expired_jwt_token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["error"].lower()

def test_malformed_token_access(malformed_token):
    """Users with malformed token receive clear error."""
    response = client.get("/api/aqi", headers={"Authorization": f"Bearer {malformed_token}"})
    assert response.status_code == 401
    assert "malformed" in response.json()["error"].lower() or "invalid" in response.json()["error"].lower()

def test_insufficient_role_jwt_access(insufficient_role_jwt_token):
    """Users with valid JWT but insufficient permissions receive 403 Forbidden."""
    response = client.get("/api/aqi", headers={"Authorization": f"Bearer {insufficient_role_jwt_token}"})
    assert response.status_code == 403
    assert "forbidden" in response.json()["error"].lower()

def test_authenticated_oauth2_access(valid_oauth2_token):
    """Authenticated users with valid OAuth2 token are granted access."""
    response = client.get("/api/aqi", headers={"Authorization": f"Bearer {valid_oauth2_token}"})
    assert response.status_code == 200
    assert response.json()["user"] == "user_oauth"
    assert response.json()["role"] == "researcher"

def test_expired_oauth2_access():
    """Users with expired OAuth2 token receive clear error."""
    response = client.get("/api/aqi", headers={"Authorization": "Bearer oauth2_expired_token"})
    assert response.status_code == 401
    assert "expired" in response.json()["error"].lower()

def test_insufficient_role_oauth2_access():
    """Users with valid OAuth2 token but insufficient permissions receive 403 Forbidden."""
    response = client.get("/api/aqi", headers={"Authorization": "Bearer oauth2_insufficient_role"})
    assert response.status_code == 403
    assert "forbidden" in response.json()["error"].lower()

def test_health_endpoint_authenticated(valid_jwt_token):
    """Health endpoint is protected and accessible with valid credentials."""
    response = client.get("/health", headers={"Authorization": f"Bearer {valid_jwt_token}"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_health_endpoint_unauthenticated():
    """Health endpoint is protected and not accessible without credentials."""
    response = client.get("/health")
    assert response.status_code == 401
    assert "Unauthorized" in response.json()["error"]

# Edge case: revoked token (simulate via TokenValidator)
def test_revoked_token(monkeypatch, valid_jwt_token):
    """Revoked tokens are rejected with clear error."""
    def revoked_validate(self, token):
        raise RevokedTokenError("Token has been revoked")
    monkeypatch.setattr(TokenValidator, "validate", revoked_validate)
    response = client.get("/api/aqi", headers={"Authorization": f"Bearer {valid_jwt_token}"})
    assert response.status_code == 401
    assert "revoked" in response.json()["error"].lower()