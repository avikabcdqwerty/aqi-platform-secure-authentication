# AQI Platform Secure Authentication

## Overview

All AQI API endpoints are protected by robust authentication middleware supporting both OAuth2 and JWT flows. Access is strictly enforced for authorized researchers, with role-based access control (RBAC), rate limiting, lockout, and comprehensive audit logging.

---

## Authentication Flows

### 1. JWT Authentication

- **Bearer Token**: Clients send a JWT in the `Authorization: Bearer <token>` header.
- **Validation**: The middleware verifies the JWT signature, expiry (`exp`), audience, and required claims (`sub`, `role`).
- **Revocation**: Optionally, tokens may be checked for revocation.
- **RBAC**: The `role` claim is checked against allowed roles for the endpoint.

#### Example Request

```http
GET /api/aqi
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 2. OAuth2 Authentication

- **Bearer Token**: Clients send an OAuth2 access token in the `Authorization: Bearer <token>` header.
- **Introspection**: The middleware calls the configured OAuth2 introspection endpoint to validate the token.
- **Claims**: The response must include `active: true`, `sub`, `role`, and optionally `scope`.
- **RBAC**: The `role` claim is checked against allowed roles for the endpoint.

#### Example Request

```http
GET /api/aqi
Authorization: Bearer <oauth2_access_token>
```

---

## Error Codes & Responses

| HTTP Status | Error Code      | Description                                                                 |
|-------------|----------------|-----------------------------------------------------------------------------|
| 401         | Unauthorized   | Missing, expired, malformed, or revoked token.                              |
| 403         | Forbidden      | Valid token, but insufficient permissions (role or scope).                   |
| 429         | Too Many Requests | Rate limit or lockout triggered due to repeated failed authentication attempts. |
| 422         | Validation Error | Request validation failed (e.g., malformed input).                          |
| 500         | Internal Server Error | Unexpected server error.                                             |

### Example Error Response

```json
{
  "error": "Unauthorized: Token has expired",
  "code": 401
}
```

---

## Rate Limiting & Lockout

- **Failed Authentication Attempts**: Tracked per token and client IP using Redis.
- **Limit**: After `AUTH_FAILED_ATTEMPTS_LIMIT` consecutive failures, lockout is enforced for `AUTH_LOCKOUT_TTL` seconds.
- **Response**: Locked out clients receive a `429 Too Many Requests` error.
- **Reset**: Successful authentication resets the failed attempt counter and lockout state.

---

## Security Considerations

- **TLS Enforcement**: All authentication traffic must be encrypted using TLS 1.2 or higher.
- **Secret Management**: JWT keys and OAuth2 secrets are stored securely via environment variables or HashiCorp Vault/KMS.
- **No Plaintext Credentials**: No sensitive credential data is stored or logged in plaintext.
- **Audit Logging**: All authentication and authorization events are logged in a structured, sanitized format for compliance.
- **Stateless Middleware**: Authentication logic is stateless and thread-safe.
- **No Fallback**: Unauthenticated access is never permitted.

---

## Required Claims

| Claim   | Description                  | Required |
|---------|------------------------------|----------|
| sub     | Subject (user identifier)    | Yes      |
| role    | User role (e.g., researcher) | Yes      |
| exp     | Expiry (UNIX timestamp)      | Yes      |
| scope   | OAuth2 scopes (optional)     | Optional |

---

## RBAC Enforcement

- **Default Role**: All endpoints require at least the `researcher` role.
- **Custom Roles**: Additional roles (e.g., `admin`) may be required for specific endpoints.
- **Insufficient Role**: Users with valid credentials but insufficient roles receive a `403 Forbidden` error.

---

## Audit Logging

- **Events Logged**: Authentication success, failure, authorization failure, rate limit, lockout, and validation errors.
- **Sanitization**: No tokens, secrets, or sensitive credential data are logged.
- **Format**: Structured JSON with timestamp, event type, user, endpoint, status code, detail, and client IP.

---

## Automated Testing

- **Coverage**: Authentication success, failure (expired, malformed, revoked), RBAC, rate limiting, lockout, and edge cases.
- **Tools**: `pytest` with FastAPI `TestClient` and mocking for deterministic tests.

---

## Configuration

All secrets, keys, and limits are configured via environment variables or Vault/KMS. See `src/config/settings.py` for details.

---

## Example Environment Variables

```
AQI_API_HOST=0.0.0.0
AQI_API_PORT=8000
AQI_API_ENFORCE_HTTPS=true
AQI_JWT_ALGORITHMS=RS256
AQI_JWT_AUDIENCE=aqi-platform
AQI_ALLOWED_ROLES=researcher,admin
AQI_OAUTH2_INTROSPECTION_URL=https://auth.example.com/introspect
AQI_OAUTH2_CLIENT_ID=your-client-id
AQI_OAUTH2_CLIENT_SECRET=your-client-secret
AQI_REDIS_URL=redis://localhost:6379/0
AQI_AUTH_FAILED_ATTEMPTS_LIMIT=5
AQI_AUTH_LOCKOUT_TTL=900
AQI_AUTH_RATE_LIMIT_TTL=300
```

---

## Security Linting & Static Analysis

- **Bandit** and **SonarQube** are integrated in CI/CD for security linting and static analysis.

---

## References

- [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 6749: OAuth2](https://tools.ietf.org/html/rfc6749)
- [RFC 7662: OAuth2 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [FastAPI Security Best Practices](https://fastapi.tiangolo.com/advanced/security/)