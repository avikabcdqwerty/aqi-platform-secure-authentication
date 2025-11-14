from typing import Callable, Optional, Any
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS
from starlette.types import ASGIApp

from src.auth.token_validator import TokenValidator, TokenValidationError, InvalidTokenError, ExpiredTokenError, RevokedTokenError
from src.auth.oauth2_introspector import OAuth2Introspector, OAuth2IntrospectionError
from src.security.rate_limiter import RateLimiter, RateLimitExceededError, LockoutError
from src.config.settings import Settings
from src.logging.audit_logger import AuditLogger

class AuthMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware for authentication and RBAC enforcement.
    Supports JWT and OAuth2 tokens, rate limiting, lockout, and audit logging.
    """

    def __init__(
        self,
        app: ASGIApp,
        settings: Settings,
        audit_logger: AuditLogger,
    ):
        super().__init__(app)
        self.settings = settings
        self.audit_logger = audit_logger
        self.token_validator = TokenValidator(settings=settings)
        self.oauth2_introspector = OAuth2Introspector(settings=settings)
        self.rate_limiter = RateLimiter(settings=settings)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Extract Authorization header
        auth_header: Optional[str] = request.headers.get("authorization")
        endpoint = str(request.url)
        client_ip = request.client.host if request.client else "unknown"

        # All endpoints require authentication
        if not auth_header or not auth_header.lower().startswith("bearer "):
            self.audit_logger.log_event(
                event_type="auth_failure",
                user=None,
                endpoint=endpoint,
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header",
                client_ip=client_ip
            )
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={
                    "error": "Unauthorized: Missing or invalid Authorization header",
                    "code": HTTP_401_UNAUTHORIZED
                }
            )

        token = auth_header.split(" ", 1)[1].strip()

        # Rate limiting and lockout check (by token or IP)
        try:
            await self.rate_limiter.check_attempt(token=token, client_ip=client_ip)
        except RateLimitExceededError as e:
            self.audit_logger.log_event(
                event_type="rate_limit_exceeded",
                user=None,
                endpoint=endpoint,
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                detail=str(e),
                client_ip=client_ip
            )
            return JSONResponse(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Too many authentication attempts. Please try again later.",
                    "code": HTTP_429_TOO_MANY_REQUESTS
                }
            )
        except LockoutError as e:
            self.audit_logger.log_event(
                event_type="lockout",
                user=None,
                endpoint=endpoint,
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                detail=str(e),
                client_ip=client_ip
            )
            return JSONResponse(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Account temporarily locked due to repeated failed authentication attempts.",
                    "code": HTTP_429_TOO_MANY_REQUESTS
                }
            )

        # Token validation (JWT or OAuth2)
        user_claims: Optional[dict] = None
        token_type: Optional[str] = None
        try:
            if self.token_validator.is_jwt(token):
                # Validate JWT token
                user_claims = self.token_validator.validate(token)
                token_type = "jwt"
            else:
                # OAuth2 token introspection
                user_claims = await self.oauth2_introspector.introspect(token)
                token_type = "oauth2"
        except (InvalidTokenError, ExpiredTokenError, RevokedTokenError, TokenValidationError, OAuth2IntrospectionError) as e:
            # Log failed attempt and increment rate limiter
            await self.rate_limiter.increment_failed_attempt(token=token, client_ip=client_ip)
            self.audit_logger.log_event(
                event_type="auth_failure",
                user=None,
                endpoint=endpoint,
                status_code=HTTP_401_UNAUTHORIZED,
                detail=str(e),
                client_ip=client_ip
            )
            error_detail = "Unauthorized: " + str(e)
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={
                    "error": error_detail,
                    "code": HTTP_401_UNAUTHORIZED
                }
            )

        # Reset failed attempts on successful authentication
        await self.rate_limiter.reset_attempts(token=token, client_ip=client_ip)

        # RBAC enforcement
        required_roles = self._get_required_roles(request)
        user_role = user_claims.get("role")
        if required_roles and user_role not in required_roles:
            self.audit_logger.log_event(
                event_type="authorization_failure",
                user=user_claims.get("sub"),
                endpoint=endpoint,
                status_code=HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: required roles {required_roles}, user role {user_role}",
                client_ip=client_ip
            )
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={
                    "error": "Forbidden: Insufficient permissions",
                    "code": HTTP_403_FORBIDDEN
                }
            )

        # Attach user info to request.state for downstream handlers
        request.state.user = {
            "sub": user_claims.get("sub"),
            "role": user_role,
            "token_type": token_type,
            "scopes": user_claims.get("scope", []),
        }

        # Log successful authentication event
        self.audit_logger.log_event(
            event_type="auth_success",
            user=user_claims.get("sub"),
            endpoint=endpoint,
            status_code=200,
            detail=f"Authenticated via {token_type}",
            client_ip=client_ip
        )

        # Proceed to next handler
        response = await call_next(request)
        return response

    def _get_required_roles(self, request: Request) -> Optional[list]:
        """
        Determine required roles for the endpoint.
        This can be extended to use route metadata, OpenAPI tags, or custom decorators.
        For now, all endpoints require 'researcher' role by default.
        """
        # Example: Use route tags or path to determine required roles
        path = request.url.path
        if path.startswith("/api/aqi"):
            return ["researcher"]
        if path.startswith("/health"):
            return ["researcher"]
        # Default required role
        return ["researcher"]

__all__ = ["AuthMiddleware"]