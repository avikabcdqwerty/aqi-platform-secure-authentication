import uvicorn
from fastapi import FastAPI, Request, Response, status, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.config.settings import Settings, get_settings
from src.middleware.auth_middleware import AuthMiddleware
from src.logging.audit_logger import audit_logger

# Initialize FastAPI app
app = FastAPI(
    title="AQI Platform Secure API",
    description="Secure, authenticated API for AQI platform research endpoints.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Load settings
settings: Settings = get_settings()

# Enforce HTTPS (TLS 1.2+) at the application level (for local/dev; production should enforce at gateway/load balancer)
if settings.ENFORCE_HTTPS:
    app.add_middleware(HTTPSRedirectMiddleware)

# CORS configuration (restrict origins for security)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)

# Attach authentication middleware (OAuth2/JWT, RBAC, rate limiting)
app.add_middleware(
    AuthMiddleware,
    settings=settings,
    audit_logger=audit_logger
)

# Global exception handlers for standardized error responses
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    # Log the error event (without sensitive data)
    audit_logger.log_event(
        event_type="http_exception",
        user=None,
        endpoint=str(request.url),
        status_code=exc.status_code,
        detail=str(exc.detail)
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "code": exc.status_code
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    audit_logger.log_event(
        event_type="validation_error",
        user=None,
        endpoint=str(request.url),
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=str(exc.errors())
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation error",
            "details": exc.errors(),
            "code": status.HTTP_422_UNPROCESSABLE_ENTITY
        }
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    audit_logger.log_event(
        event_type="server_error",
        user=None,
        endpoint=str(request.url),
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=str(exc)
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "code": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    )

# Example protected endpoint (all endpoints require authentication via middleware)
@app.get("/api/aqi", tags=["AQI Data"], summary="Get AQI data (protected)")
async def get_aqi_data(request: Request):
    """
    Returns AQI data for authorized researchers.
    Authentication and RBAC enforced by middleware.
    """
    # User info injected by AuthMiddleware (request.state.user)
    user = getattr(request.state, "user", None)
    if not user:
        # Should not happen; middleware enforces authentication
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Unauthorized", "code": status.HTTP_401_UNAUTHORIZED}
        )
    # Example response (replace with real data logic)
    return {
        "user": user["sub"],
        "role": user.get("role"),
        "aqi": 42,
        "status": "success"
    }

# Health check endpoint (protected)
@app.get("/health", tags=["System"], summary="Health check (protected)")
async def health_check(request: Request):
    """
    Health check endpoint. Requires authentication.
    """
    user = getattr(request.state, "user", None)
    if not user:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Unauthorized", "code": status.HTTP_401_UNAUTHORIZED}
        )
    return {"status": "ok"}

# Export FastAPI app for ASGI servers
__all__ = ["app"]

if __name__ == "__main__":
    # Run with Uvicorn (TLS should be enforced in production via gateway/load balancer)
    uvicorn.run(
        "src.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        ssl_keyfile=settings.SSL_KEYFILE if settings.ENFORCE_HTTPS else None,
        ssl_certfile=settings.SSL_CERTFILE if settings.ENFORCE_HTTPS else None,
        log_level="info"
    )