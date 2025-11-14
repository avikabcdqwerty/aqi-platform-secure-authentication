import time
from typing import Any, Dict
import jwt  # PyJWT
from jwt import InvalidTokenError as PyJWTInvalidTokenError, ExpiredSignatureError, DecodeError

from src.auth.key_store import KeyStore
from src.config.settings import Settings

class TokenValidationError(Exception):
    """Base exception for token validation errors."""
    pass

class InvalidTokenError(TokenValidationError):
    """Raised when a token is malformed or invalid."""
    pass

class ExpiredTokenError(TokenValidationError):
    """Raised when a token is expired."""
    pass

class RevokedTokenError(TokenValidationError):
    """Raised when a token is revoked."""
    pass

class TokenValidator:
    """
    Validates JWT tokens for authentication and authorization.
    Checks signature, expiry, and parses claims.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.key_store = KeyStore(settings=settings)

    def is_jwt(self, token: str) -> bool:
        """
        Heuristically determines if the token is a JWT.
        """
        # JWTs have three dot-separated base64url segments
        return token.count('.') == 2

    def validate(self, token: str) -> Dict[str, Any]:
        """
        Validates a JWT token.
        Returns claims if valid, raises exception otherwise.
        """
        try:
            # Get public key(s) for signature verification
            public_keys = self.key_store.get_public_keys()
            # Try each key (support for key rotation)
            last_error = None
            for key in public_keys:
                try:
                    claims = jwt.decode(
                        token,
                        key=key,
                        algorithms=self.settings.JWT_ALGORITHMS,
                        audience=self.settings.JWT_AUDIENCE,
                        options={
                            "verify_signature": True,
                            "verify_exp": True,
                            "verify_aud": True,
                            "require": ["exp", "sub", "role"]
                        }
                    )
                    # Check for revocation (optional, e.g., via Redis or DB)
                    if self.key_store.is_token_revoked(token):
                        raise RevokedTokenError("Token has been revoked")
                    # Additional custom claim checks (e.g., scope, role)
                    self._validate_claims(claims)
                    return claims
                except (PyJWTInvalidTokenError, ExpiredSignatureError, DecodeError) as e:
                    last_error = e
                    continue
            # If none of the keys worked, raise error
            if isinstance(last_error, ExpiredSignatureError):
                raise ExpiredTokenError("Token has expired")
            elif isinstance(last_error, PyJWTInvalidTokenError):
                raise InvalidTokenError("Invalid JWT token")
            elif isinstance(last_error, DecodeError):
                raise InvalidTokenError("Malformed JWT token")
            else:
                raise InvalidTokenError("JWT validation failed")
        except RevokedTokenError as e:
            raise
        except ExpiredTokenError as e:
            raise
        except Exception as e:
            raise TokenValidationError(f"Token validation error: {str(e)}")

    def _validate_claims(self, claims: Dict[str, Any]) -> None:
        """
        Additional claim validation (role, scope, etc.).
        Raises InvalidTokenError if claims are insufficient.
        """
        # Ensure required claims are present
        required_claims = ["sub", "role", "exp"]
        for claim in required_claims:
            if claim not in claims:
                raise InvalidTokenError(f"Missing required claim: {claim}")

        # Check expiry (redundant if PyJWT verifies 'exp', but double-check for safety)
        exp = claims.get("exp")
        if exp is not None and int(exp) < int(time.time()):
            raise ExpiredTokenError("Token has expired")

        # Role validation (optional, can be enforced in middleware)
        role = claims.get("role")
        if role not in self.settings.ALLOWED_ROLES:
            raise InvalidTokenError(f"Invalid role: {role}")

        # Scope validation (optional)
        # scopes = claims.get("scope", [])
        # if not isinstance(scopes, list):
        #     raise InvalidTokenError("Invalid scope format")

__all__ = [
    "TokenValidator",
    "TokenValidationError",
    "InvalidTokenError",
    "ExpiredTokenError",
    "RevokedTokenError"
]