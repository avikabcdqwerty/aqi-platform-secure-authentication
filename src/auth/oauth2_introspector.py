import httpx
from typing import Dict, Any
from src.config.settings import Settings

class OAuth2IntrospectionError(Exception):
    """Raised when OAuth2 token introspection fails."""
    pass

class OAuth2Introspector:
    """
    Handles OAuth2 token introspection via remote provider.
    Validates token, checks expiry, parses claims.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.introspection_url = settings.OAUTH2_INTROSPECTION_URL
        self.client_id = settings.OAUTH2_CLIENT_ID
        self.client_secret = settings.OAUTH2_CLIENT_SECRET
        self.allowed_roles = settings.ALLOWED_ROLES

    async def introspect(self, token: str) -> Dict[str, Any]:
        """
        Introspects the OAuth2 token using the remote provider.
        Returns claims if valid, raises exception otherwise.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=self.settings.TLS_VERIFY) as client:
                data = {
                    "token": token,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                response = await client.post(self.introspection_url, data=data, headers=headers)
                if response.status_code != 200:
                    raise OAuth2IntrospectionError(f"Introspection endpoint returned {response.status_code}")
                resp_json = response.json()
                # RFC 7662: 'active' must be True for valid tokens
                if not resp_json.get("active", False):
                    raise OAuth2IntrospectionError("Token is inactive or invalid")
                # Check expiry
                if "exp" in resp_json and int(resp_json["exp"]) < int(self._current_time()):
                    raise OAuth2IntrospectionError("Token has expired")
                # Check required claims
                required_claims = ["sub", "role"]
                for claim in required_claims:
                    if claim not in resp_json:
                        raise OAuth2IntrospectionError(f"Missing required claim: {claim}")
                # Role validation
                role = resp_json.get("role")
                if role not in self.allowed_roles:
                    raise OAuth2IntrospectionError(f"Invalid role: {role}")
                # Optionally check scope, etc.
                return resp_json
        except Exception as e:
            raise OAuth2IntrospectionError(f"OAuth2 introspection failed: {str(e)}")

    def _current_time(self) -> int:
        """Returns current UTC time as integer seconds."""
        import time
        return int(time.time())

__all__ = [
    "OAuth2Introspector",
    "OAuth2IntrospectionError"
]