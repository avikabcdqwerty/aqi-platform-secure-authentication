import os
from typing import List
from src.config.settings import Settings

try:
    import hvac  # HashiCorp Vault client
except ImportError:
    hvac = None  # Vault integration is optional, fallback to env vars

class KeyStoreError(Exception):
    """Raised when key retrieval or secret management fails."""
    pass

class KeyStore:
    """
    Manages JWT signing keys and secrets.
    Integrates with HashiCorp Vault/KMS or environment variables.
    Provides key rotation and revocation support.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self._vault_client = None
        if self.settings.VAULT_ENABLED and hvac:
            self._vault_client = self._init_vault_client()

    def _init_vault_client(self):
        """
        Initializes the HashiCorp Vault client.
        """
        try:
            client = hvac.Client(
                url=self.settings.VAULT_ADDR,
                token=self.settings.VAULT_TOKEN,
                verify=self.settings.TLS_VERIFY
            )
            if not client.is_authenticated():
                raise KeyStoreError("Vault authentication failed")
            return client
        except Exception as e:
            raise KeyStoreError(f"Vault client initialization failed: {str(e)}")

    def get_public_keys(self) -> List[str]:
        """
        Retrieves public keys for JWT signature verification.
        Supports key rotation (returns all active keys).
        """
        keys = []
        if self._vault_client:
            try:
                # Example: Read keys from Vault at a configured path
                secret = self._vault_client.secrets.kv.v2.read_secret_version(
                    path=self.settings.VAULT_JWT_PUBLIC_KEYS_PATH
                )
                keys_data = secret["data"]["data"]
                for key_name, key_value in keys_data.items():
                    if key_value:
                        keys.append(key_value)
            except Exception as e:
                raise KeyStoreError(f"Failed to retrieve public keys from Vault: {str(e)}")
        else:
            # Fallback to environment variable(s)
            env_keys = os.getenv(self.settings.JWT_PUBLIC_KEYS_ENV, "")
            for key in env_keys.split(";"):
                key = key.strip()
                if key:
                    keys.append(key)
        if not keys:
            raise KeyStoreError("No public keys available for JWT verification")
        return keys

    def get_private_key(self) -> str:
        """
        Retrieves the private key for JWT signing (if needed).
        """
        if self._vault_client:
            try:
                secret = self._vault_client.secrets.kv.v2.read_secret_version(
                    path=self.settings.VAULT_JWT_PRIVATE_KEY_PATH
                )
                key = secret["data"]["data"].get("private_key")
                if not key:
                    raise KeyStoreError("Private key not found in Vault")
                return key
            except Exception as e:
                raise KeyStoreError(f"Failed to retrieve private key from Vault: {str(e)}")
        else:
            key = os.getenv(self.settings.JWT_PRIVATE_KEY_ENV, "")
            if not key:
                raise KeyStoreError("Private key not found in environment")
            return key

    def is_token_revoked(self, token: str) -> bool:
        """
        Checks if a token has been revoked.
        This can be implemented via Redis, Vault, or a database.
        For now, always returns False (no revocation).
        """
        # TODO: Integrate with Redis or Vault for real revocation tracking
        return False

__all__ = [
    "KeyStore",
    "KeyStoreError"
]