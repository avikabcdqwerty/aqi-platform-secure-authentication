import aioredis
from typing import Optional
from src.config.settings import Settings

class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded."""
    pass

class LockoutError(Exception):
    """Raised when lockout is in effect due to repeated failed attempts."""
    pass

class RateLimiter:
    """
    Tracks failed authentication attempts, enforces rate limiting and lockout.
    Uses Redis for atomic counters and TTL.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.redis_url = settings.REDIS_URL
        self.failed_attempts_limit = settings.AUTH_FAILED_ATTEMPTS_LIMIT
        self.lockout_ttl = settings.AUTH_LOCKOUT_TTL
        self.rate_limit_ttl = settings.AUTH_RATE_LIMIT_TTL
        self._redis: Optional[aioredis.Redis] = None

    async def _get_redis(self) -> aioredis.Redis:
        """
        Lazily initializes and returns the Redis connection.
        """
        if self._redis is None:
            self._redis = await aioredis.create_redis_pool(self.redis_url, encoding="utf-8")
        return self._redis

    def _key(self, token: str, client_ip: str) -> str:
        """
        Generates a Redis key for tracking failed attempts.
        """
        # Use a hash of token and IP for privacy and uniqueness
        import hashlib
        key_raw = f"auth:fail:{client_ip}:{token}"
        return "aqi_auth_fail_" + hashlib.sha256(key_raw.encode()).hexdigest()

    def _lockout_key(self, token: str, client_ip: str) -> str:
        """
        Generates a Redis key for lockout state.
        """
        import hashlib
        key_raw = f"auth:lockout:{client_ip}:{token}"
        return "aqi_auth_lockout_" + hashlib.sha256(key_raw.encode()).hexdigest()

    async def check_attempt(self, token: str, client_ip: str) -> None:
        """
        Checks if the client/token is currently rate limited or locked out.
        Raises RateLimitExceededError or LockoutError if limits are exceeded.
        """
        redis = await self._get_redis()
        lockout_key = self._lockout_key(token, client_ip)
        lockout = await redis.get(lockout_key)
        if lockout:
            raise LockoutError("Lockout in effect due to repeated failed authentication attempts.")
        fail_key = self._key(token, client_ip)
        fail_count = await redis.get(fail_key)
        if fail_count and int(fail_count) >= self.failed_attempts_limit:
            # Set lockout
            await redis.set(lockout_key, "1", expire=self.lockout_ttl)
            await redis.delete(fail_key)
            raise LockoutError("Lockout in effect due to repeated failed authentication attempts.")
        # Optionally implement global rate limiting here

    async def increment_failed_attempt(self, token: str, client_ip: str) -> None:
        """
        Increments the failed authentication attempt counter.
        """
        redis = await self._get_redis()
        fail_key = self._key(token, client_ip)
        count = await redis.incr(fail_key)
        if count == 1:
            await redis.expire(fail_key, self.rate_limit_ttl)
        if count >= self.failed_attempts_limit:
            lockout_key = self._lockout_key(token, client_ip)
            await redis.set(lockout_key, "1", expire=self.lockout_ttl)
            await redis.delete(fail_key)

    async def reset_attempts(self, token: str, client_ip: str) -> None:
        """
        Resets the failed attempt counter and lockout state after successful authentication.
        """
        redis = await self._get_redis()
        fail_key = self._key(token, client_ip)
        lockout_key = self._lockout_key(token, client_ip)
        await redis.delete(fail_key)
        await redis.delete(lockout_key)

    async def close(self) -> None:
        """
        Closes the Redis connection.
        """
        if self._redis:
            self._redis.close()
            await self._redis.wait_closed()
            self._redis = None

__all__ = [
    "RateLimiter",
    "RateLimitExceededError",
    "LockoutError"
]