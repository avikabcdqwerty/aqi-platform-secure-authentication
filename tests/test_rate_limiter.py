import pytest
import asyncio

from src.security.rate_limiter import RateLimiter, RateLimitExceededError, LockoutError
from src.config.settings import get_settings

class DummyRedis:
    """
    Dummy in-memory Redis for testing RateLimiter logic.
    """
    def __init__(self):
        self.store = {}

    async def get(self, key):
        val = self.store.get(key)
        if val is None:
            return None
        if isinstance(val, dict) and "expire" in val:
            import time
            if time.time() > val["expire"]:
                self.store.pop(key)
                return None
            return val["value"]
        return val

    async def set(self, key, value, expire=None):
        if expire:
            import time
            self.store[key] = {"value": value, "expire": time.time() + expire}
        else:
            self.store[key] = value

    async def incr(self, key):
        val = await self.get(key)
        if val is None:
            self.store[key] = 1
            return 1
        if isinstance(val, dict):
            val = val["value"]
        self.store[key] = val + 1
        return val + 1

    async def expire(self, key, ttl):
        if key in self.store:
            import time
            val = self.store[key]
            if isinstance(val, dict):
                val["expire"] = time.time() + ttl
            else:
                self.store[key] = {"value": val, "expire": time.time() + ttl}

    async def delete(self, key):
        self.store.pop(key, None)

    def close(self):
        pass

    async def wait_closed(self):
        pass

@pytest.fixture
def rate_limiter(monkeypatch):
    settings = get_settings()
    rl = RateLimiter(settings=settings)
    dummy_redis = DummyRedis()
    monkeypatch.setattr(rl, "_get_redis", lambda: dummy_redis)
    return rl

@pytest.mark.asyncio
async def test_rate_limiter_allows_initial_attempts(rate_limiter):
    token = "testtoken"
    ip = "127.0.0.1"
    # Should allow up to limit
    for i in range(rate_limiter.failed_attempts_limit):
        await rate_limiter.increment_failed_attempt(token, ip)
        await rate_limiter.check_attempt(token, ip)  # Should not raise

@pytest.mark.asyncio
async def test_rate_limiter_lockout(rate_limiter):
    token = "lockouttoken"
    ip = "127.0.0.2"
    # Exceed limit
    for i in range(rate_limiter.failed_attempts_limit):
        await rate_limiter.increment_failed_attempt(token, ip)
    # Next attempt triggers lockout
    with pytest.raises(LockoutError):
        await rate_limiter.check_attempt(token, ip)

@pytest.mark.asyncio
async def test_rate_limiter_reset_attempts(rate_limiter):
    token = "resettoken"
    ip = "127.0.0.3"
    for i in range(rate_limiter.failed_attempts_limit):
        await rate_limiter.increment_failed_attempt(token, ip)
    # Lockout should be in effect
    with pytest.raises(LockoutError):
        await rate_limiter.check_attempt(token, ip)
    # Reset attempts
    await rate_limiter.reset_attempts(token, ip)
    # Should allow again
    await rate_limiter.check_attempt(token, ip)  # Should not raise

@pytest.mark.asyncio
async def test_rate_limiter_expiry(rate_limiter):
    token = "expirytest"
    ip = "127.0.0.4"
    await rate_limiter.increment_failed_attempt(token, ip)
    # Simulate expiry by manually adjusting DummyRedis
    key = rate_limiter._key(token, ip)
    lockout_key = rate_limiter._lockout_key(token, ip)
    # Expire fail key
    import time
    rate_limiter._get_redis().store[key]["expire"] = time.time() - 1
    # Should be expired
    await rate_limiter.check_attempt(token, ip)  # Should not raise
    # Lockout key expiry
    await rate_limiter.increment_failed_attempt(token, ip)
    rate_limiter._get_redis().store[lockout_key] = {"value": "1", "expire": time.time() - 1}
    await rate_limiter.check_attempt(token, ip)  # Should not raise

@pytest.mark.asyncio
async def test_rate_limiter_multiple_tokens(rate_limiter):
    ip = "127.0.0.5"
    tokens = ["tokenA", "tokenB"]
    for token in tokens:
        for i in range(rate_limiter.failed_attempts_limit):
            await rate_limiter.increment_failed_attempt(token, ip)
    for token in tokens:
        with pytest.raises(LockoutError):
            await rate_limiter.check_attempt(token, ip)