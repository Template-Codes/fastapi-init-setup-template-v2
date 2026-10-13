---
# redis-caching-and-state-rules
Description:
  Redis caching architecture, key namespacing, TTL expiration enforcement, atomic pipelines, and cache invalidation strategies using the stateless async Redis client.
---

# Redis Caching & State Management Rules

This skill governs the async Redis client usage, key namespacing conventions, TTL expiration enforcement, and cache invalidation patterns across the XCOM ERP backend.

---

## 1. Client Access & Dependency Injection

The application uses an asynchronous singleton connection pool defined in `src/clients/redis.py`:
- **FastAPI Dependency**: Always inject `aioredis.Redis` via `Depends(get_async_cache)` from `db.cache_session`.
- **Central Utility**: Use or extend `MaintainCacheKeyUtils` (`src/utils/maintain_cache_key.py`) for consistent key generation and state operations.

```python
from db.cache_session import get_async_cache
import redis.asyncio as aioredis
from fastapi import Depends

class MyService:
    def __init__(self, cache: aioredis.Redis = Depends(get_async_cache)):
        self._cache = cache
```

---

## 2. Key Namespacing Standards

All Redis keys must follow a hierarchical, colon-separated format: `<domain>:<subdomain>:<identifier>` or `<feature>:<param1>:<param2>`.

| Purpose | Pattern | Example |
| :--- | :--- | :--- |
| **User Session** | `user:sessions:{user_id}` | `user:sessions:018f...` |
| **Profile State** | `user:profile_completed:{user_id}` | `user:profile_completed:018f...` |
| **Failed Login Counter** | `failed_login_count:{ip}:{username}` | `failed_login_count:192.168.1.1:admin` |
| **Lockout Block Key** | `failed_login_block:{ip}:{username}` | `failed_login_block:192.168.1.1:admin` |
| **Rate Limiter** | `rate_limit:{ip}:{minute_epoch}` | `rate_limit:10.0.0.1:2849102` |

---

## 3. Mandatory TTL Expiration Enforcement

> [!IMPORTANT]
> **No Unbounded Keys**: Every key created via `set`, `setex`, or counters MUST have an explicit Time-To-Live (`ex` or `expire`). Unbounded keys lead to memory leaks and invalid state persistence.

```python
# Session with JWT TTL
await self.async_cache.set(
    name=f"user:sessions:{user_id}",
    value=session_json,
    ex=settings.REFRESH_JWT_EXPIRY_SEC,
)

# Counter with sliding window expiry
attempts = await self.async_cache.incr(count_key)
if attempts == 1:
    await self.async_cache.expire(count_key, 900)  # 15 minutes window
```

---

## 4. Atomic Pipelines & Rate Limiting

For multi-step key operations or race-condition prevention, use Redis pipelines with transaction support:

```python
async with self.async_cache.pipeline(transaction=True) as pipe:
    pipe.set(session_key, session_data, ex=3600)
    pipe.sadd(f"user:active_sessions:{user_id}", session_id)
    pipe.expire(f"user:active_sessions:{user_id}", 3600)
    await pipe.execute()
```

---

## 5. Safe Cache Invalidation Strategies

1. **Direct Invalidation on Mutation**: Invalidate cached profiles or permissions immediately upon updating or deleting database records.
2. **Safe Pattern Deletions**: Never use blocking `keys()` in production. Always use non-blocking `scan_iter()`:
```python
async def clear_user_cache_patterns(cache: aioredis.Redis, user_id: str):
    async for key in cache.scan_iter(f"*:{user_id}"):
        await cache.delete(key)
```
3. **Graceful Fallbacks**: Catch Redis network errors (`ConnectionError`, `TimeoutError`) and allow the application to fall back gracefully to the primary database when appropriate.
