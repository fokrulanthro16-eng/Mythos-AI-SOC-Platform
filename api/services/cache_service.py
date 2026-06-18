"""api/services/cache_service.py — Redis async wrapper with graceful degradation."""

from __future__ import annotations

import json
import os
from typing import Any

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


class CacheService:
    """Thin async wrapper around redis.asyncio. Falls back silently when Redis
    is unavailable so the API continues to work without caching."""

    def __init__(self) -> None:
        self._client: Any = None

    async def connect(self) -> None:
        try:
            import redis.asyncio as aioredis  # type: ignore[import]

            client = aioredis.from_url(_REDIS_URL, decode_responses=True)
            await client.ping()
            self._client = client
        except Exception:
            self._client = None

    async def disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    async def get(self, key: str) -> Any | None:
        if not self._client:
            return None
        try:
            val = await self._client.get(key)
            return json.loads(val) if val else None
        except Exception:
            return None

    async def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        if not self._client:
            return False
        try:
            await self._client.setex(key, ttl, json.dumps(value, default=str))
            return True
        except Exception:
            return False

    async def delete(self, key: str) -> bool:
        if not self._client:
            return False
        try:
            await self._client.delete(key)
            return True
        except Exception:
            return False

    async def is_blacklisted(self, jti: str) -> bool:
        if not self._client:
            return False
        try:
            return bool(await self._client.exists(f"blacklist:{jti}"))
        except Exception:
            return False

    async def blacklist_token(self, jti: str, ttl: int) -> None:
        if not self._client:
            return
        try:
            await self._client.setex(f"blacklist:{jti}", ttl, "1")
        except Exception:
            pass

    async def invalidate_user_tokens(self, user_id: str) -> None:
        if not self._client:
            return
        try:
            await self._client.setex(f"user_invalidated:{user_id}", 86_400, "1")
        except Exception:
            pass


cache = CacheService()
