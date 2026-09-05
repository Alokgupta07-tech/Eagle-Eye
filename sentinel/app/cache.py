"""Session context store. Canonical: Redis (N=20 window, activity-extended TTL).
Fallback: in-memory store with identical semantics. Multi-turn reassembly depends on this."""
from __future__ import annotations

import time
from collections import deque


class MemorySessionStore:
    mode = "memory"

    def __init__(self, window: int, ttl_s: int):
        self.maxlen = window
        self.ttl = ttl_s
        self._data: dict[str, deque] = {}
        self._exp: dict[str, float] = {}

    def _prune(self, sid: str):
        if sid in self._exp and self._exp[sid] < time.time() and sid in self._data:
            if self._exp[sid] < time.time():
                del self._data[sid]
                del self._exp[sid]

    async def push(self, sid: str, text: str):
        self._prune(sid)
        dq = self._data.setdefault(sid, deque(maxlen=self.maxlen))
        dq.append(text)
        self._exp[sid] = time.time() + self.ttl   # TTL extended on ACTIVITY, not creation

    async def window(self, sid: str) -> list[str]:
        self._prune(sid)
        return list(self._data.get(sid, ()))

    async def ping(self) -> bool:
        return True

    async def close(self):
        pass


class RedisSessionStore:
    mode = "redis"

    def __init__(self, client, window: int, ttl_s: int):
        self.r = client
        self.window = window
        self.ttl = ttl_s

    async def push(self, sid: str, text: str):
        key = f"sess:{sid}:msgs"
        pipe = self.r.pipeline()
        pipe.rpush(key, text)
        pipe.ltrim(key, -self.window, -1)
        pipe.expire(key, self.ttl)                # activity-extended TTL
        await pipe.execute()

    async def window(self, sid: str) -> list[str]:
        vals = await self.r.lrange(f"sess:{sid}:msgs", 0, -1)
        return [v.decode() if isinstance(v, bytes) else v for v in vals]

    async def ping(self) -> bool:
        return bool(await self.r.ping())

    async def close(self):
        await self.r.aclose()


async def build_session_store(settings):
    """Redis when available and reachable; memory otherwise. Never raises."""
    try:
        import redis.asyncio as aioredis  # type: ignore
        client = aioredis.from_url(settings.REDIS_URL, socket_timeout=1.5,
                                   socket_connect_timeout=1.5)
        store = RedisSessionStore(client, settings.SESSION_WINDOW, settings.SESSION_TTL_S)
        if await store.ping():
            return store
    except Exception as exc:  # noqa: BLE001
        print(f"[cache] redis unavailable ({exc.__class__.__name__}); using memory store")
    return MemorySessionStore(settings.SESSION_WINDOW, settings.SESSION_TTL_S)
