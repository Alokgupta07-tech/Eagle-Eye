"""Target chatbot client. `internal://mock` routes in-process to the built-in
vulnerable canary target; everything else goes out over HTTP (OpenAI-style chat body)."""
from __future__ import annotations

import httpx

from . import mocktarget

MOCK_PREFIX = "internal://mock"


async def call_target(target: dict, messages: list[dict], session_id: str,
                      settings, timeout: float = 30.0,
                      tools: list[dict] | None = None) -> str:
    url = target["endpoint_url"]
    if url == "internal://anthropic":
        key = settings.ANTHROPIC_API_KEY
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post("https://api.anthropic.com/v1/messages",
                             headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                             json={"model": settings.ANTHROPIC_MODEL, "max_tokens": 300,
                                   "messages": messages})
            r.raise_for_status()
            return r.json()["content"][0]["text"]
    if url == "internal://openai":
        key = settings.OPENAI_API_KEY
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post("https://api.openai.com/v1/chat/completions",
                             headers={"Authorization": f"Bearer {key}"},
                             json={"model": settings.OPENAI_MODEL,
                                   "messages": messages, "max_tokens": 300})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
    if url in ("internal://mock-rag", "internal://mock-rag-hardened"):
        return mocktarget.handle_chat_rag(messages, session_id, settings,
                                          hardened="hardened" in url, tools=tools)
    if url.startswith(MOCK_PREFIX):
        return mocktarget.handle_chat(messages, session_id, settings,
                                      hardened="hardened" in url, tools=tools)

    headers = {"Content-Type": "application/json"}
    if target.get("auth_header"):
        headers["Authorization"] = target["auth_header"]
    payload = {"model": target.get("name", "target"), "messages": messages}
    if tools:
        payload["tools"] = tools
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(url, json=payload,
                         headers={**headers, "X-Session-Id": session_id})
        r.raise_for_status()
        data = r.json()
    # OpenAI-style, then Anthropic-style fallback
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        pass
    try:
        return data["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        pass
    return str(data)[:2000]
