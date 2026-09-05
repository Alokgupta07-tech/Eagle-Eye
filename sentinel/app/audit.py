"""Plane 4 — sealed, hash-chained audit log facade (P6).
Append-only; records chain via sha256(prev_hash || canonical_json(payload)).
FP labels append NEW records — originals are never edited."""
from __future__ import annotations


class Audit:
    def __init__(self, store):
        self.store = store

    async def seal(self, payload: dict) -> int:
        return await self.store.audit_append(payload)

    async def verify(self, run_id: str | None = None) -> dict:
        return await self.store.audit_verify(run_id=run_id)
