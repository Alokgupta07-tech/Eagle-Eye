"""Embedding-similarity layer. Corpus embeddings load from Postgres into an in-memory
numpy matrix; cosine via dot product on normalized vectors. Reloaded after corpus changes
and on /admin/reload-rules. With EMBEDDER=st, similarities are semantic; with the offline
embedder they're exact-char-n-gram — still catches verbatim/near-verbatim corpus attacks."""
from __future__ import annotations

import base64
import numpy as np


class SimilarityEngine:
    def __init__(self, embedder, strong: float):
        self.embedder = embedder
        self.strong = strong
        self.ids: list[str] = []
        self.matrix: np.ndarray | None = None

    async def reload(self, store):
        rows = await store.all_embeddings()
        self.ids = [pid for pid, _ in rows]
        self.matrix = (np.asarray([v for _, v in rows], dtype=np.float64)
                       if rows else None)

    def score(self, text: str) -> dict:
        if self.matrix is None or len(self.ids) == 0 or not text.strip():
            return {"score": 0.0, "top_pattern_id": None, "cos": 0.0, "strong": False}
        q = np.asarray(self.embedder.embed([text])[0], dtype=np.float64)
        sims = self.matrix @ q
        i = int(np.argmax(sims))
        cos = float(sims[i])
        return {"score": round(max(0.0, cos) * 100.0, 1),
                "top_pattern_id": self.ids[i], "cos": round(cos, 4),
                "strong": cos >= self.strong}


def looks_encoded(tok: str) -> bool:
    if len(tok) >= 16 and len(tok) % 4 == 0:
        try:
            base64.b64decode(tok, validate=True)
            return True
        except Exception:  # noqa: BLE001
            return False
    return False
