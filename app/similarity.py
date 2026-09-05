"""Embedding-similarity layer. Corpus embeddings load from the store into an in-memory
numpy matrix; cosine via dot product on normalized vectors. Reloaded after corpus changes
and on /admin/reload-rules. With EMBEDDER=st, similarities are semantic; with the offline
embedder they're exact-char-n-gram — still catches verbatim/near-verbatim corpus attacks.

v2.4: `exclude_ids` lets batch mode mask a pattern and its whole mutation family so a
corpus attack is never scored against itself (the self-match artefact)."""
from __future__ import annotations

import numpy as np


class SimilarityEngine:
    def __init__(self, embedder, strong: float):
        self.embedder = embedder
        self.strong = strong
        self.ids: list[str] = []
        self.matrix: np.ndarray | None = None
        self._index: dict[str, int] = {}

    async def reload(self, store):
        rows = await store.all_embeddings()
        self.ids = [pid for pid, _ in rows]
        self._index = {pid: i for i, pid in enumerate(self.ids)}
        self.matrix = (np.asarray([v for _, v in rows], dtype=np.float64)
                       if rows else None)

    def score(self, text: str, exclude_ids: set[str] | None = None) -> dict:
        empty = {"score": 0.0, "top_pattern_id": None, "cos": 0.0, "strong": False,
                 "second_best": None, "excluded": 0}
        if self.matrix is None or len(self.ids) == 0 or not text.strip():
            return empty
        q = np.asarray(self.embedder.embed([text])[0], dtype=np.float64)
        sims = self.matrix @ q
        excluded = 0
        if exclude_ids:
            for pid in exclude_ids:
                i = self._index.get(pid)
                if i is not None:
                    sims[i] = -np.inf
                    excluded += 1
        if not np.isfinite(sims).any():
            return {**empty, "excluded": excluded}
        order = np.argsort(-sims)
        i = int(order[0])
        cos = float(sims[i])
        second = None
        if len(order) > 1 and np.isfinite(sims[order[1]]):
            j = int(order[1])
            second = {"id": self.ids[j], "cos": round(float(sims[j]), 4)}
        return {"score": round(max(0.0, cos) * 100.0, 1),
                "top_pattern_id": self.ids[i], "cos": round(cos, 4),
                "strong": cos >= self.strong, "second_best": second,
                "excluded": excluded}
