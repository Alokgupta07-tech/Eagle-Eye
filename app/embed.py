"""Embedding service. Primary: sentence-transformers all-MiniLM-L6-v2.
Fallback (mandatory): deterministic offline char-3-gram hash embeddings.
Both produce L2-normalized 384-d vectors so cosine == dot product."""
from __future__ import annotations

import hashlib
import numpy as np

DIM = 384


class OfflineEmbedder:
    mode = "offline"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]

    @staticmethod
    def _one(text: str) -> list[float]:
        vec = np.zeros(DIM, dtype=np.float64)
        norm = " ".join(text.lower().split())
        grams: list[str] = []
        for word in norm.split(" "):
            w = f" {word} "
            grams.extend(w[i:i + 3] for i in range(max(1, len(w) - 2)))
        for g in grams:
            h = hashlib.blake2b(g.encode("utf-8"), digest_size=9).digest()
            idx = int.from_bytes(h[:8], "big") % DIM
            sign = 1.0 if h[8] % 2 == 0 else -1.0
            vec[idx] += sign
        n = np.linalg.norm(vec)
        if n > 0:
            vec /= n
        return vec.tolist()


class STEmbedder:
    mode = "st-384"

    def __init__(self):
        from sentence_transformers import SentenceTransformer  # type: ignore
        self._m = SentenceTransformer("all-MiniLM-L6-v2")

    def embed(self, texts: list[str]) -> list[list[float]]:
        arr = self._m.encode(texts, normalize_embeddings=True)
        return [list(map(float, v))[:DIM] for v in arr]


def build_embedder(mode: str):
    """auto → try sentence-transformers, ANY failure → offline. Never raises."""
    if mode in ("auto", "st"):
        try:
            return STEmbedder()
        except Exception as exc:  # noqa: BLE001 - deliberate broad fallback
            if mode == "st":
                print(f"[embed] sentence-transformers unavailable ({exc}); using offline")
    return OfflineEmbedder()


def cosine(a: list[float], b: list[float]) -> float:
    va, vb = np.asarray(a, dtype=np.float64), np.asarray(b, dtype=np.float64)
    denom = float(np.linalg.norm(va) * np.linalg.norm(vb))
    return float(np.dot(va, vb) / denom) if denom else 0.0
