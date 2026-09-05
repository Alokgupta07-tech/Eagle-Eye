"""Score fusion + confidence gating + decision bands (P2, P3)."""
from __future__ import annotations


def fuse(rules: float, similarity: float, obfuscation: float, judge: float | None,
         w: dict[str, float]) -> float:
    """Weighted fusion. Judge contributes only when invoked (uncertain band / response side)."""
    raw = w["rules"] * rules + w["similarity"] * similarity + w["obfuscation"] * obfuscation
    if judge is not None:
        raw += w["judge"] * judge
    return round(raw, 1)


def confidence(scores: dict, jury: dict | None) -> float:
    """0.5*coverage + 0.5*conviction — tracked SEPARATELY from score (P3)."""
    fired = sum([
        scores.get("rules", 0) > 0,
        scores.get("similarity", 0) > 0,
        scores.get("obfuscation", 0) > 0,
        jury is not None,
    ])
    coverage = fired / 4.0
    if jury is not None:
        conv = {"3-0": 1.0, "2-1": 0.7, "dissent": 0.3,
                "2-0": 0.8, "1-1": 0.4, "single": 0.5}.get(jury.get("agreement", "single"), 0.5)
    else:
        conv = min(1.0, max(scores.get("rules", 0), scores.get("similarity", 0)) / 100.0
                   + scores.get("obfuscation", 0) / 30.0)
    return round(max(0.0, min(1.0, 0.5 * coverage + 0.5 * conv)), 2)


def band_for(raw: float, conf: float, lo: float, hi: float, conf_min: float) -> tuple[float, str]:
    """P3: high score + low confidence can never BLOCK — capped into REVIEW.
    Returns the (possibly capped) effective score and the band."""
    if raw >= hi and conf < conf_min:
        raw = hi - 5.0
    if raw < lo:
        return raw, "ALLOW"
    if raw < hi:
        return raw, "REVIEW"
    return raw, "BLOCK"
