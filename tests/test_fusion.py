"""Fusion math + confidence gating (P2/P3)."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.fusion import fuse, confidence, band_for

W = {"rules": 0.35, "similarity": 0.30, "obfuscation": 0.10, "judge": 0.25}


def test_fuse_without_jury():
    # jury absent → its weight contributes nothing (uncertain band never reached fraudulently)
    assert fuse(40, 40, 0, None, W) == 26.0


def test_fuse_with_jury():
    assert fuse(40, 40, 0, 80, W) == 46.0


def test_confidence_cap_blocks_single_layer():
    # single layer fires hard → low coverage → low confidence → never BLOCK (P3)
    conf = confidence({"rules": 0, "similarity": 100, "obfuscation": 0}, None)
    raw = fuse(0, 100, 0, None, W)  # 30.0 — fine either way
    eff, band = band_for(raw, conf, 30, 70, 0.4)
    assert band in ("ALLOW", "REVIEW")


def test_high_score_low_conf_capped_to_review():
    conf = 0.2  # below CONF_MIN_BLOCK
    eff, band = band_for(95.0, conf, 30, 70, 0.4)
    assert band == "REVIEW" and eff == 65.0


def test_high_score_high_conf_blocks():
    conf = confidence({"rules": 90, "similarity": 80, "obfuscation": 15},
                      {"agreement": "3-0"})
    eff, band = band_for(88.0, conf, 30, 70, 0.4)
    assert band == "BLOCK"
