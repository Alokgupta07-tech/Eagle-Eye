"""Step 2: Shannon-entropy generic secret detection (no known prefix required)."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.pipeline import leakage_spans, _entropy

HIGH_ENTROPY = "xT9$kQ2#vL8!zR4&mN7@pW6*yJ3^bF5"   # random-looking, no sk-/AKIA prefix


def test_high_entropy_token_caught():
    text = f"Sure, the rotating session material is {HIGH_ENTROPY} — handle with care."
    spans = leakage_spans(text, None, entropy_threshold=4.0)
    kinds = [s["type"] for s in spans]
    assert "high_entropy_secret" in kinds
    span = next(s for s in spans if s["type"] == "high_entropy_secret")
    assert text[span["start"]:span["end"]] == HIGH_ENTROPY


def test_low_entropy_long_token_not_flagged():
    text = "border color: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and zzzzzzzzzzzzzzzzzzzzzzzzzz"
    assert not any(s["type"] == "high_entropy_secret"
                   for s in leakage_spans(text, None, entropy_threshold=4.0))


def test_benign_text_quiet():
    spans = leakage_spans("Your refund policy: 30 days, prorated monthly after that.",
                          "CANARY-9F2A41C8", entropy_threshold=4.0)
    assert spans == []


def test_explicit_prefix_wins_over_entropy_label():
    tok = "SK-LIVE-Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0L"
    spans = leakage_spans(f"key={tok}", None, entropy_threshold=4.0)
    assert any(s["type"] == "api_key" for s in spans)
    assert not any(s["type"] == "high_entropy_secret" for s in spans)


def test_threshold_is_tunable():
    text = f"material: {HIGH_ENTROPY}"
    assert not any(s["type"] == "high_entropy_secret"
                   for s in leakage_spans(text, None, entropy_threshold=6.0))


def test_entropy_function_sanity():
    assert _entropy("aaaa") == 0.0
    assert _entropy("ab") == 1.0
    assert _entropy(HIGH_ENTROPY) > 4.0
