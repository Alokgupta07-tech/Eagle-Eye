"""Text normalization + obfuscation decode chain + canonical hashing helpers."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import string
import unicodedata

# --- small homoglyph folding table (common Cyrillic/Greek lookalikes) ---
HOMOGLYPHS = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0501": "d", "\u04bb": "h", "\u03bd": "v", "\u03c1": "p", "\u03c4": "t",
    "\u043a": "k", "\u043c": "m", "\u0442": "t", "\u043d": "h", "\u0410": "A",
    "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
})

LEETSPEAK = str.maketrans({
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o",
    "5": "s", "$": "s", "7": "t", "8": "b", "+": "t", "9": "g",
})

_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
_HIDDEN_MD = re.compile(r"<!--(.*?)-->|```[a-z]*\n?(.*?)```|\[\^\d+\]:\s*([^\n]+)", re.S)


def strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH.sub("", text)


def reveal_hidden_markup(text: str) -> str:
    """Pull instruction text out of HTML comments, code fences and footnotes so the
    rule/similarity layers see it inline (v2.4 step 9, markdown_hidden_instruction)."""
    found = [next(g for g in m.groups() if g) for m in _HIDDEN_MD.finditer(text)]
    return " ".join(f.strip() for f in found if f and f.strip())


_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
_PRINTABLE = set(string.printable)


def _mostly_printable(s: str) -> bool:
    if not s:
        return False
    good = sum(1 for c in s if c in _PRINTABLE or c.isspace())
    return good / len(s) >= 0.9


def _try_token_decodes(text: str) -> tuple[str, list[str]]:
    """Replace any base64/hex token that strictly decodes to printable text."""
    notes: list[str] = []
    tokens = text.split(" ")
    out: list[str] = []
    for tok in tokens:
        replaced = False
        if _B64_RE.fullmatch(tok) and len(tok) % 4 == 0:
            try:
                dec = base64.b64decode(tok, validate=True).decode("utf-8", "strict")
                if _mostly_printable(dec):
                    out.append(dec)
                    notes.append(f"base64:{tok[:18]}…")
                    replaced = True
            except (binascii.Error, UnicodeDecodeError, ValueError):
                pass
        if not replaced and _HEX_RE.fullmatch(tok) and len(tok.replace("0x", "")) % 2 == 0:
            try:
                dec = bytes.fromhex(tok.replace("0x", "")).decode("utf-8", "strict")
                if _mostly_printable(dec):
                    out.append(dec)
                    notes.append(f"hex:{tok[:18]}…")
                    replaced = True
            except (ValueError, UnicodeDecodeError):
                pass
        if not replaced:
            out.append(tok)
    return " ".join(out), notes


def decode_chain(text: str) -> dict:
    """Full obfuscation pipeline. Token-level base64/hex decode happens BEFORE any
    leetspeak fold (folding digits would corrupt encoded blobs). Returns variants."""
    variants: dict[str, str] = {"original": text}
    transforms: list[str] = []

    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        transforms.append("nfkc")
        variants["nfkc"] = nfkc
    zw = strip_zero_width(nfkc)
    if zw != nfkc:
        transforms.append("zero_width")
        variants["zero_width"] = zw
        nfkc = zw
    hidden = reveal_hidden_markup(nfkc)
    if hidden and hidden != nfkc.strip():
        transforms.append("hidden_markup")
        variants["hidden_markup"] = hidden

    base = nfkc
    for _ in range(2):  # nested encodings: decode up to two rounds
        decoded, notes = _try_token_decodes(base)
        if decoded == base:
            break
        transforms.extend(notes)
        variants["decoded"] = decoded
        base = decoded

    homo = base.translate(HOMOGLYPHS)
    if homo != base:
        transforms.append("homoglyph")
        variants["homoglyph"] = homo

    leet = homo.translate(LEETSPEAK)
    if leet != homo:
        transforms.append("leetspeak")
        variants["leetspeak"] = leet

    return {"variants": variants, "transforms": transforms}


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def payload_id(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()
