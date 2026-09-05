"""Canonical Technocore text, signature, nonce, and note rules."""

import base64
import binascii
import hashlib
import re
import time
import unicodedata

_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_REPLACED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
_MAX_NONCE = 9_999_999_999_999_999_999


def sweep_single_line(text: str, *, limit: int) -> str:
    """Apply Technocore's documented single-line storage transformation."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    swept = "".join(
        " " if unicodedata.category(character) in _REPLACED_CATEGORIES else character
        for character in text
    ).strip()
    if not swept:
        raise ValueError("text is empty after the single-line sweep")
    if len(swept) > limit:
        raise ValueError(f"text exceeds the {limit}-character limit")
    return swept


def validate_name(name: str) -> str:
    if not isinstance(name, str) or _NAME_PATTERN.fullmatch(name) is None:
        raise ValueError("name must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return name


def _validate_nonce(nonce: int) -> int:
    if isinstance(nonce, bool) or not isinstance(nonce, int):
        raise ValueError("nonce must be an integer of 1 to 19 digits")
    if nonce < 1 or nonce > _MAX_NONCE:
        raise ValueError("nonce must contain 1 to 19 digits")
    return nonce


def message_payload(room: str, nonce: int, text: str) -> bytes:
    validate_name(room)
    _validate_nonce(nonce)
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return f"{room}|{nonce}|{text}".encode("utf-8")


def encode_signature(signature: bytes) -> str:
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must be exactly 64 bytes")
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def decode_signature(encoded: str) -> bytes:
    if not isinstance(encoded, str) or len(encoded) != 86:
        raise ValueError("signature must be an 86-character canonical Base64URL string")
    try:
        signature = base64.b64decode(encoded + "==", altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError) as error:
        raise ValueError("signature must use canonical Base64URL") from error
    if len(signature) != 64 or encode_signature(signature) != encoded:
        raise ValueError("signature must use canonical Base64URL")
    return signature


def next_nonce(previous: int | None, now_ms: int | None = None) -> int:
    if previous is not None:
        _validate_nonce(previous)
    current = int(time.time() * 1000) if now_ms is None else now_ms
    if isinstance(current, bool) or not isinstance(current, int):
        raise ValueError("current time must be integer milliseconds")
    candidate = max(current, (previous or 0) + 1)
    return _validate_nonce(candidate)


def did_note_location(did: str) -> tuple[str, str]:
    if not isinstance(did, str) or not did.startswith("did:key:"):
        raise ValueError("DID must be a did:key string")
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return f"did-{fingerprint[:2]}", fingerprint[2:]

