"""Append-only public evidence for verified Technocore actions."""

import json
import os
from pathlib import Path
from typing import Any

from .identity import verify_signature
from .protocol import decode_signature, message_payload

_SENSITIVE_KEY_PARTS = ("seed", "private", "password", "token", "credential")
_BASE_FIELDS = ("action", "did", "destination", "ts", "url")
_MESSAGE_FIELDS = ("nonce", "signature", "text", "seq")


def _check_no_sensitive_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
                raise ValueError(f"proof contains a sensitive field name: {key}")
            _check_no_sensitive_keys(child)
    elif isinstance(value, list):
        for child in value:
            _check_no_sensitive_keys(child)


def _validate_proof(proof: dict[str, Any]) -> None:
    if not isinstance(proof, dict):
        raise ValueError("proof must be a JSON object")
    _check_no_sensitive_keys(proof)
    missing = [field for field in _BASE_FIELDS if field not in proof]
    if proof.get("action") == "signed_message":
        missing.extend(field for field in _MESSAGE_FIELDS if field not in proof)
    if missing:
        raise ValueError(f"proof is missing required public fields: {', '.join(missing)}")


def append_proof(path: Path, proof: dict[str, Any]) -> None:
    _validate_proof(proof)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(proof, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    with path.open("ab") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def read_proofs(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        try:
            proof = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"malformed proof JSON on line {line_number}") from error
        _validate_proof(proof)
        records.append(proof)
    return records


def verify_message_proof(proof: dict[str, Any]) -> bool:
    _validate_proof(proof)
    if proof.get("action") != "signed_message":
        raise ValueError("proof is not a signed-message record")
    room = proof["destination"]
    nonce = proof["nonce"]
    text = proof["text"]
    did = proof["did"]
    signature = proof["signature"]
    if not all(isinstance(value, str) for value in (room, text, did, signature)):
        raise ValueError("signed-message proof contains invalid string fields")
    if isinstance(nonce, bool) or not isinstance(nonce, int):
        raise ValueError("signed-message proof contains an invalid nonce")
    verify_signature(
        did,
        message_payload(room, nonce, text),
        decode_signature(signature),
    )
    return True

