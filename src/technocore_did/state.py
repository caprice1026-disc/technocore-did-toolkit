"""Atomic persistence for public identity metadata and room nonces."""

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets

from .protocol import next_nonce, validate_name


@dataclass(frozen=True)
class PublicState:
    version: int
    did: str
    mailbox: str
    created_at: str
    last_nonce_by_room: dict[str, int]

    @classmethod
    def create(cls, did: str, mailbox: str) -> "PublicState":
        if not isinstance(did, str) or not did:
            raise ValueError("DID must be a non-empty string")
        validate_name(mailbox)
        return cls(
            version=1,
            did=did,
            mailbox=mailbox,
            created_at=datetime.now(timezone.utc).isoformat(),
            last_nonce_by_room={},
        )


def _state_from_dict(data: object) -> PublicState:
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("unsupported or malformed public-state version")
    did = data.get("did")
    mailbox = data.get("mailbox")
    created_at = data.get("created_at")
    nonces = data.get("last_nonce_by_room")
    if not isinstance(did, str) or not did:
        raise ValueError("public state has an invalid DID")
    validate_name(mailbox)
    if not isinstance(created_at, str) or not created_at:
        raise ValueError("public state has an invalid creation time")
    if not isinstance(nonces, dict):
        raise ValueError("public state has an invalid nonce map")
    checked_nonces: dict[str, int] = {}
    for room, nonce in nonces.items():
        validate_name(room)
        if next_nonce(nonce - 1, nonce) != nonce:
            raise ValueError("public state has an invalid nonce")
        checked_nonces[room] = nonce
    return PublicState(1, did, mailbox, created_at, checked_nonces)


def load_state(path: Path) -> PublicState:
    data = json.loads(path.read_text(encoding="utf-8"))
    return _state_from_dict(data)


def save_state(path: Path, state: PublicState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    encoded = (
        json.dumps(asdict(state), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def propose_nonce(
    state: PublicState, room: str, now_ms: int | None = None
) -> int:
    validate_name(room)
    return next_nonce(state.last_nonce_by_room.get(room), now_ms)


def record_nonce(
    path: Path, state: PublicState, room: str, nonce: int
) -> PublicState:
    validate_name(room)
    previous = state.last_nonce_by_room.get(room)
    if next_nonce(previous, nonce) != nonce:
        raise ValueError("nonce must be greater than the recorded room nonce")
    updated_nonces = dict(state.last_nonce_by_room)
    updated_nonces[room] = nonce
    updated = replace(state, last_nonce_by_room=updated_nonces)
    save_state(path, updated)
    return updated

