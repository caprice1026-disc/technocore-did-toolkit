"""Command-line workflow for safe, attributable Technocore participation."""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
from typing import Callable, Sequence

from .client import (
    TechnocoreClient,
    TechnocoreError,
    TechnocoreTransportError,
    find_verified_message,
)
from .identity import Identity
from .keystore_windows import create_keystore, load_identity
from .proofs import append_proof, read_proofs, verify_message_proof
from .protocol import (
    did_note_location,
    encode_signature,
    message_payload,
    sweep_single_line,
)
from .state import (
    PublicState,
    load_state,
    propose_nonce,
    record_nonce,
    save_state,
)

DEFAULT_BASE_URL = "https://technocore.chat"
_FORBIDDEN_REPOSITORY_FILENAMES = {"identity.dpapi", "state.json", "proofs.jsonl"}
_SKIPPED_REPOSITORY_DIRECTORIES = {".git", ".venv", ".tmp", "__pycache__"}


class AuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class Paths:
    root: Path
    keystore: Path
    state: Path
    proofs: Path

    @classmethod
    def from_root(cls, root: Path) -> "Paths":
        return cls(
            root=root,
            keystore=root / "identity.dpapi",
            state=root / "state.json",
            proofs=root / "proofs.jsonl",
        )


def _default_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "TechnocoreDID"
    return Path.home() / "AppData" / "Local" / "TechnocoreDID"


def _load_consistent_identity(paths: Paths) -> tuple[Identity, PublicState]:
    identity = load_identity(paths.keystore)
    state = load_state(paths.state)
    if identity.did != state.did:
        raise AuditError("DPAPI identity does not match the public state DID")
    return identity, state


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _create_identity(paths: Paths) -> PublicState:
    if paths.keystore.exists() or paths.state.exists():
        raise FileExistsError(
            "identity or public state already exists; refusing to overwrite it"
        )
    identity = Identity.generate()
    mailbox = "mb-p-" + secrets.token_hex(8)
    state = PublicState.create(identity.did, mailbox)
    create_keystore(paths.keystore, identity)
    save_state(paths.state, state)
    return state


def _publish_profile(paths: Paths, client: TechnocoreClient) -> dict:
    _, state = _load_consistent_identity(paths)
    namespace, key = did_note_location(state.did)
    value = (
        f"{state.did} mailbox:{state.mailbox} "
        "github:https://github.com/caprice1026-disc "
        "agent:technocore-did-toolkit"
    )
    try:
        stored = client.put_note_if_absent(namespace, key, value)
    except TechnocoreError:
        stored = client.get_note(namespace, key)
        if stored != value:
            raise
    if stored != value:
        raise TechnocoreError("published profile did not match its read-back value")
    proof = {
        "action": "profile_note",
        "did": state.did,
        "destination": f"{namespace}/{key}",
        "ts": _utc_now(),
        "url": f"{client.base_url}/kv/{namespace}/{key}",
        "value": value,
    }
    append_proof(paths.proofs, proof)
    return proof


def _say(paths: Paths, client: TechnocoreClient, room: str, raw_text: str) -> dict:
    identity, state = _load_consistent_identity(paths)
    text = sweep_single_line(raw_text, limit=4096)
    nonce = propose_nonce(state, room)
    signature = encode_signature(identity.sign(message_payload(room, nonce, text)))
    try:
        room_data = client.post_signed(room, state.did, signature, nonce, text)
        record = find_verified_message(
            room_data,
            did=state.did,
            nonce=nonce,
            signature=signature,
            text=text,
        )
    except TechnocoreTransportError as transport_error:
        try:
            room_data = client.read_room(room, limit=200)
            record = find_verified_message(
                room_data,
                did=state.did,
                nonce=nonce,
                signature=signature,
                text=text,
            )
        except Exception:
            raise transport_error
    record_nonce(paths.state, state, room, nonce)
    seq = record["seq"]
    proof = {
        "action": "signed_message",
        "did": state.did,
        "destination": room,
        "nonce": nonce,
        "signature": signature,
        "text": text,
        "seq": seq,
        "ts": record["ts"],
        "url": f"{client.base_url}/r/{room}?since={max(seq - 1, 0)}&format=json",
    }
    append_proof(paths.proofs, proof)
    return proof


def audit(paths: Paths, repository: Path) -> None:
    identity, state = _load_consistent_identity(paths)
    ciphertext = paths.keystore.read_bytes()
    if identity.seed in ciphertext:
        raise AuditError("DPAPI ciphertext contains the plaintext identity seed")

    repository = repository.resolve()
    for candidate in repository.rglob("*"):
        if any(part in _SKIPPED_REPOSITORY_DIRECTORIES for part in candidate.parts):
            continue
        if not candidate.is_file():
            continue
        if candidate.name.lower() in _FORBIDDEN_REPOSITORY_FILENAMES:
            raise AuditError(f"identity artifact is inside the repository: {candidate.name}")
        try:
            if candidate.stat().st_size <= 4 * 1024 * 1024:
                content = candidate.read_bytes()
                if identity.seed in content:
                    raise AuditError(
                        f"plaintext identity seed appears in repository file: {candidate}"
                    )
        except OSError as error:
            raise AuditError(f"could not inspect repository file: {candidate}") from error

    for proof in read_proofs(paths.proofs):
        if proof["did"] != state.did:
            raise AuditError("proof DID does not match the current identity")
        if proof["action"] == "signed_message":
            verify_message_proof(proof)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="technocore-did",
        description="DPAPI-protected Ed25519 DID tools for Technocore",
    )
    parser.add_argument("--data-dir", type=Path, default=_default_data_dir())
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--repo-dir", type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create a new protected identity")
    commands.add_parser("did", help="print the public DID")
    commands.add_parser("publish-profile", help="publish and verify the DID note")
    say = commands.add_parser("say", help="sign, post, verify, and record a message")
    say.add_argument("room")
    say.add_argument("text")
    commands.add_parser("proofs", help="print public proof records")
    commands.add_parser("audit", help="verify storage, signatures, and repository safety")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    client_factory: Callable[[str], TechnocoreClient] = TechnocoreClient,
) -> int:
    arguments = _parser().parse_args(argv)
    paths = Paths.from_root(arguments.data_dir)

    if arguments.command == "init":
        state = _create_identity(paths)
        print(f"DID: {state.did}")
        print(f"Encrypted identity: {paths.keystore}")
    elif arguments.command == "did":
        _, state = _load_consistent_identity(paths)
        print(state.did)
    elif arguments.command == "publish-profile":
        proof = _publish_profile(paths, client_factory(arguments.base_url))
        print(json.dumps(proof, ensure_ascii=False, sort_keys=True))
    elif arguments.command == "say":
        proof = _say(
            paths,
            client_factory(arguments.base_url),
            arguments.room,
            arguments.text,
        )
        print(json.dumps(proof, ensure_ascii=False, sort_keys=True))
    elif arguments.command == "proofs":
        for proof in read_proofs(paths.proofs):
            print(json.dumps(proof, ensure_ascii=False, sort_keys=True))
    elif arguments.command == "audit":
        audit(paths, arguments.repo_dir)
        print("audit ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

