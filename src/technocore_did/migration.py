"""Offline, authenticated identity migration using standard compact JWE.

RFC 7516/7518 encryption is delegated to JWCrypto. Private key material uses
PKCS#8 DER inside the authenticated payload, never as a plaintext file.
"""

import base64
import binascii
import json
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto import jwa, jwe, jwk

from .identity import Identity, public_key_from_did
from .keystore_windows import create_keystore, unprotect_seed
from .proofs import _validate_proof, verify_message_proof
from .protocol import did_note_location, sweep_single_line
from .state import PublicState, _state_bytes, _state_from_dict, save_state

FORMAT = "technocore-did-migration"
VERSION = 1
ALGORITHM = "PBES2-HS512+A256KW"
ENCRYPTION = "A256GCM"
ITERATIONS = 600_000
MAX_ITERATIONS = 1_000_000
MAX_BACKUP_BYTES = 6 * 1024 * 1024
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_PROOFS_BYTES = 3 * 1024 * 1024
MAX_PROOFS = 10_000
_ALLOWED_ALGORITHMS = [ALGORITHM, ENCRYPTION]
_STATE_FIELDS = {"version", "did", "mailbox", "created_at", "last_nonce_by_room"}
_BASE_PROOF_FIELDS = {"action", "did", "destination", "ts", "url"}
_FILES = {"identity.dpapi": 4096, "state.json": 64 * 1024,
          "proofs.jsonl": MAX_PROOFS_BYTES}

# JWCrypto exposes this documented application setting. Our compact-only
# parser checks one recipient and a bounded p2c before invoking the library.
jwa.default_max_pbkdf2_iterations = MAX_ITERATIONS


class MigrationError(ValueError):
    """A safe-to-display migration failure, without secret input values."""


@dataclass(repr=False)
class Snapshot:
    identity: Identity
    state: PublicState
    proofs: list[dict]


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise MigrationError("duplicate JSON field")
        result[key] = value
    return result


def _json(data: bytes) -> object:
    try:
        return json.loads(data, object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise MigrationError("invalid migration JSON") from None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str, limit: int) -> bytes:
    if (not isinstance(value, str) or len(value) > (limit * 4 // 3 + 4)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        raise MigrationError("invalid Base64URL field")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4),
                                   altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise MigrationError("invalid Base64URL field") from None
    if len(decoded) > limit or _b64(decoded) != value:
        raise MigrationError("noncanonical or oversized Base64URL field")
    return decoded


def _read_bounded(path: Path, limit: int, *, optional: bool = False) -> bytes:
    if optional and not path.exists():
        return b""
    with path.open("rb") as stream:
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise MigrationError("migration input exceeds its size limit")
    return result


def validate_passphrase(passphrase: str) -> None:
    try:
        valid = (isinstance(passphrase, str) and len(passphrase) >= 20
                 and len(passphrase.encode("utf-8")) <= 1024 and "\0" not in passphrase)
    except UnicodeError:
        valid = False
    if not valid:
        raise MigrationError("use a passphrase of at least 20 characters (max 1024 UTF-8 bytes)")


def _validate_snapshot(snapshot: Snapshot) -> None:
    state = snapshot.state
    _state(asdict(state))
    if len(_state_bytes(state)) > _FILES["state.json"]:
        raise MigrationError("public state exceeds its restored size limit")
    if snapshot.identity.did != state.did:
        raise MigrationError("private key does not match the state DID")
    if len(snapshot.proofs) > MAX_PROOFS:
        raise MigrationError("too many proof records")
    try:
        created = datetime.fromisoformat(state.created_at.replace("Z", "+00:00"))
        if created.tzinfo is None:
            raise ValueError()
        for proof in snapshot.proofs:
            _validate_proof(proof)
            if proof["did"] != state.did:
                raise ValueError()
            for field in ("destination", "ts", "url"):
                if not isinstance(proof[field], str) or len(proof[field]) > 2048:
                    raise ValueError()
            action = proof["action"]
            if action == "signed_message":
                if set(proof) != _BASE_PROOF_FIELDS | {"nonce", "signature", "text", "seq"}:
                    raise ValueError()
                if type(proof["seq"]) is not int or proof["seq"] < 1:
                    raise ValueError()
                if sweep_single_line(proof["text"], limit=4096) != proof["text"]:
                    raise ValueError()
                verify_message_proof(proof)
                if state.last_nonce_by_room.get(proof["destination"], 0) < proof["nonce"]:
                    raise ValueError()
            elif action == "profile_note":
                namespace, key = did_note_location(state.did)
                if (set(proof) != _BASE_PROOF_FIELDS | {"value"}
                        or proof["destination"] != f"{namespace}/{key}"
                        or not isinstance(proof["value"], str)
                        or len(proof["value"]) > 4096
                        or not proof["value"].startswith(state.did + " mailbox:" + state.mailbox + " ")):
                    raise ValueError()
            else:
                raise ValueError()
    except Exception:  # noqa: BLE001 -- expose only the safe public validation error
        raise MigrationError("state or proofs are inconsistent with the identity") from None
    _proof_bytes(snapshot.proofs)


def _proof_bytes(proofs: list[dict]) -> bytes:
    # Match append_proof's UTF-8 representation and enforce the size that will
    # actually be written on import, before creating any destination files.
    data = b"".join((json.dumps(proof, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
                    for proof in proofs)
    if len(data) > MAX_PROOFS_BYTES:
        raise MigrationError("proofs exceed their restored size limit")
    return data


def _proof_records(values: list[object]) -> list[dict]:
    if len(values) > MAX_PROOFS:
        raise MigrationError("too many proof records")
    records: list[dict] = []
    for value in values:
        if not isinstance(value, dict):
            raise MigrationError("proof records must be JSON objects")
        records.append(value)
    return records


def _state(value: object) -> PublicState:
    try:
        if (not isinstance(value, dict) or set(value) != _STATE_FIELDS
                or type(value["version"]) is not int
                or not isinstance(value["last_nonce_by_room"], dict)
                or len(value["last_nonce_by_room"]) > 1000
                or any(type(nonce) is not int for nonce in value["last_nonce_by_room"].values())):
            raise TypeError()
        return _state_from_dict(value)
    except (ValueError, TypeError, KeyError):
        raise MigrationError("invalid public state") from None


def _encode_payload(snapshot: Snapshot) -> bytes:
    _validate_snapshot(snapshot)
    key = Ed25519PrivateKey.from_private_bytes(snapshot.identity.seed)
    pkcs8 = key.private_bytes(serialization.Encoding.DER,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    payload = _json_bytes({"format": FORMAT, "version": VERSION, "pkcs8": _b64(pkcs8),
                           "state": asdict(snapshot.state), "proofs": snapshot.proofs})
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise MigrationError("migration payload exceeds its size limit")
    return payload


def _decode_payload(payload: bytes) -> Snapshot:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise MigrationError("migration payload exceeds its size limit")
    value = _json(payload)
    if (not isinstance(value, dict)
            or set(value) != {"format", "version", "pkcs8", "state", "proofs"}
            or value["format"] != FORMAT or type(value["version"]) is not int
            or value["version"] != VERSION or not isinstance(value["proofs"], list)):
        raise MigrationError("unsupported migration payload")
    try:
        key = serialization.load_der_private_key(_unb64(value["pkcs8"], 128), None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError()
        seed = key.private_bytes(serialization.Encoding.Raw,
                                 serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    except (ValueError, TypeError):
        raise MigrationError("invalid Ed25519 PKCS#8 key") from None
    snapshot = Snapshot(Identity.from_seed(seed), _state(value["state"]),
                        _proof_records(value["proofs"]))
    _validate_snapshot(snapshot)
    return snapshot


def _validate_envelope(data: bytes) -> str:
    if not data or len(data) > MAX_BACKUP_BYTES:
        raise MigrationError("empty or oversized migration file")
    try:
        compact = data.decode("ascii")
    except UnicodeError:
        raise MigrationError("migration file must be compact JWE") from None
    parts = compact.split(".")
    if len(parts) != 5:
        raise MigrationError("migration file must be compact JWE")
    header = _json(_unb64(parts[0], 1024))
    if (not isinstance(header, dict)
            or set(header) != {"alg", "enc", "typ", "v", "p2c", "p2s"}
            or header["alg"] != ALGORITHM or header["enc"] != ENCRYPTION
            or header["typ"] != FORMAT or type(header["v"]) is not int
            or header["v"] != VERSION or type(header["p2c"]) is not int
            or not ITERATIONS <= header["p2c"] <= MAX_ITERATIONS
            or len(_unb64(header["p2s"], 32)) != 32):
        raise MigrationError("unsupported JWE header or KDF parameters")
    if (len(_unb64(parts[1], 40)) != 40 or len(_unb64(parts[2], 12)) != 12
            or len(_unb64(parts[4], 16)) != 16):
        raise MigrationError("invalid JWE field length")
    _unb64(parts[3], MAX_PAYLOAD_BYTES)
    return compact


def encrypt_snapshot(snapshot: Snapshot, passphrase: str) -> bytes:
    validate_passphrase(passphrase)
    header = {"alg": ALGORITHM, "enc": ENCRYPTION, "typ": FORMAT, "v": VERSION,
              "p2c": ITERATIONS, "p2s": _b64(secrets.token_bytes(32))}
    token = jwe.JWE(_encode_payload(snapshot), protected=header,
                    algs=_ALLOWED_ALGORITHMS, recipient=jwk.JWK.from_password(passphrase))
    data = token.serialize(compact=True).encode("ascii")
    _validate_envelope(data)
    # Validate the actual encrypted artifact before publishing it.
    decrypt_snapshot(data, passphrase, expected_did=snapshot.state.did)
    return data


def decrypt_snapshot(data: bytes, passphrase: str, *, expected_did: str) -> Snapshot:
    validate_passphrase(passphrase)
    if not isinstance(expected_did, str):
        raise MigrationError("expected DID must be an Ed25519 did:key")
    try:
        public_key_from_did(expected_did)
    except ValueError:
        raise MigrationError("expected DID must be an Ed25519 did:key") from None
    compact = _validate_envelope(data)
    token = jwe.JWE(algs=_ALLOWED_ALGORITHMS)
    try:
        token.deserialize(compact, key=jwk.JWK.from_password(passphrase))
    except Exception:  # noqa: BLE001 -- library errors may contain secret-bearing input
        raise MigrationError("backup authentication failed (wrong passphrase or damaged file)") from None
    snapshot = _decode_payload(token.payload)
    if snapshot.state.did != expected_did:
        raise MigrationError("backup DID does not match the expected DID")
    return snapshot


def _source_files(root: Path) -> dict[str, bytes]:
    return {name: _read_bounded(root / name, limit, optional=name == "proofs.jsonl")
            for name, limit in _FILES.items()}


def _snapshot(files: dict[str, bytes]) -> Snapshot:
    lines = files["proofs.jsonl"].splitlines()
    if len(lines) > MAX_PROOFS:
        raise MigrationError("too many proof records")
    records = _proof_records([_json(line) for line in lines])
    return Snapshot(Identity.from_seed(unprotect_seed(files["identity.dpapi"])),
                    _state(_json(files["state.json"])), records)


def _exists(path: Path) -> bool:
    return os.path.lexists(path)


def _publish_file(temporary: Path, destination: Path) -> None:
    # Windows rename refuses any existing target. POSIX rename replaces files,
    # so use an exclusive hard link there instead.
    if os.name == "nt":
        os.rename(temporary, destination)
    else:
        os.link(temporary, destination)
        temporary.unlink()


def _write_descriptor(descriptor: int, data: bytes) -> None:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _write_new(path: Path, data: bytes) -> None:
    _write_descriptor(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), data)


def export_backup(root: Path, output: Path, passphrase: str, *, repository: Path,
                  source_stopped: bool) -> str:
    if not source_stopped:
        raise MigrationError("stop all source writers, then acknowledge --source-stopped")
    root, output, repository = root.resolve(), output.absolute(), repository.resolve()
    resolved_output = output.resolve()
    if (resolved_output.is_relative_to(root) or resolved_output.is_relative_to(repository)
            or any((parent / ".git").exists() for parent in resolved_output.parents)):
        raise MigrationError("backup must be outside the data directory, --repo-dir and detected .git checkouts")
    if _exists(output):
        raise FileExistsError("backup destination already exists")
    if not output.parent.is_dir():
        raise MigrationError("backup parent directory must already exist")
    files = _source_files(root)
    snapshot = _snapshot(files)
    encrypted = encrypt_snapshot(snapshot, passphrase)
    if files != _source_files(root):
        raise MigrationError("source changed during export; stop writers and retry")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp",
                                                dir=output.parent)
    temporary = Path(temporary_name)
    try:
        _write_descriptor(descriptor, encrypted)
        _publish_file(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return snapshot.state.did


def _publish_directory(staging: Path, destination: Path) -> None:
    if _exists(destination):
        raise FileExistsError("import destination already exists")
    os.rename(staging, destination)


def import_backup(backup: Path, destination: Path, passphrase: str, *, expected_did: str,
                  repository: Path | None = None) -> str:
    destination = destination.absolute()
    if _exists(destination):
        raise FileExistsError("import requires an absent data directory; existing data is never overwritten")
    if os.name != "nt":
        raise MigrationError("identity import requires Windows DPAPI and Windows exclusive rename")
    resolved = destination.resolve()
    if ((repository is not None and resolved.is_relative_to(repository.resolve()))
            or any((parent / ".git").exists() for parent in resolved.parents)):
        raise MigrationError("import data directory must be outside --repo-dir and detected .git checkouts")
    snapshot = decrypt_snapshot(_read_bounded(backup, MAX_BACKUP_BYTES), passphrase,
                                expected_did=expected_did)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.import-",
                                   dir=destination.parent))
    try:
        create_keystore(staging / "identity.dpapi", snapshot.identity)
        save_state(staging / "state.json", snapshot.state)
        proof_data = _proof_bytes(snapshot.proofs)
        _write_new(staging / "proofs.jsonl", proof_data)
        # Read back the new DPAPI store, not merely the exported signature.
        restored = _snapshot(_source_files(staging))
        _validate_snapshot(restored)
        if restored.identity.seed != snapshot.identity.seed:
            raise MigrationError("destination DPAPI round-trip changed the key")
        challenge = secrets.token_bytes(32)
        public_key_from_did(expected_did).verify(restored.identity.sign(challenge), challenge)
        _publish_directory(staging, destination)
    finally:
        # Only our three known staging files; never recursively delete a path.
        if staging.exists():
            for name in _FILES:
                (staging / name).unlink(missing_ok=True)
            staging.rmdir()
    return snapshot.state.did
