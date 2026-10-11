import hmac
import json
import os
import secrets
import sys
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jwcrypto import jwe, jwk

from technocore_did import migration as m
from technocore_did.identity import Identity, verify_signature
from technocore_did.keystore_windows import create_keystore, load_identity
from technocore_did.protocol import encode_signature, message_payload
from technocore_did.state import PublicState, load_state, propose_nonce, save_state


def require_secret_equal(actual, expected):
    if not hmac.compare_digest(actual, expected):
        pytest.fail("private material mismatch", pytrace=False)


@pytest.fixture
def sample():
    identity = Identity.generate()
    nonce = 1_900_000_000_000
    state = replace(PublicState.create(identity.did, "mb-p-migration-test"),
                    last_nonce_by_room={"lobby": nonce})
    proof = {"action": "signed_message", "did": identity.did, "destination": "lobby",
             "ts": "2026-10-11T00:00:00Z", "url": "https://example.test/r/lobby",
             "nonce": nonce, "text": "migration test", "seq": 1,
             "signature": encode_signature(identity.sign(message_payload("lobby", nonce, "migration test")))}
    return m.Snapshot(identity, state, [proof]), secrets.token_urlsafe(32)


@pytest.fixture
def encrypted(sample):
    snapshot, password = sample
    return snapshot, password, m.encrypt_snapshot(snapshot, password)


@pytest.fixture
def protectors(monkeypatch):
    # Distinct random AEAD keys model two independent OS protection contexts.
    # This is a unit model, not a test of Windows account/PC portability.
    keys = {name: AESGCM.generate_key(bit_length=256) for name in ("source", "target")}
    context = ["source"]

    def create(path, identity):
        path.parent.mkdir(parents=True, exist_ok=True)
        nonce = secrets.token_bytes(12)
        blob = nonce + AESGCM(keys[context[0]]).encrypt(nonce, identity.seed, b"test store")
        m._write_new(path, blob)

    def unprotect(blob):
        return AESGCM(keys[context[0]]).decrypt(blob[:12], blob[12:], b"test store")

    monkeypatch.setattr(m, "create_keystore", create)
    monkeypatch.setattr(m, "unprotect_seed", unprotect)
    return context, create, unprotect


def write_source(root, snapshot, create):
    root.mkdir()
    create(root / "identity.dpapi", snapshot.identity)
    save_state(root / "state.json", snapshot.state)
    (root / "proofs.jsonl").write_bytes(m._proof_bytes(snapshot.proofs))


def test_authenticated_pkcs8_round_trip_and_new_signature(encrypted):
    snapshot, password, data = encrypted
    restored = m.decrypt_snapshot(data, password, expected_did=snapshot.state.did)
    require_secret_equal(restored.identity.seed, snapshot.identity.seed)
    assert restored.state == snapshot.state
    assert restored.proofs == snapshot.proofs
    challenge = secrets.token_bytes(32)
    verify_signature(snapshot.state.did, challenge, restored.identity.sign(challenge))
    token = jwe.JWE(algs=[m.ALGORITHM, m.ENCRYPTION])
    token.deserialize(data.decode("ascii"), key=jwk.JWK.from_password(password))
    key = serialization.load_der_private_key(m._unb64(json.loads(token.payload)["pkcs8"], 128), None)
    require_secret_equal(key.private_bytes_raw(), snapshot.identity.seed)
    assert not hmac.compare_digest(data, m.encrypt_snapshot(snapshot, password))
    if any(fragment in data for fragment in (snapshot.identity.seed, snapshot.identity.seed.hex().encode(), password.encode())):
        pytest.fail("secret material appeared in backup output", pytrace=False)


def test_wrong_passphrase_and_did_fail(encrypted):
    snapshot, password, data = encrypted
    with pytest.raises(m.MigrationError, match="authentication failed"):
        m.decrypt_snapshot(data, secrets.token_urlsafe(32), expected_did=snapshot.state.did)
    with pytest.raises(m.MigrationError, match="expected DID"):
        m.decrypt_snapshot(data, password, expected_did=Identity.generate().did)


@pytest.mark.parametrize("part", range(5))
def test_each_jwe_component_tamper_is_rejected(encrypted, part):
    snapshot, password, data = encrypted
    parts = data.decode("ascii").split(".")
    raw = bytearray(m._unb64(parts[part], m.MAX_BACKUP_BYTES))
    raw[-1] ^= 1
    parts[part] = m._b64(raw)
    with pytest.raises(m.MigrationError):
        m.decrypt_snapshot(".".join(parts).encode(), password, expected_did=snapshot.state.did)


@pytest.mark.parametrize("data", [b"", b"not-jwe", b"a.b.c.d.e", b"\xff", b"{}.{}", b"a." * 6])
def test_malformed_and_truncated_files_fail(sample, data):
    snapshot, password = sample
    with pytest.raises(m.MigrationError):
        m.decrypt_snapshot(data, password, expected_did=snapshot.state.did)


@pytest.mark.parametrize("change", [{"p2c": True}, {"p2c": 0}, {"p2c": 10**12},
    {"v": 2}, {"alg": "dir"}, {"enc": "A128GCM"}, {"zip": "DEF"}, {"p2s": "short"}])
def test_parameters_rejected_before_library_decrypt(encrypted, change, monkeypatch):
    snapshot, password, data = encrypted
    parts = data.decode().split(".")
    header = json.loads(m._unb64(parts[0], 1024))
    header.update(change)
    parts[0] = m._b64(m._json_bytes(header))
    monkeypatch.setattr(m.jwe.JWE, "deserialize", lambda *a, **k: pytest.fail("decrypt must not run"))
    with pytest.raises(m.MigrationError):
        m.decrypt_snapshot(".".join(parts).encode(), password, expected_did=snapshot.state.did)


def test_size_and_duplicate_fields_rejected(encrypted, monkeypatch):
    snapshot, password, data = encrypted
    monkeypatch.setattr(m, "MAX_BACKUP_BYTES", len(data) - 1)
    with pytest.raises(m.MigrationError, match="oversized"):
        m.decrypt_snapshot(data, password, expected_did=snapshot.state.did)
    with pytest.raises(m.MigrationError):
        m._json(b'{"version":1,"version":2}')


@pytest.mark.parametrize("password", ["", "too short", "x" * 1025, "x" * 30 + "\0"])
def test_weak_or_invalid_passphrase_is_rejected(sample, password):
    with pytest.raises(m.MigrationError, match="passphrase"):
        m.encrypt_snapshot(sample[0], password)


def test_two_protection_contexts_and_nonce_continuation(tmp_path, sample, protectors):
    snapshot, password = sample
    context, create, unprotect = protectors
    source, target, backup = tmp_path / "source", tmp_path / "target", tmp_path / "backup.tcdid.jwe"
    write_source(source, snapshot, create)
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    m.export_backup(source, backup, password, repository=tmp_path / "repo", source_stopped=True)
    context[0] = "target"
    with pytest.raises(InvalidTag):
        unprotect(before["identity.dpapi"])
    assert m.import_backup(backup, target, password, expected_did=snapshot.state.did) == snapshot.state.did
    require_secret_equal(unprotect((target / "identity.dpapi").read_bytes()), snapshot.identity.seed)
    assert (target / "identity.dpapi").read_bytes() != before["identity.dpapi"]
    assert load_state(target / "state.json") == snapshot.state
    assert propose_nonce(load_state(target / "state.json"), "lobby", now_ms=1) == snapshot.state.last_nonce_by_room["lobby"] + 1
    assert {p.name: p.read_bytes() for p in source.iterdir()} == before


@pytest.mark.skipif(sys.platform != "win32", reason="temporary Windows DPAPI integration")
def test_real_dpapi_export_import_with_temporary_random_key(tmp_path, sample):
    snapshot, password = sample
    source, target, backup = tmp_path / "source", tmp_path / "target", tmp_path / "backup.tcdid.jwe"
    write_source(source, snapshot, create_keystore)
    m.export_backup(source, backup, password, repository=tmp_path / "repo", source_stopped=True)
    m.import_backup(backup, target, password, expected_did=snapshot.state.did)
    restored = load_identity(target / "identity.dpapi")
    require_secret_equal(restored.seed, snapshot.identity.seed)
    challenge = secrets.token_bytes(32)
    verify_signature(snapshot.state.did, challenge, restored.sign(challenge))


def test_existing_destination_protected_before_decryption(tmp_path, encrypted, monkeypatch):
    snapshot, password, data = encrypted
    backup, target = tmp_path / "backup", tmp_path / "target"
    backup.write_bytes(data)
    target.mkdir()
    (target / "identity.dpapi").write_bytes(secrets.token_bytes(64))
    before = (target / "identity.dpapi").read_bytes()
    monkeypatch.setattr(m, "decrypt_snapshot", lambda *a, **k: pytest.fail("existing identity must not be opened"))
    with pytest.raises(FileExistsError):
        m.import_backup(backup, target, password, expected_did=snapshot.state.did)
    assert hmac.compare_digest((target / "identity.dpapi").read_bytes(), before)


@pytest.mark.parametrize("boundary", ["create_keystore", "save_state", "_write_new", "_publish_directory"])
def test_failed_import_leaves_no_partial_target(tmp_path, encrypted, protectors, monkeypatch, boundary):
    snapshot, password, data = encrypted
    backup, target = tmp_path / "backup", tmp_path / "target"
    backup.write_bytes(data)
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(m, boundary, interrupt)
    with pytest.raises(KeyboardInterrupt):
        m.import_backup(backup, target, password, expected_did=snapshot.state.did)
    assert not target.exists()
    assert not list(tmp_path.glob(".target.import-*"))


def test_import_publish_race_preserves_other_identity(tmp_path, encrypted, protectors, monkeypatch):
    snapshot, password, data = encrypted
    backup, target = tmp_path / "backup", tmp_path / "target"
    backup.write_bytes(data)
    original = m._publish_directory
    marker = secrets.token_bytes(64)
    def race(staging, destination):
        destination.mkdir()
        (destination / "identity.dpapi").write_bytes(marker)
        original(staging, destination)
    monkeypatch.setattr(m, "_publish_directory", race)
    with pytest.raises(FileExistsError):
        m.import_backup(backup, target, password, expected_did=snapshot.state.did)
    assert hmac.compare_digest((target / "identity.dpapi").read_bytes(), marker)
    assert not (target / "state.json").exists()


def test_export_requires_stop_and_refuses_repo_or_existing_file(tmp_path, sample, protectors):
    snapshot, password = sample
    source = tmp_path / "source"
    write_source(source, snapshot, protectors[1])
    backup = tmp_path / "backup.tcdid.jwe"
    with pytest.raises(m.MigrationError, match="source-stopped"):
        m.export_backup(source, backup, password, repository=tmp_path / "repo", source_stopped=False)
    with pytest.raises(m.MigrationError, match="outside"):
        m.export_backup(source, source / "backup.tcdid.jwe", password, repository=tmp_path / "repo", source_stopped=True)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    with pytest.raises(m.MigrationError, match="outside"):
        m.export_backup(source, repo / "backup.tcdid.jwe", password, repository=tmp_path / "different", source_stopped=True)
    backup.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        m.export_backup(source, backup, password, repository=repo, source_stopped=True)
    assert backup.read_bytes() == b"existing"


def test_source_change_aborts_export(tmp_path, sample, protectors, monkeypatch):
    snapshot, password = sample
    source, backup = tmp_path / "source", tmp_path / "backup.tcdid.jwe"
    write_source(source, snapshot, protectors[1])
    original = m.encrypt_snapshot
    def concurrent_write(*args):
        encrypted = original(*args)
        (source / "proofs.jsonl").write_bytes(b"")
        return encrypted
    monkeypatch.setattr(m, "encrypt_snapshot", concurrent_write)
    with pytest.raises(m.MigrationError, match="source changed"):
        m.export_backup(source, backup, password, repository=tmp_path / "repo", source_stopped=True)
    assert not backup.exists()


def test_inconsistent_state_and_proofs_rejected(sample):
    snapshot, password = sample
    cases = [replace(snapshot, state=replace(snapshot.state, did=Identity.generate().did)),
             replace(snapshot, state=replace(snapshot.state, last_nonce_by_room={"lobby": 1})),
             replace(snapshot, proofs=[{**snapshot.proofs[0], "text": "modified"}]),
             replace(snapshot, state=replace(snapshot.state, last_nonce_by_room={"lobby": True}))]
    for invalid in cases:
        with pytest.raises(m.MigrationError):
            m.encrypt_snapshot(invalid, password)


def test_japanese_proof_history_exports_and_imports(tmp_path, sample, protectors):
    snapshot, password = sample
    text = "あ" * 4096
    proofs = []
    for index in range(130):
        nonce = snapshot.state.last_nonce_by_room["lobby"] - 129 + index
        proofs.append({**snapshot.proofs[0], "nonce": nonce, "text": text,
                       "seq": index + 1,
                       "signature": encode_signature(snapshot.identity.sign(message_payload("lobby", nonce, text)))})
    snapshot = replace(snapshot, proofs=proofs)
    assert len(m._proof_bytes(proofs)) < m.MAX_PROOFS_BYTES
    # ASCII escapes in the former import representation exceeded the read limit.
    assert len(b"".join(m._json_bytes(p) + b"\n" for p in proofs)) > m.MAX_PROOFS_BYTES
    source, target, backup = tmp_path / "source", tmp_path / "target", tmp_path / "backup.tcdid.jwe"
    write_source(source, snapshot, protectors[1])
    m.export_backup(source, backup, password, repository=tmp_path / "repo", source_stopped=True)
    protectors[0][0] = "target"
    m.import_backup(backup, target, password, expected_did=snapshot.state.did)
    assert json.loads((target / "proofs.jsonl").read_text(encoding="utf-8").splitlines()[-1]) == proofs[-1]


@pytest.mark.parametrize("limit", ["state", "proofs"])
def test_restored_size_limits_checked_while_decoding(sample, monkeypatch, limit):
    payload = m._encode_payload(sample[0])
    if limit == "state":
        monkeypatch.setattr(m, "_FILES", {**m._FILES, "state.json": 10})
    else:
        monkeypatch.setattr(m, "MAX_PROOFS_BYTES", 10)
    with pytest.raises(m.MigrationError, match="restored size limit"):
        m._decode_payload(payload)


def test_proof_count_checked_before_parsing_or_key_access(monkeypatch):
    monkeypatch.setattr(m, "_json", lambda *a: pytest.fail("excess records must not be parsed"))
    with pytest.raises(m.MigrationError, match="too many proof"):
        m._snapshot({"proofs.jsonl": b"{}\n" * (m.MAX_PROOFS + 1)})


def test_export_temp_allocation_failure_preserves_existing_file(tmp_path, sample, protectors, monkeypatch):
    source, backup = tmp_path / "source", tmp_path / "backup.tcdid.jwe"
    write_source(source, sample[0], protectors[1])
    other = tmp_path / ".backup.tcdid.jwe.collision.tmp"
    other.write_bytes(b"other caller's file")
    def allocation_failure(**kwargs):
        raise FileExistsError()
    monkeypatch.setattr(m.tempfile, "mkstemp", allocation_failure)
    with pytest.raises(FileExistsError):
        m.export_backup(source, backup, sample[1], repository=tmp_path / "repo", source_stopped=True)
    assert other.read_bytes() == b"other caller's file"
    assert not backup.exists()


def test_interrupted_export_removes_only_owned_temp(tmp_path, sample, protectors, monkeypatch):
    source, backup = tmp_path / "source", tmp_path / "backup.tcdid.jwe"
    write_source(source, sample[0], protectors[1])
    def interrupted(descriptor, data):
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data[:128])
            raise KeyboardInterrupt()
    monkeypatch.setattr(m, "_write_descriptor", interrupted)
    with pytest.raises(KeyboardInterrupt):
        m.export_backup(source, backup, sample[1], repository=tmp_path / "repo", source_stopped=True)
    assert not backup.exists()
    assert not list(tmp_path.glob(".backup.tcdid.jwe.*.tmp"))


def test_export_publish_race_preserves_other_file(tmp_path, sample, protectors, monkeypatch):
    source, backup = tmp_path / "source", tmp_path / "backup.tcdid.jwe"
    write_source(source, sample[0], protectors[1])
    original = m._publish_file
    def race(temporary, destination):
        destination.write_bytes(b"other backup")
        original(temporary, destination)
    monkeypatch.setattr(m, "_publish_file", race)
    with pytest.raises(FileExistsError):
        m.export_backup(source, backup, sample[1], repository=tmp_path / "repo", source_stopped=True)
    assert backup.read_bytes() == b"other backup"
    assert not list(tmp_path.glob(".backup.tcdid.jwe.*.tmp"))
