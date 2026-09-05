import json
from pathlib import Path

import pytest

from technocore_did.cli import AuditError, Paths, audit, main
from technocore_did.keystore_windows import load_identity
from technocore_did.proofs import read_proofs, verify_message_proof
from technocore_did.state import load_state


class FakeClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.notes = {}
        self.rooms = {}

    def put_note_if_absent(self, namespace, key, value):
        location = (namespace, key)
        if location in self.notes:
            raise RuntimeError("note already exists")
        self.notes[location] = value
        return value

    def get_note(self, namespace, key):
        return self.notes.get((namespace, key))

    def post_signed(self, room, did, signature, nonce, text):
        message = {
            "seq": len(self.rooms.get(room, [])) + 1,
            "ts": "2026-09-05T00:00:00.000000Z",
            "from": did,
            "text": text,
            "nonce": nonce,
            "sig": signature,
        }
        self.rooms.setdefault(room, []).append(message)
        return {
            "room": room,
            "count": len(self.rooms[room]),
            "first_seq": 1,
            "last_seq": message["seq"],
            "messages": list(self.rooms[room]),
        }

    def read_room(self, room, limit=200):
        messages = self.rooms.get(room, [])[-limit:]
        return {
            "room": room,
            "count": len(messages),
            "first_seq": messages[0]["seq"] if messages else None,
            "last_seq": messages[-1]["seq"] if messages else 0,
            "messages": list(messages),
        }


@pytest.fixture
def paths(tmp_path):
    return Paths.from_root(tmp_path / "data")


def test_init_creates_private_keystore_and_public_state(paths, capsys):
    assert main(["--data-dir", str(paths.root), "init"]) == 0
    state = load_state(paths.state)
    assert state.did.startswith("did:key:z6Mk")
    assert state.mailbox.startswith("mb-p-")
    assert paths.keystore.exists()
    output = capsys.readouterr().out
    assert load_identity(paths.keystore).seed.hex() not in output


def test_say_sweeps_signs_verifies_records_and_advances_nonce(paths, capsys):
    client = FakeClient("https://example.test")
    main(["--data-dir", str(paths.root), "init"])
    capsys.readouterr()

    assert (
        main(
            [
                "--data-dir",
                str(paths.root),
                "--base-url",
                client.base_url,
                "say",
                "lobby",
                "hello\nworld",
            ],
            client_factory=lambda _: client,
        )
        == 0
    )

    proof = read_proofs(paths.proofs)[0]
    assert proof["text"] == "hello world"
    assert proof["destination"] == "lobby"
    assert verify_message_proof(proof) is True
    assert load_state(paths.state).last_nonce_by_room["lobby"] == proof["nonce"]


def test_publish_profile_records_exact_read_back(paths, capsys):
    client = FakeClient("https://example.test")
    main(["--data-dir", str(paths.root), "init"])
    capsys.readouterr()
    assert (
        main(
            [
                "--data-dir",
                str(paths.root),
                "--base-url",
                client.base_url,
                "publish-profile",
            ],
            client_factory=lambda _: client,
        )
        == 0
    )
    proof = read_proofs(paths.proofs)[0]
    assert proof["action"] == "profile_note"
    assert proof["did"] in proof["value"]
    assert "github:https://github.com/caprice1026-disc" in proof["value"]


def test_audit_detects_identity_artifact_in_repository(paths, tmp_path):
    main(["--data-dir", str(paths.root), "init"])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "identity.dpapi").write_bytes(b"encrypted")
    with pytest.raises(AuditError, match="identity.dpapi"):
        audit(paths, repo)


def test_paths_match_windows_default_names(tmp_path):
    paths = Paths.from_root(Path(tmp_path))
    assert paths.keystore.name == "identity.dpapi"
    assert paths.state.name == "state.json"
    assert paths.proofs.name == "proofs.jsonl"
