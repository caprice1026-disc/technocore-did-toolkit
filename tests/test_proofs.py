import json

import pytest
from cryptography.exceptions import InvalidSignature

from technocore_did.identity import Identity
from technocore_did.proofs import append_proof, read_proofs, verify_message_proof
from technocore_did.protocol import encode_signature, message_payload


def test_append_proof_writes_public_jsonl_without_seed(tmp_path):
    path = tmp_path / "proofs.jsonl"
    proof = {
        "action": "signed_message",
        "did": "did:key:zexample",
        "destination": "lobby",
        "nonce": 1,
        "signature": "public-signature",
        "text": "hello",
        "seq": 9,
        "ts": "2026-09-05T00:00:00Z",
        "url": "https://technocore.chat/r/lobby?since=8&format=json",
    }
    append_proof(path, proof)
    assert json.loads(path.read_text(encoding="utf-8")) == proof
    assert read_proofs(path) == [proof]
    assert "seed" not in path.read_text(encoding="utf-8").lower()


def test_sensitive_field_names_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="sensitive"):
        append_proof(
            tmp_path / "proofs.jsonl",
            {
                "action": "profile_note",
                "did": "did:key:zexample",
                "destination": "did-aa/bbbb",
                "ts": "2026-09-05T00:00:00Z",
                "url": "https://technocore.chat/kv/did-aa/bbbb",
                "private_key": "must-not-land",
            },
        )


def test_message_proof_verifies_and_detects_modified_text():
    identity = Identity.from_seed(bytes(32))
    nonce = 1_700_000_000_000
    payload = message_payload("lobby", nonce, "hello")
    proof = {
        "action": "signed_message",
        "did": identity.did,
        "destination": "lobby",
        "nonce": nonce,
        "signature": encode_signature(identity.sign(payload)),
        "text": "hello",
        "seq": 9,
        "ts": "2026-09-05T00:00:00Z",
        "url": "https://technocore.chat/r/lobby?since=8&format=json",
    }
    assert verify_message_proof(proof) is True
    proof["text"] = "changed"
    with pytest.raises(InvalidSignature):
        verify_message_proof(proof)

