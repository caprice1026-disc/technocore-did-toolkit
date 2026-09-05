import pytest
from cryptography.exceptions import InvalidSignature

from technocore_did.identity import Identity, public_key_from_did, verify_signature


def test_zero_seed_derives_known_ed25519_did():
    identity = Identity.from_seed(bytes(32))
    assert identity.did == "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"


def test_signature_verifies_and_modified_payload_fails():
    identity = Identity.from_seed(bytes(32))
    signature = identity.sign(b"lobby|1|hello")
    verify_signature(identity.did, b"lobby|1|hello", signature)
    with pytest.raises(InvalidSignature):
        verify_signature(identity.did, b"lobby|1|changed", signature)


def test_bad_seed_and_bad_did_are_rejected():
    with pytest.raises(ValueError, match="32 bytes"):
        Identity.from_seed(b"short")
    with pytest.raises(ValueError, match="Ed25519 did:key"):
        public_key_from_did("did:key:not-ed25519")

