"""Ed25519 did:key identity derivation and signature verification."""

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_INDEX = {character: index for index, character in enumerate(_ALPHABET)}
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def _b58encode(data: bytes) -> str:
    leading_zeroes = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    characters: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        characters.append(_ALPHABET[remainder])
    return "1" * leading_zeroes + "".join(reversed(characters))


def _b58decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            digit = _ALPHABET_INDEX[character]
        except KeyError as error:
            raise ValueError("invalid Base58BTC character") from error
        number = number * 58 + digit
    decoded = (
        number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    )
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\0" * leading_zeroes + decoded


@dataclass(frozen=True)
class Identity:
    """An Ed25519 identity represented internally by its 32-byte private seed."""

    seed: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        return cls(bytes(seed))

    @classmethod
    def generate(cls) -> "Identity":
        private_key = Ed25519PrivateKey.generate()
        seed = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return cls(seed)

    @property
    def did(self) -> str:
        public_key = Ed25519PrivateKey.from_private_bytes(self.seed).public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return "did:key:z" + _b58encode(_ED25519_MULTICODEC_PREFIX + public_bytes)

    def sign(self, payload: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(self.seed).sign(payload)


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Resolve an Ed25519 did:key locally, rejecting other encodings."""

    if not did.startswith("did:key:z"):
        raise ValueError("expected an Ed25519 did:key")
    decoded = _b58decode(did.removeprefix("did:key:z"))
    if len(decoded) != 34 or not decoded.startswith(_ED25519_MULTICODEC_PREFIX):
        raise ValueError("expected an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def verify_signature(did: str, payload: bytes, signature: bytes) -> None:
    """Raise InvalidSignature if the payload was not signed by the DID key."""

    public_key_from_did(did).verify(signature, payload)

