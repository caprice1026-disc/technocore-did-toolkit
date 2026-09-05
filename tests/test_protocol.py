import pytest

from technocore_did.protocol import (
    decode_signature,
    did_note_location,
    encode_signature,
    message_payload,
    next_nonce,
    sweep_single_line,
    validate_name,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  hello\nworld  ", "hello world"),
        ("a\u200db", "a b"),
        ("a\ue000b", "a b"),
        ("日本語 café", "日本語 café"),
    ],
)
def test_single_line_sweep(raw, expected):
    assert sweep_single_line(raw, limit=4096) == expected


def test_empty_or_oversized_swept_text_is_rejected():
    with pytest.raises(ValueError, match="empty"):
        sweep_single_line("\n\u200d", limit=4096)
    with pytest.raises(ValueError, match="4096"):
        sweep_single_line("x" * 4097, limit=4096)


def test_message_payload_is_exact_utf8():
    assert message_payload("lobby", 123, "こんにちは") == (
        "lobby|123|こんにちは".encode("utf-8")
    )


def test_signature_encoding_is_canonical_and_unpadded():
    encoded = encode_signature(bytes(range(64)))
    assert len(encoded) == 86
    assert "=" not in encoded
    assert decode_signature(encoded) == bytes(range(64))
    with pytest.raises(ValueError, match="canonical"):
        decode_signature(encoded[:-1] + "B")


def test_nonce_is_monotonic_when_clock_stalls_or_moves_backwards():
    assert next_nonce(None, 1_700_000_000_000) == 1_700_000_000_000
    assert next_nonce(1_700_000_000_005, 1_700_000_000_000) == 1_700_000_000_006


def test_nonce_range_and_protocol_names_are_validated():
    assert validate_name("mb-p-0123_abcd") == "mb-p-0123_abcd"
    with pytest.raises(ValueError, match="name"):
        validate_name("Lobby")
    with pytest.raises(ValueError, match="19 digits"):
        next_nonce(9_999_999_999_999_999_999, 1)


def test_did_note_location_matches_sha256_shard():
    assert did_note_location(
        "did:key:z6MkrTVwRJyv7eAWzcuomHZBnA4nZ8TdQYdQFcdGoxqNo7gJ"
    ) == ("did-12", "a5e64ecaf9f447")

