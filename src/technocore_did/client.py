"""Small verified HTTP client for Technocore rooms and notes."""

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .identity import verify_signature
from .protocol import (
    decode_signature,
    message_payload,
    sweep_single_line,
    validate_name,
)

_MAX_RESPONSE_BYTES = 1024 * 1024


class TechnocoreError(RuntimeError):
    """A refused or malformed Technocore operation."""


class TechnocoreTransportError(TechnocoreError):
    """A request whose remote completion state may be unknown."""


class TechnocoreClient:
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> tuple[bytes, str]:
        data = None
        headers: dict[str, str] = {}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=data, headers=headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = response.read(_MAX_RESPONSE_BYTES + 1)
                content_type = response.headers.get("Content-Type", "")
        except HTTPError as error:
            response_body = error.read(4096).decode("utf-8", errors="replace").strip()
            if allow_not_found and error.code == 404:
                return b"", ""
            raise TechnocoreError(
                f"Technocore HTTP {error.code}: {response_body}"
            ) from error
        except (URLError, TimeoutError, OSError) as error:
            raise TechnocoreTransportError(f"Technocore transport error: {error}") from error
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise TechnocoreError("Technocore response exceeded the 1 MiB safety limit")
        return payload, content_type

    def read_room(self, room: str, limit: int = 200) -> dict[str, Any]:
        validate_name(room)
        query = urlencode({"format": "json", "limit": limit})
        payload, content_type = self._request(f"/r/{quote(room)}?{query}")
        if "application/json" not in content_type.lower():
            raise TechnocoreError("Technocore room response was not JSON")
        try:
            result = json.loads(payload)
        except json.JSONDecodeError as error:
            raise TechnocoreError("Technocore returned malformed room JSON") from error
        if (
            not isinstance(result, dict)
            or result.get("room") != room
            or not isinstance(result.get("messages"), list)
        ):
            raise TechnocoreError("Technocore returned an invalid room object")
        return result

    def post_signed(
        self,
        room: str,
        did: str,
        signature: str,
        nonce: int,
        text: str,
    ) -> dict[str, Any]:
        validate_name(room)
        decode_signature(signature)
        message_payload(room, nonce, text)
        if sweep_single_line(text, limit=4096) != text:
            raise ValueError("signed text must already have the single-line sweep applied")
        query = urlencode({"format": "json"})
        payload, content_type = self._request(
            f"/r/{quote(room)}?{query}",
            body={
                "did": did,
                "sig": signature,
                "nonce": str(nonce),
                "text": text,
            },
        )
        if "application/json" not in content_type.lower():
            raise TechnocoreError("Technocore signed-write response was not JSON")
        try:
            result = json.loads(payload)
        except json.JSONDecodeError as error:
            raise TechnocoreError("Technocore returned malformed signed-write JSON") from error
        if not isinstance(result, dict) or result.get("room") != room:
            raise TechnocoreError("Technocore returned an invalid signed-write object")
        return result

    def get_note(self, namespace: str, key: str) -> str | None:
        validate_name(namespace)
        validate_name(key)
        payload, _ = self._request(
            f"/kv/{quote(namespace)}/{quote(key)}", allow_not_found=True
        )
        if not payload:
            return None
        text = payload.decode("utf-8")
        if not text.startswith("!! UNTRUSTED CONTENT") or "\n\n" not in text:
            raise TechnocoreError("Technocore note response lacked its untrusted-data banner")
        return text.split("\n\n", 1)[1].rstrip("\r\n")

    def put_note_if_absent(self, namespace: str, key: str, value: str) -> str:
        validate_name(namespace)
        validate_name(key)
        swept = sweep_single_line(value, limit=8192)
        if swept != value:
            raise ValueError("note value must already have the single-line sweep applied")
        self._request(
            f"/kv/{quote(namespace)}/{quote(key)}",
            body={"value": value, "if_absent": True},
        )
        stored = self.get_note(namespace, key)
        if stored != value:
            raise TechnocoreError("Technocore note read-back did not match the requested value")
        return stored


def find_verified_message(
    room_data: dict[str, Any],
    *,
    did: str,
    nonce: int,
    signature: str,
    text: str,
) -> dict[str, Any]:
    room = room_data.get("room")
    if not isinstance(room, str):
        raise TechnocoreError("room result has no valid room name")
    for message in room_data.get("messages", []):
        if (
            isinstance(message, dict)
            and message.get("from") == did
            and message.get("nonce") == nonce
            and message.get("sig") == signature
            and message.get("text") == text
        ):
            verify_signature(
                did,
                message_payload(room, nonce, text),
                decode_signature(signature),
            )
            return message
    raise TechnocoreError("verified signed message was not present in the room response")

