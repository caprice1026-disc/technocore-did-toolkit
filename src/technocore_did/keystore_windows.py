"""Current-user Windows DPAPI storage for an Ed25519 private seed."""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import secrets
import sys

from .identity import Identity

_ENTROPY = b"technocore-did-toolkit/v1"
_HEADER = b"TCDID\x01"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _input_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(
        len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    return blob, buffer


def _windows_libraries():
    if sys.platform != "win32":
        raise OSError("Windows DPAPI is available only on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.restype = wintypes.HLOCAL
    return crypt32, kernel32


def protect_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    crypt32, kernel32 = _windows_libraries()
    source, source_buffer = _input_blob(seed)
    entropy, entropy_buffer = _input_blob(_ENTROPY)
    output = _DataBlob()
    _ = source_buffer, entropy_buffer
    success = crypt32.CryptProtectData(
        ctypes.byref(source),
        "Technocore Ed25519 identity",
        ctypes.byref(entropy),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        ciphertext = ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
    return _HEADER + ciphertext


def unprotect_seed(blob: bytes) -> bytes:
    if not blob.startswith(_HEADER):
        raise ValueError("unsupported or malformed DPAPI identity envelope")
    crypt32, kernel32 = _windows_libraries()
    source, source_buffer = _input_blob(blob[len(_HEADER) :])
    entropy, entropy_buffer = _input_blob(_ENTROPY)
    output = _DataBlob()
    description = wintypes.LPWSTR()
    _ = source_buffer, entropy_buffer
    success = crypt32.CryptUnprotectData(
        ctypes.byref(source),
        ctypes.byref(description),
        ctypes.byref(entropy),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        seed = ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
        if description:
            kernel32.LocalFree(description)
    if len(seed) != 32:
        raise ValueError("DPAPI identity did not contain a 32-byte Ed25519 seed")
    return seed


def create_keystore(path: Path, identity: Identity) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"identity already exists: {path}")
    encrypted = protect_seed(identity.seed)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_identity(path: Path) -> Identity:
    return Identity.from_seed(unprotect_seed(path.read_bytes()))

