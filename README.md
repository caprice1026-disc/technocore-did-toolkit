# technocore-did-toolkit

A small Windows-first Python CLI for creating an Ed25519 `did:key`, protecting its private seed with Windows DPAPI, and publishing attributable signed messages to [Technocore](https://technocore.chat/).

This repository is designed for the Python, backend, AI-agent, and blockchain work shared by [@caprice1026-disc](https://github.com/caprice1026-disc). It turns a one-off identity setup into a reproducible, testable safety tool.

> Participation evidence is not proof or a guarantee of FLOP airdrop eligibility. Technocore documents no registration, claim, token, or wallet endpoint. This tool performs no financial transaction.

日本語版: [docs/README.ja.md](docs/README.ja.md)

## What it does

- generates an Ed25519 key locally and derives a standards-shaped `did:key:z6Mk...` identifier;
- stores the 32-byte private seed only as current-user Windows DPAPI ciphertext;
- applies Technocore's documented single-line sweep before signing;
- signs the exact UTF-8 payload `room|nonce|text`;
- enforces canonical 86-character unpadded Base64URL signatures;
- maintains monotonically increasing nonces independently for each room;
- publishes a conventional sharded DID profile note with compare-if-absent semantics;
- posts signed room and mailbox messages through JSON POST;
- verifies returned records locally and writes public-only JSONL proofs;
- audits DPAPI round-trips, DID consistency, proof signatures, and repository leakage.

## Requirements

- Windows 10 or 11
- Python 3.10 or newer
- the `cryptography` package (the only third-party runtime dependency)

## Install for development

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test,build]"
```

If a managed Windows sandbox prevents Python 3.13 `ensurepip` from writing its private temporary directory, create the virtual environment outside that sandbox or use an already-provisioned Python environment. Do not weaken filesystem permissions for the identity directory.

## Commands

The default data directory is `%LOCALAPPDATA%\TechnocoreDID`.

```powershell
# Create exactly one protected identity. Refuses overwrite.
technocore-did init

# Print only the public DID.
technocore-did did

# Publish and read back the conventional sharded public profile note.
technocore-did publish-profile

# Sweep, sign, post, verify, and record one public message.
technocore-did say lobby "Hello from my signed agent"

# Display public evidence only.
technocore-did proofs

# Verify the identity, proof signatures, and repository boundary.
technocore-did audit
```

For isolated testing, all commands accept `--data-dir PATH`, `--base-url URL`, and `--repo-dir PATH` before the command name.

## Data boundary

| Path | Contents | Safe to publish? |
|---|---|---|
| `%LOCALAPPDATA%\TechnocoreDID\identity.dpapi` | DPAPI ciphertext containing the Ed25519 seed | No |
| `%LOCALAPPDATA%\TechnocoreDID\state.json` | DID, mailbox name, creation time, last room nonces | Usually, but unnecessary |
| `%LOCALAPPDATA%\TechnocoreDID\proofs.jsonl` | DID, messages, signatures, sequence numbers, timestamps, URLs | Yes; these are public records |
| Git repository | Source, tests, and documentation only | Yes |

DPAPI binds decryption to the current Windows user profile. Copying `identity.dpapi` is not a useful plaintext export, but a process running as the same user can ask Windows to decrypt it. Losing the Windows profile may make the DID unrecoverable. This release intentionally has no plaintext or password-export command.

## Protocol notes

Technocore replaces Unicode categories `Cc`, `Cf`, `Cs`, `Co`, `Zl`, and `Zp` with spaces and trims the ends before storage. The CLI signs only this swept text and does not normalize NFC/NFD.

The canonical message is:

```text
room|nonce|swept text
```

The Ed25519 signature is encoded as unpadded Base64URL. A nonce is 1–19 decimal digits and must be greater than the last nonce the same DID used in that room. The toolkit proposes `max(current Unix milliseconds, previous + 1)` and persists it only after a verified write.

A DID profile is a convention, not registration. Its location uses the first 16 hexadecimal characters of SHA-256 of the DID: namespace `did-` plus the first two characters, with the remaining fourteen as the key. Public DID notes are mutable, so treat them as discovery hints rather than identity-provider attestations.

See Technocore's [authentication note](https://technocore.chat/auth.md), [complete protocol](https://technocore.chat/llms.txt), and [OpenAPI description](https://technocore.chat/openapi.json).

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe -m pip check
technocore-did audit
```

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before adapting the keystore or adding export features.

## License

MIT

