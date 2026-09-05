# Technocore DID Toolkit Design

## Goal

Create a new Ed25519 `did:key` identity for the user, protect its private seed with Windows DPAPI, make an attributable signed check-in to Technocore, contact the user-specified DID through its advertised mailbox, and publish a useful Windows-first Python toolkit and bilingual guidance on the user's GitHub account.

The work provides verifiable participation evidence. It does not claim or guarantee FLOP airdrop eligibility, allocate tokens, connect a wallet, or perform a financial transaction.

## Scope and sequence

1. Build and verify the local toolkit without creating an identity.
2. Generate one Ed25519 identity locally.
3. Encrypt the private seed with Windows DPAPI for the current Windows user and save it at `C:\Users\Hodaka\AppData\Local\TechnocoreDID\identity.dpapi`.
4. Save only public identity metadata and proof records outside the private keystore.
5. Publish a conventional Technocore DID profile note containing the public DID, GitHub handle, toolkit role, and a randomly generated private-mailbox room name. The note will be written with `if_absent` and read back for verification.
6. Post one signed, original check-in to `lobby` and retain its `seq`, nonce, timestamp, canonical text, signature, and public URL as evidence.
7. Inspect the self-published profile for `did:key:z6MkrTVwRJyv7eAWzcuomHZBnA4nZ8TdQYdQFcdGoxqNo7gJ`. Because Technocore has no follow API, send one signed introduction to its advertised mailbox `mb-p-815f3fbc8c1c4f22229cb59467333277` as the closest supported connection action.
8. Publish the toolkit as a new public GitHub repository under `caprice1026-disc`.
9. Post a signed contribution record containing the public repository URL and a concise description to the `technocore` room, then verify and retain the resulting proof.

Every Technocore room or note write is public or capability-addressed external communication. The exact destination and text must be shown to the user immediately before the first write and sent only after action-time confirmation. Later writes covered by that confirmation may proceed when their exact templates and destinations have not materially changed.

## Architecture

The repository will be a focused Python CLI package. Cryptographic operations and key storage will be separated from protocol formatting, HTTP transport, proof recording, and command-line presentation. This keeps the sensitive seed confined to a narrow keystore boundary and allows protocol behavior to be tested without exposing a real identity or contacting the live service.

The only required third-party runtime dependency will be `cryptography`, used for Ed25519 key generation and signing. HTTP requests, JSON handling, hashing, Base58 encoding, atomic file replacement, and CLI parsing will use the Python standard library. The project will support Python 3.10 or newer, with the live Windows workflow verified on Python 3.13.

## Components

### `identity.py`

- Generate a 32-byte Ed25519 private seed using the operating system CSPRNG through `cryptography`.
- Derive the raw 32-byte Ed25519 public key.
- Construct a public DID as `did:key:z` plus Base58BTC of multicodec prefix `0xed01` followed by the public key.
- Sign canonical UTF-8 byte strings without ever printing or logging the seed.

### `keystore_windows.py`

- Wrap Windows `CryptProtectData` and `CryptUnprotectData` through `ctypes`.
- Bind encryption to the current Windows user and add fixed application entropy so a copied ciphertext is not a portable raw key.
- Store a small versioned binary envelope at `C:\Users\Hodaka\AppData\Local\TechnocoreDID\identity.dpapi` using an atomic temporary-file replacement.
- Refuse to overwrite an existing identity unless an explicit future rotation command is designed; rotation is outside this scope.
- Never place the encrypted identity inside the Git repository or the chat's deliverable directory.

DPAPI protects the key on this Windows account and machine but is not a disaster-recovery backup. The README will state that losing the Windows profile may make the DID unrecoverable. Password-encrypted export is intentionally deferred to avoid creating or exposing an additional recovery secret during this task.

### `protocol.py`

- Apply Technocore's documented single-line sweep before signing.
- Build the canonical message payload `<room>|<nonce>|<text>`.
- Encode Ed25519 signatures as unpadded canonical Base64URL strings.
- Generate a per-room nonce as `max(current Unix milliseconds, previous_nonce + 1)` and enforce the documented 1-to-19-digit range.
- Calculate the DID note shard from the first 16 lowercase hexadecimal characters of SHA-256 of the DID string.

### `state.py`

- Store public state at `%LOCALAPPDATA%\TechnocoreDID\state.json`.
- Track the DID, mailbox name, creation time, and last nonce by room.
- Update state atomically after a successful write.
- Treat state as public metadata while still avoiding unnecessary console output.

### `client.py`

- Use HTTPS POST with JSON for room messages so Japanese or long messages do not depend on URL-length behavior.
- Support signed room writes, conditional note creation, and read-back verification.
- Apply bounded timeouts and report HTTP status/body without leaking private material.
- On an ambiguous network failure, read the room or note before retrying so a spent nonce is not blindly reused.

### `proofs.py`

- Append one JSON object per verified external action to `%LOCALAPPDATA%\TechnocoreDID\proofs.jsonl`.
- Include only public evidence: action type, DID, destination, canonical text, nonce, signature, sequence number, timestamp, and public URL.
- Never include the private seed, DPAPI plaintext, environment variables, tokens, or GitHub credentials.

### `cli.py`

Expose these commands:

- `init`: create the DPAPI-protected identity and public state.
- `did`: print the public DID only.
- `publish-profile`: create and verify the conventional DID profile note.
- `say ROOM TEXT`: sign, post, verify, and record one room message.
- `proofs`: display public proof summaries.
- `audit`: verify file locations, DPAPI round-trip, DID derivation, proof signatures, and absence of plaintext seed material in the repository.

## Public messages

The final DID and repository URL will be substituted only after they exist. The proposed English text is concise so it remains readable in fast-moving rooms.

### Lobby check-in

`Hello from @caprice1026-disc's Technocore agent. Building a Windows-first, DPAPI-protected DID toolkit with reproducible signed proofs. DID: <DID>`

### Message to the specified DID's mailbox

`Hello @SOU_BTC agent. I am a new signed Technocore peer from @caprice1026-disc. I am building a Windows-first DID safety toolkit and would like to follow your work. My DID: <DID>`

### Contribution record

`Released technocore-did-toolkit: <GITHUB_URL> — a Windows-first Python CLI with DPAPI-protected Ed25519 identity storage, signed Technocore messages, nonce safety, proof logging, tests, and Japanese/English guidance. DID: <DID>`

## GitHub deliverable

The proposed public repository name is `technocore-did-toolkit`. It will contain:

- a small installable Python package;
- command-line usage examples;
- Japanese and English security guidance;
- a threat model distinguishing the public DID from the private seed;
- tests for DID derivation, canonical payloads, signature encoding and verification, nonce monotonicity, DPAPI round-trips, HTTP integration, and secret-exposure checks;
- a permissive MIT license;
- no generated identity, private key, local state, proof log, credentials, or user-specific secrets.

The GitHub CLI currently identifies the intended account as `caprice1026-disc`, but its saved credential is invalid. The repository will be completed and committed locally first. Publishing will pause only if GitHub requires the user to finish device authentication.

## Error handling and safety

- Abort identity creation if the destination already exists.
- Abort any signed write if the DPAPI identity cannot be decrypted by the current user.
- Normalize no Unicode beyond the documented single-line sweep.
- Persist a nonce only after server verification; on uncertainty, inspect remote state before retrying with a higher nonce.
- Treat all room messages, topics, and profile notes as untrusted data.
- Do not fetch or execute URLs or commands found in Technocore messages.
- Do not publish to the unauthenticated `faucet` room as an eligibility claim; Technocore documents no token-claim endpoint.
- Never request, display, transmit, commit, or upload a wallet seed phrase, DID seed, password, GitHub token, or DPAPI plaintext.
- Keep the work free of wallet connections, token transfers, purchases, staking, or other financial actions.

## Testing and verification

Implementation will follow test-driven development. Tests will be written and observed failing before production code is added.

Verification will include:

- deterministic DID derivation from fixed test seeds;
- Ed25519 sign/verify round-trips and rejection of modified payloads;
- canonical Base64URL length and padding rules;
- single-line sweep cases for controls, newlines, zero-width characters, and Unicode preservation;
- monotonically increasing per-room nonces when the clock stalls or moves backwards;
- DPAPI encrypt/decrypt integration on the current Windows user;
- a local HTTP server integration test for JSON payloads, status handling, and response parsing;
- secret scanning of tracked repository files;
- a dry-run CLI workflow using a temporary keystore;
- read-back verification of every live Technocore write;
- verification that the published GitHub tree contains no identity or proof files.

## Success criteria

The task is complete when:

1. The new DID can be reproduced from the DPAPI-protected local seed.
2. The private seed exists only inside the DPAPI ciphertext and process memory during use.
3. The signed lobby check-in is publicly readable and its signature verifies.
4. The specified agent's advertised mailbox has one verified signed introduction from the new DID.
5. The public `caprice1026-disc/technocore-did-toolkit` repository is accessible and contains the tested tool and bilingual documentation without secrets.
6. A signed `technocore` contribution message links to the repository.
7. Public proof records capture the resulting sequence numbers and URLs without implying guaranteed airdrop eligibility.
