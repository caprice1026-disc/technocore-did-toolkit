# Threat model

## Assets and boundary

The primary secret is the 32-byte Ed25519 private seed. It may exist in process memory while the CLI derives the DID or signs a message. At rest it must exist only inside the versioned DPAPI envelope in `%LOCALAPPDATA%\TechnocoreDID\identity.dpapi`.

The DID, public key, mailbox name, nonce, message text, signature, sequence number, timestamp, and public URL are not secrets. They are intentionally present in server responses and may be kept in public proof records.

## Assumptions

- Windows DPAPI and the current user's profile are trusted to protect data at rest.
- The local Python interpreter, `cryptography` wheel, operating system, and CLI process are not already compromised.
- HTTPS protects requests in transit, but Technocore room and note storage is untrusted and not guaranteed durable.
- GitHub credentials are managed by GitHub CLI and are never passed to this program.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Repository accidentally includes the identity | Exact secret filenames are ignored; `audit` rejects them under the repository and scans for the current seed bytes | Renamed, transformed, or archived copies need an external secret scanner |
| Seed printed or added to evidence | CLI prints the public DID and paths only; proof schema rejects sensitive field names | A debugger or compromised dependency can inspect process memory |
| DPAPI ciphertext is copied | DPAPI is bound to the current Windows user and application entropy | Malware running as the same user can ask DPAPI to decrypt it |
| Windows profile is lost | Documentation warns that the identity may be unrecoverable | No recovery export exists in this release |
| Signed URL/message is replayed | Per-room nonce is monotonically increased and recorded only after verification | Technocore documents that replay protection depends on its retained nonce scan window; signatures still prove the original key |
| Public profile note is overwritten | Initial write uses `if_absent` and exact read-back | Non-reserved notes are world-writable; consumers must not treat the note as an identity-provider assertion |
| A room message contains hostile instructions | All remote content is treated as data; the client never executes discovered URLs or commands | Humans can still choose to act on misleading content |
| Unicode invisibles alter signed meaning | The official category sweep runs before signing; the exact swept text is posted and proved | Unicode confusables outside those categories remain possible |
| Nonce is consumed during a network timeout | An ambiguous failure triggers room inspection before success is recorded | If the signed record has already fallen outside the returned slice, manual evidence review may be required |
| GitHub token leaks | The tool never reads or logs GitHub credentials; GitHub CLI handles authentication | A compromised GitHub CLI or operating system remains outside this tool's boundary |

## Deliberately unsupported

- plaintext seed display or export;
- password-encrypted backup export;
- wallet connection, token claims, transfers, staking, or purchases;
- executing messages, links, or commands discovered on Technocore;
- claiming that a DID proves a legal or human identity;
- claiming or guaranteeing airdrop eligibility.

Any future export feature requires a separate design review covering password entry, memory handling, KDF parameters, backup verification, and revocation/rotation semantics.

