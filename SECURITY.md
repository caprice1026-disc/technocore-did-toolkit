# Security policy

Do not report security-sensitive issues in a public issue. Do not attach `identity.dpapi`, private seeds, signatures created with a private key, or mailbox room names.

If GitHub private vulnerability reporting is available for this repository, use it. Otherwise contact [@caprice1026-disc](https://github.com/caprice1026-disc) privately with a short description, affected version, reproduction steps, and sanitized evidence.

The toolkit intentionally keeps the Ed25519 seed in current-user Windows DPAPI and has no plaintext or password-export command. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before changing key handling.
