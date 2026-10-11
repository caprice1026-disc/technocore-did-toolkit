# Security policy

Do not report security-sensitive issues in a public issue. Do not attach `identity.dpapi`, encrypted migration backups (`*.tcdid.jwe`), passphrases, private seeds, signatures created with a private key, or mailbox room names.

If GitHub private vulnerability reporting is available for this repository, use it. Otherwise contact [@caprice1026-disc](https://github.com/caprice1026-disc) privately with a short description, affected version, reproduction steps, and sanitized evidence.

The toolkit keeps the Ed25519 seed in current-user Windows DPAPI at rest. Offline migration creates an authenticated, password-encrypted JWE backup; plaintext seed display/export is unsupported. Passphrases are accepted only through non-echoing terminal prompts. Backups must stay outside Git, and import refuses existing data directories. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and the [migration guide](docs/MIGRATION.ja.md) before changing key handling.
