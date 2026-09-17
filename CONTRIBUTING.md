# Contributing

Issues and pull requests are welcome for reproducibility fixes, documentation, and narrowly scoped improvements.

## Before opening an issue or pull request

- Use Windows 10 or 11 with Python 3.10 or newer.
- Run `\.venv\Scripts\python.exe -m pytest -q`, `\.venv\Scripts\python.exe -m build`, and `\.venv\Scripts\python.exe -m pip check`.
- Never include `identity.dpapi`, private seeds, plaintext keys, or mailbox capabilities in an issue, log, or pull request.
- For a behavior report, include the Windows version, Python version, command, and sanitized output.

Small, focused pull requests are easier to review. Please explain any protocol or security trade-off in the pull request body.
