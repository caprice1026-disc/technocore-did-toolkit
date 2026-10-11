import getpass
import hmac
import secrets

import pytest

from technocore_did import cli
from technocore_did.identity import Identity
from technocore_did.migration import MigrationError


def test_migration_passphrase_requires_real_terminal(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: pytest.fail("must not prompt on a pipe"))
    with pytest.raises(MigrationError, match="interactive terminal"):
        cli._read_passphrase(confirm=True)


def test_prompt_confirmation_and_no_echo_fallback(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    password = secrets.token_urlsafe(32)
    entries = iter([password, password])
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: next(entries))
    if not hmac.compare_digest(cli._read_passphrase(confirm=True), password):
        pytest.fail("prompt changed passphrase", pytrace=False)
    entries = iter([password, secrets.token_urlsafe(32)])
    with pytest.raises(MigrationError, match="confirmation"):
        cli._read_passphrase(confirm=True)
    def unsafe(*a):
        raise getpass.GetPassWarning()
    monkeypatch.setattr(cli.getpass, "getpass", unsafe)
    with pytest.raises(MigrationError, match="secure terminal"):
        cli._read_passphrase(confirm=False)


def test_source_stop_required_before_prompt_or_key_access(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_read_passphrase", lambda **k: pytest.fail("must refuse before prompting"))
    assert cli.main(["--data-dir", str(tmp_path / "source"), "export", str(tmp_path / "backup")]) == 1
    assert "source-stopped" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["export", "import"])
def test_cli_outputs_only_public_result_and_catches_secret_bearing_errors(tmp_path, monkeypatch, capsys, command):
    password, did = secrets.token_urlsafe(32), Identity.generate().did
    monkeypatch.setattr(cli, "_read_passphrase", lambda **k: password)
    method = "export_backup" if command == "export" else "import_backup"
    monkeypatch.setattr(cli, method, lambda *a, **k: did)
    args = ["--data-dir", str(tmp_path / "data"), command, str(tmp_path / "backup")]
    args += ["--source-stopped"] if command == "export" else ["--expected-did", did]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    assert did in captured.out
    if password in captured.out + captured.err:
        pytest.fail("secret material appeared in CLI output", pytrace=False)
    def fail(*a, **k):
        raise RuntimeError(password)
    monkeypatch.setattr(cli, method, fail)
    assert cli.main(args) == 1
    captured = capsys.readouterr()
    if password in captured.out + captured.err:
        pytest.fail("secret material appeared in CLI error", pytrace=False)
    assert "Traceback" not in captured.err


def test_passphrase_argument_is_not_available(tmp_path, capsys):
    password = secrets.token_urlsafe(32)
    with pytest.raises(SystemExit):
        cli.main(["export", str(tmp_path / "backup"), "--source-stopped", "--password", password])
    captured = capsys.readouterr()
    if password in captured.out + captured.err:
        pytest.fail("secret material appeared in argument error", pytrace=False)
    assert "Input values were omitted" in captured.err


def test_invalid_command_does_not_echo_input(capsys):
    password = secrets.token_urlsafe(32)
    with pytest.raises(SystemExit):
        cli.main([password])
    captured = capsys.readouterr()
    if password in captured.out + captured.err:
        pytest.fail("secret material appeared in command error", pytrace=False)
