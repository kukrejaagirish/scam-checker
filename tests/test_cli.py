import io
import json
import subprocess
import sys

from scam_checker.cli import main


def test_cli_argument_text_output(capsys):
    code = main(["Your account will be blocked, update KYC now"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Risk:" in out
    assert "1930" in out


def test_cli_json_output(capsys):
    code = main(["--json", "hello, how are you?"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["level"] == "Low"
    assert "score" in data


def test_cli_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("You have won a lottery! Pay registration fee"))
    code = main([])
    assert code == 1
    assert "Lottery" in capsys.readouterr().out


def test_module_entry_point():
    proc = subprocess.run(
        [sys.executable, "-m", "scam_checker", "Share your OTP now"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 1
    assert "OTP" in proc.stdout
