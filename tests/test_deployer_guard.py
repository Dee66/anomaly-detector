import os
import sys
import pytest

from src.deployer_guard import is_deploy_allowed, require_deploy_allowed_or_exit


def test_is_deploy_allowed_default_false(monkeypatch):
    monkeypatch.delenv('ALLOW_AWS_DEPLOY', raising=False)
    monkeypatch.delenv('DEPLOY_CONFIRM', raising=False)
    assert not is_deploy_allowed()


def test_is_deploy_allowed_true_when_both_set(monkeypatch):
    monkeypatch.setenv('ALLOW_AWS_DEPLOY', '1')
    monkeypatch.setenv('DEPLOY_CONFIRM', 'I_ACCEPT_COSTS')
    assert is_deploy_allowed()


def test_require_deploy_allowed_or_exit_exits_and_prints_message(monkeypatch, capsys):
    # Ensure env is not set
    monkeypatch.delenv('ALLOW_AWS_DEPLOY', raising=False)
    monkeypatch.delenv('DEPLOY_CONFIRM', raising=False)

    with pytest.raises(SystemExit) as exc:
        require_deploy_allowed_or_exit("Test message")

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "ERROR: Real AWS deployments are disabled by default." in captured.err
    assert "ALLOW_AWS_DEPLOY=1" in captured.err
    assert "I_ACCEPT_COSTS" in captured.err
    assert "Test message" in captured.err
import os
import subprocess
import pytest

from src.deployer_guard import is_deploy_allowed


def test_deploy_allowed_default_false(monkeypatch):
    monkeypatch.delenv("ALLOW_AWS_DEPLOY", raising=False)
    monkeypatch.delenv("DEPLOY_CONFIRM", raising=False)
    assert is_deploy_allowed() is False


def test_deploy_allowed_true_with_both(monkeypatch):
    monkeypatch.setenv("ALLOW_AWS_DEPLOY", "1")
    monkeypatch.setenv("DEPLOY_CONFIRM", "I_ACCEPT_COSTS")
    assert is_deploy_allowed() is True
