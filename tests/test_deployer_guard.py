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
