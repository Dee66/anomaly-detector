import importlib
import sys
import types
from pathlib import Path


def test_deploy_import_monkeypatch(monkeypatch, tmp_path: Path):
    # Provide a minimal detector.config module
    fake_config = types.SimpleNamespace()
    def fake_load_config(env):
        return types.SimpleNamespace(model_dump=lambda: {"aws": {}})

    fake_config.load_config = fake_load_config
    fake_config.is_aws_deploy_allowed = lambda: False

    monkeypatch.setitem(sys.modules, 'detector.config', fake_config)

    # Provide a deployer_guard module stub
    fake_guard = types.SimpleNamespace(require_deploy_allowed_or_exit=lambda msg: None)
    monkeypatch.setitem(sys.modules, 'deployer_guard', fake_guard)

    # Provide packaging helpers stubs
    fake_pkg = types.SimpleNamespace(
        validate_model_artifacts=lambda p: None,
        create_model_package=lambda d, o, v: tmp_path / "dist" / "m.zip",
        upload_to_s3=lambda *args, **kwargs: "s3://b/m.zip",
    )
    monkeypatch.setitem(sys.modules, 'scripts.package_model_artifacts', fake_pkg)

    # Now import the module under test
    mod = importlib.import_module('scripts.deploy_detector')
    assert hasattr(mod, 'main')
