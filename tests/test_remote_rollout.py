"""Exercise rollback without contacting a deployment host or Docker daemon."""

import importlib.util
import json
import tarfile
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1] / "deploy" / "remote_rollout.py"
spec = importlib.util.spec_from_file_location("remote_rollout", MODULE)
rollout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rollout)


@pytest.mark.parametrize("failure", [False, True])
def test_rollout_commit_or_restore(tmp_path, monkeypatch, failure):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yaml").write_text("services: {}\n")
    initial = "MCP_IMAGE=old-image\nPRIVATE_VALUE=test-only\n"
    (tmp_path / ".env").write_text(initial)
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz"):
        pass
    revision = "a" * 40
    monkeypatch.setattr(
        "sys.argv", ["rollout", str(tmp_path), str(archive), revision, "https://example.com"]
    )
    calls = []

    def run(args, *, env=None, capture=False):
        calls.append((args, env))
        if args[-3:] == ["ps", "-q", "mcp"]:
            return "container\n"
        if args[:2] == ["docker", "inspect"]:
            if "--format" in args:
                return "healthy\n"
            return json.dumps(
                [
                    {
                        "Image": "sha256:previous",
                        "Config": {"Env": ["MCP_OAUTH_ALLOWED_SUBJECTS=disabled-test"]},
                    }
                ]
            )
        if args[-3:] == ["config", "--format", "json"]:
            return json.dumps(
                {
                    "services": {
                        "mcp": {"environment": {"MCP_OAUTH_ALLOWED_SUBJECTS": "disabled-test"}}
                    }
                }
            )
        return ""

    def check(url):
        if failure:
            raise RuntimeError("synthetic health failure")

    monkeypatch.setattr(rollout, "run", run)
    monkeypatch.setattr(rollout, "public_checks", check)
    if failure:
        with pytest.raises(RuntimeError, match="synthetic"):
            rollout.main()
        assert (tmp_path / ".env").read_text() == initial
        assert calls[-1][1]["MCP_IMAGE"] == "sha256:previous"
        expected = "rolled_back"
    else:
        rollout.main()
        assert "MCP_IMAGE=pinterest-mcp:git-" + revision in (tmp_path / ".env").read_text()
        assert "PRIVATE_VALUE=test-only" in (tmp_path / ".env").read_text()
        expected = "completed"
    assert json.loads((tmp_path / "rollout-state.json").read_text())["phase"] == expected
    assert (tmp_path / ".env").stat().st_mode & 0o777 == 0o600


def test_rejects_non_https_origin():
    with pytest.raises(ValueError):
        rollout.public_checks("file:///etc/passwd")
