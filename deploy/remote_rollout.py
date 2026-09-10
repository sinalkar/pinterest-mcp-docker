"""Deploy an MCP foundation image on an existing host; keep public access disabled.

Executed over SSH by deploy.sh. No application/Keycloak/database secrets are transferred.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def run(args, *, env=None, capture=False):
    return subprocess.run(  # noqa: S603 -- argv only; fixed docker executable and validated inputs
        args,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    ).stdout


def atomic_write(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".rollout-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def public_checks(url):
    if not re.fullmatch(r"https://[a-zA-Z0-9.-]+", url):
        raise ValueError("Invalid public origin")

    # Use ordinary TLS verification; redirects are rejected as a configuration error.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    client = urllib.request.build_opener(NoRedirect)
    with client.open(url + "/healthz", timeout=15) as response:
        if response.status != 200:
            raise RuntimeError("Public health check failed")
    request = urllib.request.Request(  # noqa: S310 -- HTTPS origin validated above
        url + "/mcp",
        data=b"{}",
        headers={"Content-Type": "application/json"},
    )
    try:
        client.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        if error.code == 401 and error.headers.get("WWW-Authenticate"):
            return
    raise RuntimeError("Public MCP authentication challenge failed")


def main():
    directory, archive, revision, url = sys.argv[1:]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid commit")
    if not re.fullmatch(r"https://[a-zA-Z0-9.-]+", url):
        raise ValueError("Invalid public origin")
    base = Path(directory).resolve(strict=True)
    os.chdir(base)
    if not (base / "compose.yaml").is_file() or not (base / ".env").is_file():
        raise RuntimeError("Existing Compose configuration is required")
    compose = ["docker", "compose", "-f", str(base / "compose.yaml")]
    with (base / ".rollout.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        container = run([*compose, "ps", "-q", "mcp"], capture=True).strip()
        if not container:
            raise RuntimeError("Expected running MCP service was not found")
        details = json.loads(run(["docker", "inspect", container], capture=True))[0]
        previous = details["Image"]  # Immutable local image ID, not a mutable tag.
        config = dict(item.split("=", 1) for item in details["Config"]["Env"] if "=" in item)
        if not config.get("MCP_OAUTH_ALLOWED_SUBJECTS", "").startswith("disabled-"):
            raise RuntimeError("Foundation rollout requires public users to remain disabled")
        if any(
            config.get(key)
            for key in ("MCP_AUTH_TOKEN", "PINTEREST_ACCESS_TOKEN", "PINTEREST_REFRESH_TOKEN")
        ):
            raise RuntimeError("Shared credentials are incompatible with this rollout")
        state_path = base / "rollout-state.json"
        if state_path.exists():
            state = json.loads(state_path.read_text())
            if state.get("phase") == "replacing":
                recovery = os.environ | {"MCP_IMAGE": state["previous_image"]}
                run([*compose, "up", "-d", "--no-deps", "mcp"], env=recovery)
                existing = (base / ".env").read_text().splitlines()
                existing = [line for line in existing if not line.startswith("MCP_IMAGE=")]
                atomic_write(
                    base / ".env",
                    "\n".join([*existing, "MCP_IMAGE=" + state["previous_image"]]) + "\n",
                )
                state["phase"] = "rolled_back"
                atomic_write(state_path, json.dumps(state) + "\n")
                raise RuntimeError("Recovered interrupted rollout; verify health and retry")
        image = "pinterest-mcp:git-" + revision
        with tempfile.TemporaryDirectory(prefix="pinterest-build-") as build:
            with tarfile.open(archive, "r:gz") as source:
                for member in source.getmembers():
                    target = (Path(build) / member.name).resolve()
                    if not target.is_relative_to(Path(build)) or member.issym() or member.islnk():
                        raise RuntimeError("Unsafe source archive")
                    if not (member.isdir() or member.isfile()):
                        raise RuntimeError("Unsupported source archive entry")
                source.extractall(build, filter="data")
            run(
                [
                    "docker",
                    "build",
                    "--label",
                    "org.opencontainers.image.revision=" + revision,
                    "-t",
                    image,
                    build,
                ]
            )
        run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "python3",
                image,
                "-c",
                "import pinterest_mcp.app; import pinterest_mcp.http_app",
            ]
        )
        rollout_env = os.environ | {"MCP_IMAGE": image}
        # Verify the effective candidate configuration without printing secret values.
        effective = json.loads(
            run([*compose, "config", "--format", "json"], env=rollout_env, capture=True)
        )
        candidate = effective["services"]["mcp"]["environment"]
        if candidate.get("MCP_OAUTH_ALLOWED_SUBJECTS") != config["MCP_OAUTH_ALLOWED_SUBJECTS"]:
            raise RuntimeError("Candidate changes the public-user restriction")
        state = {
            "commit": revision,
            "image": image,
            "previous_image": previous,
            "phase": "replacing",
        }
        atomic_write(state_path, json.dumps(state) + "\n")
        old_env = (base / ".env").read_text()
        try:
            run([*compose, "up", "-d", "--no-deps", "mcp"], env=rollout_env)
            for _ in range(60):
                cid = run([*compose, "ps", "-q", "mcp"], env=rollout_env, capture=True).strip()
                health = run(
                    ["docker", "inspect", "--format", "{{.State.Health.Status}}", cid], capture=True
                ).strip()
                if health == "healthy":
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Candidate did not become healthy")
            public_checks(url)
            lines = [line for line in old_env.splitlines() if not line.startswith("MCP_IMAGE=")]
            atomic_write(base / ".env", "\n".join([*lines, "MCP_IMAGE=" + image]) + "\n")
            state["phase"] = "completed"
            atomic_write(state_path, json.dumps(state) + "\n")
        except BaseException:
            atomic_write(base / ".env", old_env)
            run(
                [*compose, "up", "-d", "--no-deps", "mcp"], env=os.environ | {"MCP_IMAGE": previous}
            )
            state["phase"] = "rolled_back"
            atomic_write(state_path, json.dumps(state) + "\n")
            raise
        print("DEPLOYED " + revision + " | health=healthy | MCP=401 | public_users=disabled")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Do not print subprocess output or exception strings containing host credentials.
        print(
            "Deployment failed (" + type(exc).__name__ + "); inspect private host state.",
            file=sys.stderr,
        )
        sys.exit(1)
