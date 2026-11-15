"""Sandbox profile loading, path-level egress checks, and runtime detection."""

from __future__ import annotations

import ast
import fnmatch
import posixpath
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml


def load_profile(path: str | Path) -> dict[str, Any]:
    profile = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    for rule in profile.get("egress", {}).get("allow", []):
        # A bare hostname also allows attacker-controlled paths on shared hosts.
        if not rule.get("paths"):
            raise ValueError(f"egress rule for {rule.get('host')} must list explicit paths")
    return dict(profile)


def egress_allowed(url: str, profile: dict[str, Any]) -> bool:
    """Default deny. Match scheme, exact host, and a path pattern."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.username is not None or parts.password is not None or parts.fragment:
        return False
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return False
    decoded_path = unquote(parts.path)
    if "\x00" in decoded_path or "\\" in decoded_path:
        return False
    canonical_path = posixpath.normpath("/" + decoded_path.lstrip("/"))
    egress = profile.get("egress", {})
    for rule in egress.get("allow", []):
        expected_scheme = rule.get("scheme", "https")
        default_port = 443 if expected_scheme == "https" else 80
        expected_port = rule.get("port", default_port)
        actual_port = port or (443 if parts.scheme == "https" else 80)
        host_ok = (
            parts.scheme == expected_scheme
            and parts.hostname.lower() == str(rule.get("host", "")).lower()
            and actual_port == expected_port
        )
        if host_ok and any(fnmatch.fnmatchcase(canonical_path, pattern) for pattern in rule["paths"]):
            return True
    return False


def detect_runtime() -> str:
    for name in ("runsc", "docker", "podman"):
        if shutil.which(name):
            return name
    return "none"


def runtime_banner() -> str:
    runtime = detect_runtime()
    if runtime == "none":
        return (
            "WARNING: no container runtime found. In-process isolation is a teaching "
            "approximation and not a security boundary."
        )
    return f"runtime: {runtime} available (see templates/sandbox.yaml for profiles)"


BLOCKED_MODULES = frozenset(
    {"os", "subprocess", "socket", "urllib", "http", "requests", "shutil", "sys", "ctypes", "importlib", "pathlib"}
)
BLOCKED_CALLS = frozenset({"__import__", "eval", "exec", "compile", "open", "getattr"})
# Caps what the agent sees back. It does not cap what the container writes; --memory and --pids-limit do that.
OUTPUT_LIMIT = 4_000
CONTAINER_FLAGS = (
    "--rm",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=16",
    "--memory=64m",
    "--cpus=0.5",
    "--user=65534:65534",
)


def static_gate(code: str) -> str | None:
    """Cheap pre-filter for obvious host access. Bypassable by design; the container is the boundary."""
    try:
        tree = ast.parse(code)
    except SyntaxError as error:
        return f"syntax error: {error.msg}"
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in BLOCKED_CALLS:
            return f"call to {node.func.id} is not allowed"
        for module in modules:
            if module.split(".")[0] in BLOCKED_MODULES:
                return f"import of {module} is not allowed"
    return None


def run_python(code: str, *, image: str, timeout: float = 30.0, runtime: str | None = None) -> str:
    """Run untrusted Python in a throwaway container with no network, no env, and a read-only root."""
    engine = shutil.which("docker") or shutil.which("podman")
    if engine is None:
        raise RuntimeError("no container engine; refusing to run generated code on the host")
    extra = [f"--runtime={runtime}"] if runtime else []
    name = f"pehredaar-{uuid.uuid4().hex[:12]}"
    command = [engine, "run", "--name", name, *CONTAINER_FLAGS, *extra, image, "python3", "-I", "-c", code]
    try:
        result = subprocess.run(  # noqa: S603  # argv list, no shell
            command, capture_output=True, check=False, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        # Killing the client does not stop the container, so remove it by name.
        subprocess.run([engine, "rm", "-f", name], capture_output=True, check=False, timeout=30)  # noqa: S603
        raise RuntimeError(f"container exceeded {timeout:g}s and was removed") from None
    if result.returncode == 125:
        raise RuntimeError(f"container engine failed: {result.stderr.strip()[:200]}")
    output = (result.stdout + result.stderr).strip()
    if len(output) > OUTPUT_LIMIT:
        return output[:OUTPUT_LIMIT] + "\n[output truncated]"
    return output


LIMITATIONS = (
    "In-process egress checks only cover code that routes through them; use a container for a real boundary.",
    "Containers share the host kernel; use gVisor (runtime='runsc') or a microVM for hostile code.",
)
