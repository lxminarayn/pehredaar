"""Install verified command-hook configurations without replacing user settings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse")


def builtin_tool_security(name: str) -> tuple[str, bool, str]:
    if name in {"Read", "Glob", "Grep"}:
        return "repo:read", True, "never"
    if name in {"Write", "Edit"}:
        return "repo:write", True, "when_tainted"
    if name in {"Bash", "PowerShell"}:
        return "shell:execute", False, "always"
    if name == "WebFetch":
        return "external:read", True, "never"
    raise ValueError(f"missing built-in security policy for {name}")


def runtime_policy(harness: str, builtin_names: list[str]) -> dict[str, Any]:
    scopes = sorted({builtin_tool_security(name)[0] for name in builtin_names})
    return {
        "principal": f"{harness}-local-user",
        "scopes": scopes,
        "action_limit": 50,
        "write_limit": 10,
        "intent_check": False,
    }


def install_hooks(target: Path, harness: str) -> list[Path]:
    if harness == "claude":
        return [_install_claude(target)]
    if harness == "vscode-local":
        return [_install_vscode_local(target)]
    if harness == "copilot":
        return [_install_copilot(target)]
    if harness == "generic":
        return []
    raise ValueError(f"unsupported harness: {harness}")


def _install_claude(target: Path) -> Path:
    path = target / ".claude" / "settings.json"
    settings = _read_json_object(path)
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{path} hooks must be an object")
    handler = {
        "type": "command",
        "command": "agent-guardrails",
        "args": [
            "hook",
            "--policy",
            "tools.yaml",
            "--state-dir",
            ".pehredaar",
            "--sandbox",
            "sandbox.yaml",
        ],
        "timeout": 10,
    }
    for event in EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f"{path} hooks.{event} must be an array")
        if not _contains_handler(groups):
            # Claude Code 2.1.295+ blocks the tool call when a pre-tool hook crashes or times out.
            failure = {"onFailure": "block"} if event == "PreToolUse" else {}
            groups.append({"hooks": [{**handler, **failure}]})
    _write_json(path, settings)
    return path


def _install_vscode_local(target: Path) -> Path:
    path = target / ".github" / "hooks" / "pehredaar.json"
    if path.exists():
        existing = _read_json_object(path)
        if existing.get("x-pehredaar") != 1:
            raise FileExistsError(f"refusing to replace non-Pehredaar hook file: {path}")
    command = "agent-guardrails hook --policy tools.yaml --state-dir .pehredaar --sandbox sandbox.yaml"
    handler = {"type": "command", "command": command, "windows": command, "timeout": 10}
    value = {"x-pehredaar": 1, "hooks": {event: [handler] for event in EVENTS}}
    _write_json(path, value)
    return path


def _install_copilot(target: Path) -> Path:
    path = target / ".github" / "hooks" / "pehredaar-copilot.json"
    if path.exists():
        existing = _read_json_object(path)
        if existing.get("x-pehredaar") != 1:
            raise FileExistsError(f"refusing to replace non-Pehredaar hook file: {path}")
    command = (
        "agent-guardrails hook --harness copilot --policy tools.yaml --state-dir .pehredaar --sandbox sandbox.yaml"
    )
    handler = {"type": "command", "command": command, "timeoutSec": 10}
    value = {
        "version": 1,
        "x-pehredaar": 1,
        "hooks": {event: [handler] for event in EVENTS},
    }
    _write_json(path, value)
    return path


def harness_tools(harness: str) -> list[tuple[str, str, dict[str, dict[str, Any]], str]]:
    """Built-in tool schemas as (name, description, args, output_trust)."""
    if harness not in {"claude", "vscode-local", "copilot"}:
        raise ValueError(f"unsupported harness: {harness}")
    tools = _claude_tools()
    if harness != "copilot":
        return tools
    # PascalCase event names select Copilot's VS Code-compatible mode: Claude-style tool names and
    # snake_case payloads. Arguments keep runtime names.
    merged = []
    for name, text, args, trust in tools:
        relaxed = {key: {**value, "required": False} for key, value in args.items()}
        merged.append((name, text, {**relaxed, **COPILOT_ARGS.get(name, {})}, trust))
    return merged


def _claude_tools() -> list[tuple[str, str, dict[str, dict[str, Any]], str]]:
    return [
        (
            "Read",
            "Read a workspace file",
            {
                "file_path": _path_arg(),
                "offset": _count_arg(),
                "limit": _count_arg(),
                "pages": {**_string_arg(100), "required": False},
            },
            "untrusted",
        ),
        (
            "Glob",
            "List workspace files by pattern",
            {"pattern": _glob_arg(required=True), "path": {**_path_arg(), "required": False}},
            "trusted",
        ),
        (
            "Grep",
            "Search workspace file contents",
            {
                "pattern": _string_arg(1_000),
                "path": {**_path_arg(), "required": False},
                "glob": _glob_arg(required=False),
                "type": {**_string_arg(50), "required": False},
                "output_mode": {
                    "type": "enum",
                    "required": False,
                    "values": ["content", "files_with_matches", "count"],
                },
                **{flag: {"type": "boolean", "required": False} for flag in ("-i", "-n", "multiline")},
                **{name: _count_arg() for name in ("-A", "-B", "-C", "context", "head_limit", "offset")},
            },
            "untrusted",
        ),
        (
            "Write",
            "Write a workspace file",
            {"file_path": _path_arg(), "content": _string_arg(200_000)},
            "trusted",
        ),
        (
            "Edit",
            "Edit a workspace file",
            {
                "file_path": _path_arg(),
                "old_string": _string_arg(200_000),
                "new_string": _string_arg(200_000),
                "replace_all": {"type": "boolean", "required": False},
            },
            "trusted",
        ),
        (
            "Bash",
            "Run a shell command",
            {
                "command": _string_arg(20_000),
                "description": {**_string_arg(1_000), "required": False},
                "timeout": {"type": "number", "required": False, "minimum": 0},
                "run_in_background": {"type": "boolean", "required": False},
            },
            "trusted",
        ),
        (
            "PowerShell",
            "Run a PowerShell command",
            {
                "command": _string_arg(20_000),
                "description": {**_string_arg(1_000), "required": False},
                "timeout": {"type": "number", "required": False, "minimum": 0},
                "run_in_background": {"type": "boolean", "required": False},
            },
            "trusted",
        ),
        (
            "WebFetch",
            "Fetch untrusted web content",
            {"url": _string_arg(2_048), "prompt": _string_arg(20_000)},
            "untrusted",
        ),
    ]


def _optional(arg: dict[str, Any]) -> dict[str, Any]:
    return {**arg, "required": False}


def _path_arg() -> dict[str, Any]:
    return {"type": "path", "required": True, "root": "."}


def _count_arg() -> dict[str, Any]:
    return {"type": "integer", "required": False, "minimum": 0}


def _glob_arg(*, required: bool) -> dict[str, Any]:
    # Patterns are not paths, so block absolute and parent segments explicitly.
    return {"type": "string", "required": required, "max_length": 1_000, "pattern": r"(?!/)(?!.*\.\.)[^\\]*"}


def _string_arg(max_length: int) -> dict[str, Any]:
    return {"type": "string", "required": True, "max_length": max_length}


def _contains_handler(groups: list[Any]) -> bool:
    for group in groups:
        if not isinstance(group, dict):
            continue
        handlers = group.get("hooks", [])
        if any(isinstance(item, dict) and item.get("command") == "agent-guardrails" for item in handlers):
            return True
    return False


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


LIMITATIONS = (
    "Hook schemas are verified for Claude Code, VS Code Local, and GitHub Copilot; Codex needs a separate adapter.",
)


COPILOT_ARGS: dict[str, dict[str, dict[str, Any]]] = {
    "Read": {"path": _optional(_path_arg()), "forceReadLargeFiles": {"type": "boolean", "required": False}},
    "Write": {"path": _optional(_path_arg()), "file_text": _optional(_string_arg(200_000))},
    "Edit": {
        "path": _optional(_path_arg()),
        "old_str": _optional(_string_arg(200_000)),
        "new_str": _optional(_string_arg(200_000)),
    },
    "Bash": {
        "mode": {"type": "enum", "required": False, "values": ["sync", "async"]},
        "initial_wait": {"type": "number", "required": False, "minimum": 0},
        "shellId": _optional(_string_arg(100)),
        "detach": {"type": "boolean", "required": False},
    },
    "Grep": {"paths": _optional(_path_arg())},
    "Glob": {"paths": _optional(_path_arg())},
    "WebFetch": {
        "max_length": {"type": "integer", "required": False, "minimum": 0},
        "raw": {"type": "boolean", "required": False},
        "start_index": {"type": "integer", "required": False, "minimum": 0},
    },
}
