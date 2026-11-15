import io
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml

from cli import main
from guardrails.hook import HookRuntime, adapt_output
from guardrails.integrations import install_hooks
from guardrails.ledger import Ledger
from guardrails.scaffold import scaffold


def runtime(tmp_path: Path, harness: str = "claude") -> HookRuntime:
    scaffold(tmp_path, harness=harness)
    return HookRuntime(
        policy_path=tmp_path / "tools.yaml",
        state_directory=tmp_path / ".pehredaar",
        sandbox_path=tmp_path / "sandbox.yaml",
    )


def test_hook_tracks_prompt_taint_budget_and_audit(tmp_path: Path) -> None:
    hook = runtime(tmp_path)
    common = {"session_id": "session-1", "cwd": str(tmp_path)}
    assert hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "edit src/app.py"}) == {}
    read = {
        **common,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "AGENTS.md")},
    }
    assert hook.handle(read) == {}
    hook.handle({**read, "hook_event_name": "PostToolUse", "tool_response": "untrusted"})
    write = hook.handle(
        {
            **common,
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": str(tmp_path / "src" / "app.py"), "content": "safe"},
        }
    )
    assert write["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "taint_write" in write["hookSpecificOutput"]["permissionDecisionReason"]
    state_files = list((tmp_path / ".pehredaar" / "sessions").glob("*.json"))
    state = json.loads(state_files[0].read_text(encoding="utf-8"))
    assert state["tainted"] is True
    assert state["actions_used"] == 2
    assert Ledger(tmp_path / ".pehredaar" / "ledger.jsonl").verify()


def test_a_new_prompt_starts_a_new_budget_but_keeps_taint(tmp_path: Path) -> None:
    hook = runtime(tmp_path)
    common = {"session_id": "session-3", "cwd": str(tmp_path)}
    hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "read the docs"})
    read = {
        **common,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "AGENTS.md")},
    }
    hook.handle(read)
    hook.handle({**read, "hook_event_name": "PostToolUse", "tool_response": "untrusted"})
    hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "now edit src/app.py"})
    state = json.loads(next((tmp_path / ".pehredaar" / "sessions").glob("*.json")).read_text(encoding="utf-8"))
    assert state["original_request"] == "now edit src/app.py"
    assert state["actions_used"] == 0
    # The earlier tool output is still in the model's context, so the write must still be held.
    assert state["tainted"] is True


def test_hook_denies_unknown_tools_and_disallowed_url(tmp_path: Path) -> None:
    hook = runtime(tmp_path)
    common = {"session_id": "session-2", "cwd": str(tmp_path)}
    hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "read project docs"})
    unknown = hook.handle({**common, "hook_event_name": "PreToolUse", "tool_name": "Unknown", "tool_input": {}})
    assert unknown["hookSpecificOutput"]["permissionDecision"] == "deny"
    web = hook.handle(
        {
            **common,
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://huggingface.co/attacker/model", "prompt": "read"},
        }
    )
    assert web["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "egress_path" in web["hookSpecificOutput"]["permissionDecisionReason"]


def test_hook_cli_fails_closed_on_malformed_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("not-json"))
    assert main(["hook", "--policy", str(tmp_path / "missing.yaml")]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_install_preserves_existing_settings(tmp_path: Path) -> None:
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"permissions": {"deny": ["Read(.env)"]}}\n', encoding="utf-8")
    install_hooks(tmp_path, "claude")
    install_hooks(tmp_path, "claude")
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert settings["permissions"]["deny"] == ["Read(.env)"]
    assert len(settings["hooks"]["PreToolUse"]) == 1


def test_vscode_hook_file_is_owned_and_idempotent(tmp_path: Path) -> None:
    paths = install_hooks(tmp_path, "vscode-local")
    install_hooks(tmp_path, "vscode-local")
    value = json.loads(paths[0].read_text(encoding="utf-8"))
    assert value["x-pehredaar"] == 1
    assert "windows" in value["hooks"]["PreToolUse"][0]


def test_copilot_hook_uses_versioned_contract_and_flat_decision(tmp_path: Path) -> None:
    scaffold(tmp_path, harness="copilot")
    path = tmp_path / ".github" / "hooks" / "pehredaar-copilot.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["version"] == 1
    assert "--harness copilot" in value["hooks"]["PreToolUse"][0]["command"]
    common = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "blocked",
        }
    }
    assert adapt_output(common, "copilot") == {
        "permissionDecision": "deny",
        "permissionDecisionReason": "blocked",
    }
    assert main(["doctor", "--path", str(tmp_path)]) == 0


def test_harness_policy_has_no_todos_for_builtins(tmp_path: Path) -> None:
    scaffold(tmp_path, harness="claude")
    policy = yaml.safe_load((tmp_path / "tools.yaml").read_text(encoding="utf-8"))
    assert policy["tools"]["Bash"]["approval"] == "always"
    assert policy["runtime"]["scopes"] == ["external:read", "repo:read", "repo:write", "shell:execute"]


def test_parallel_hook_calls_cannot_exceed_budget(tmp_path: Path) -> None:
    scaffold(tmp_path, harness="claude")
    policy_path = tmp_path / "tools.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["runtime"]["action_limit"] = 1
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    hook = HookRuntime(policy_path=policy_path, state_directory=tmp_path / ".pehredaar")
    common = {"session_id": "parallel", "cwd": str(tmp_path)}
    hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "read files"})
    event = {
        **common,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "README.md")},
    }
    with ThreadPoolExecutor(max_workers=2) as executor:
        outputs = list(executor.map(lambda _: hook.handle(event), range(2)))
    assert sum(output == {} for output in outputs) == 1
    denied = next(output for output in outputs if output)
    assert "budget" in denied["hookSpecificOutput"]["permissionDecisionReason"]


def test_host_cwd_cannot_widen_policy_roots(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    hook = runtime(project)
    common = {"session_id": "session-cwd", "cwd": str(tmp_path)}
    hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "read the docs"})
    escape = hook.handle(
        {**common, "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "secret.txt"}}
    )
    assert escape["hookSpecificOutput"]["permissionDecision"] == "deny"
    inside = hook.handle(
        {**common, "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "project/a.md"}}
    )
    assert inside == {}


def test_builtin_schemas_accept_vendor_arguments_and_block_glob_escapes(tmp_path: Path) -> None:
    hook = runtime(tmp_path)
    common = {"session_id": "session-glob", "cwd": str(tmp_path)}
    hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "find python files"})

    def pre(tool: str, tool_input: dict[str, object]) -> dict[str, object]:
        return hook.handle({**common, "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input})

    assert pre("Read", {"file_path": str(tmp_path / "a.py"), "offset": 1, "limit": 20}) == {}
    assert pre("Glob", {"pattern": "**/*.py"}) == {}
    assert pre("Grep", {"pattern": "def ", "output_mode": "content", "-n": True}) == {}
    for pattern in ("/etc/*", "../**/*.pem"):
        assert pre("Glob", {"pattern": pattern})["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not (tmp_path / "guardrails").exists()


def test_copilot_runtime_argument_names_are_still_bounded(tmp_path: Path) -> None:
    hook = runtime(tmp_path, harness="copilot")
    common = {"session_id": "session-copilot", "cwd": str(tmp_path)}
    hook.handle({**common, "hook_event_name": "UserPromptSubmit", "prompt": "read the app"})

    def read(path: str) -> dict[str, object]:
        return hook.handle(
            {**common, "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"path": path}}
        )

    assert read(str(tmp_path / "src" / "app.py")) == {}
    assert read("/etc/hosts")["hookSpecificOutput"]["permissionDecision"] == "deny"
