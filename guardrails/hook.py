"""Command-hook adapter for runtimes with a pre-tool interception point."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from guardrails._locking import file_lock, private_file
from guardrails.intent_check import matches_original_intent
from guardrails.ledger import Ledger
from guardrails.policy import ActionRequest, Decision, Verdict, apply_egress, evaluate
from guardrails.registry import ToolSpec, load_registry
from guardrails.sandbox import load_profile
from guardrails.taint import Provenance


@dataclass
class HookState:
    original_request: str = ""
    actions_used: int = 0
    writes_used: int = 0
    tainted: bool = False
    sensitive: bool = False
    origins: tuple[str, ...] = ("user_request",)


class HookRuntime:
    def __init__(
        self,
        *,
        policy_path: Path,
        state_directory: Path,
        sandbox_path: Path | None = None,
    ) -> None:
        self.policy_path = policy_path.resolve()
        self.workspace = self.policy_path.parent
        self.state_directory = state_directory.resolve()
        self.registry = load_registry(self.policy_path)
        self.runtime = _runtime_config(self.policy_path)
        self.profile = load_profile(sandbox_path) if sandbox_path else None
        self.ledger = Ledger(self.state_directory / "ledger.jsonl")

    def handle(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = payload.get("hook_event_name")
        session_id = payload.get("session_id")
        if not isinstance(event, str) or not isinstance(session_id, str) or not session_id:
            return decision_output(Verdict.DENY, "Malformed hook input: event and session_id are required.")
        if event == "UserPromptSubmit":
            prompt = payload.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                return decision_output(Verdict.DENY, "A non-empty original request is required.")
            self._update(session_id, lambda state: new_prompt(state, prompt))
            return {}
        if event == "PostToolUse":
            self._observe_output(session_id, payload)
            return {}
        if event != "PreToolUse":
            return {}
        return self._authorize(session_id, payload)

    def _authorize(self, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        tool = payload.get("tool_name")
        args = payload.get("tool_input")
        if not isinstance(tool, str) or not isinstance(args, dict):
            return decision_output(Verdict.DENY, "Malformed tool call.")
        spec = self.registry.get(tool)
        state_path = self._state_path(session_id)
        with file_lock(state_path.with_suffix(".lock")):
            state = self._load_unlocked(state_path)
            decision = self._decide(session_id, state, tool, args, spec, payload)
            if decision.verdict is not Verdict.DENY:
                reserve(state, spec.effect == "write" if spec else False)
                write_atomic(state_path, asdict(state))
        principal = str(self.runtime.get("principal", "local-user"))
        self._record(session_id, state, principal, tool, args, decision)
        return decision_output(decision.verdict, f"{decision.rule_id}: {decision.rationale}")

    def _decide(
        self,
        session_id: str,
        state: HookState,
        tool: str,
        args: dict[str, Any],
        spec: ToolSpec | None,
        payload: dict[str, Any],
    ) -> Decision:
        reference = f"{session_id}:{state.actions_used}"
        if spec is None:
            return Decision(
                Verdict.DENY,
                "policy.unregistered_tool",
                f"Tool {tool} is not registered in tools.yaml.",
                ("ASI02",),
                reference,
            )
        if not state.original_request:
            return Decision(
                Verdict.ASK,
                "policy.original_request_missing",
                "Original request was not captured; ask the user.",
                ("ASI01",),
                reference,
            )
        if spec.effect == "write" and state.writes_used >= int(self.runtime.get("write_limit", 10)):
            return Decision(
                Verdict.DENY,
                "policy.write_budget",
                "Write budget exhausted.",
                ("ASI02",),
                reference,
            )
        use_intent = bool(self.runtime.get("intent_check", False))
        intent_matches = not use_intent or matches_original_intent(state.original_request, tool, args)
        decision = evaluate(
            ActionRequest(
                run_id=session_id,
                step=state.actions_used,
                principal=str(self.runtime.get("principal", "local-user")),
                original_request=state.original_request,
                tool=tool,
                args=args,
                scopes=frozenset(map(str, self.runtime.get("scopes", ()))),
                provenance=Provenance(state.origins, state.tainted, state.sensitive),
                spec=spec,
                workspace=self.workspace,
                cwd=Path(str(payload.get("cwd", self.workspace))).resolve(),
                actions_used=state.actions_used,
                action_limit=int(self.runtime.get("action_limit", 50)),
                intent_matches=intent_matches,
            )
        )
        return apply_egress(decision, args, self.profile)

    def _observe_output(self, session_id: str, payload: dict[str, Any]) -> None:
        tool = payload.get("tool_name")
        spec = self.registry.get(str(tool))
        if spec and spec.output_trust != "trusted":
            self._update(session_id, lambda state: mark_output(state, str(tool), spec.output_trust))

    def _record(
        self,
        session_id: str,
        state: HookState,
        principal: str,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
    ) -> None:
        self.ledger.append(
            args=args,
            run=session_id,
            step=state.actions_used,
            principal=principal,
            tool=tool,
            provenance=state.origins,
            taint=Provenance(state.origins, state.tainted, state.sensitive).labels,
            verdict=decision.verdict.value,
            rule=decision.rule_id,
            asi=decision.asi_refs,
            rationale=decision.rationale,
            decided_by="policy",
            decision="continue" if decision.verdict is Verdict.ALLOW else decision.verdict.value.lower(),
        )

    def _state_path(self, session_id: str) -> Path:
        name = hashlib.sha256(session_id.encode()).hexdigest()[:32]
        return self.state_directory / "sessions" / f"{name}.json"

    def _load_unlocked(self, path: Path) -> HookState:
        if not path.exists():
            return HookState()
        return HookState(**json.loads(path.read_text(encoding="utf-8")))

    def _update(self, session_id: str, update: Any) -> HookState:
        path = self._state_path(session_id)
        with file_lock(path.with_suffix(".lock")):
            current = self._load_unlocked(path)
            updated: HookState = update(current)
            write_atomic(path, asdict(updated))
            return updated


def _runtime_config(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    runtime = raw.get("runtime", {}) if isinstance(raw, dict) else {}
    if not isinstance(runtime, dict):
        raise ValueError("tools.yaml runtime must be a mapping")
    scopes = runtime.get("scopes", ())
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        raise ValueError("tools.yaml runtime.scopes must be a list of strings")
    return runtime


def decision_output(verdict: Verdict, reason: str) -> dict[str, Any]:
    if verdict is Verdict.ALLOW:
        return {}
    decision = "ask" if verdict is Verdict.ASK else "deny"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def adapt_output(output: dict[str, Any], harness: str) -> dict[str, Any]:
    if harness != "copilot" or "hookSpecificOutput" not in output:
        return output
    specific = output["hookSpecificOutput"]
    if not isinstance(specific, dict) or "permissionDecision" not in specific:
        return output
    return {
        "permissionDecision": specific["permissionDecision"],
        "permissionDecisionReason": specific.get("permissionDecisionReason", "Pehredaar policy decision"),
    }


def new_prompt(state: HookState, prompt: str) -> HookState:
    """Start a new task budget. Earlier tool output can still sit in the model's context, so taint stays."""
    return HookState(
        original_request=prompt,
        tainted=state.tainted,
        sensitive=state.sensitive,
        origins=state.origins,
    )


def reserve(state: HookState, write: bool) -> HookState:
    state.actions_used += 1
    state.writes_used += int(write)
    return state


def mark_output(state: HookState, origin: str, trust: str) -> HookState:
    state.tainted |= trust == "untrusted"
    state.sensitive |= trust == "sensitive"
    state.origins = tuple(dict.fromkeys((*state.origins, origin)))
    return state


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        private_file(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


LIMITATIONS = (
    "Command-hook timeouts and startup failures can fail open in the host; "
    "use managed vendor policies for hard enforcement.",
)
