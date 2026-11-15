from pathlib import Path
from typing import Any

import pytest

from guardrails.approval import ApprovalStore
from guardrails.budget import Budget
from guardrails.gateway import ActionDenied, ApprovalRequired, ExecutionGateway, RunContext
from guardrails.ledger import Ledger
from guardrails.registry import ArgSpec, ToolSpec
from guardrails.taint import Provenance


def context(*, tainted: bool = False) -> RunContext:
    provenance = Provenance.untrusted_source("issue") if tainted else Provenance.trusted()
    return RunContext(
        "run-1", "user-1", frozenset({"repo:read", "repo:write"}), "write src/app.py", provenance, Budget()
    )


def gateway(tmp_path: Path, spec: ToolSpec) -> ExecutionGateway:
    return ExecutionGateway(
        registry={"write_file": spec},
        workspace=tmp_path,
        ledger=Ledger(tmp_path / "ledger.jsonl"),
        approvals=ApprovalStore(tmp_path / "approvals"),
    )


def test_denied_action_never_dispatches(tmp_path: Path) -> None:
    guard = gateway(tmp_path, ToolSpec("write", {"path": ArgSpec("path")}, "admin", True, "never"))
    calls: list[str] = []
    with pytest.raises(ActionDenied, match="policy.scope"):
        guard.execute(context(), "write_file", {"path": "src/app.py"}, lambda tool, args: calls.append(tool))
    assert calls == []


def test_approval_is_bound_and_consumed_once(tmp_path: Path) -> None:
    guard = gateway(tmp_path, ToolSpec("write", {"path": ArgSpec("path")}, "repo:write", True, "when_tainted"))
    run = context(tainted=True)
    calls: list[dict[str, Any]] = []
    with pytest.raises(ApprovalRequired) as pending:
        guard.execute(
            run, "write_file", {"path": "src/app.py"}, lambda tool, args: calls.append(args), intent_matches=True
        )
    guard.approvals.decide(pending.value.approval_id, approve=True, principal="reviewer")
    guard.execute(run, "write_file", {"path": "src/app.py"}, lambda tool, args: calls.append(args), intent_matches=True)
    assert calls == [{"path": "src/app.py"}]
    run.step = 0
    with pytest.raises(ActionDenied, match="consumed"):
        guard.execute(
            run, "write_file", {"path": "src/app.py"}, lambda tool, args: calls.append(args), intent_matches=True
        )


def test_unregistered_tool_fails_closed(tmp_path: Path) -> None:
    guard = gateway(tmp_path, ToolSpec("read", {}, "repo:read", True, "never"))
    with pytest.raises(ActionDenied, match="unregistered"):
        guard.execute(context(), "shell", {}, lambda tool, args: None)


def test_ledger_names_the_approver_and_budget_is_checked_before_approval_is_spent(tmp_path: Path) -> None:
    guard = gateway(tmp_path, ToolSpec("write", {"path": ArgSpec("path")}, "repo:write", True, "always"))
    run = context()
    run.budget = Budget(action_limit=5, write_limit=0)
    with pytest.raises(ApprovalRequired) as pending:
        guard.execute(run, "write_file", {"path": "src/app.py"}, lambda tool, args: None, intent_matches=True)
    guard.approvals.decide(pending.value.approval_id, approve=True, principal="reviewer:ravi")
    with pytest.raises(ActionDenied, match="budget"):
        guard.execute(run, "write_file", {"path": "src/app.py"}, lambda tool, args: None, intent_matches=True)
    assert guard.approvals.load(pending.value.approval_id).decision == "approved"
    run.budget = Budget()
    guard.execute(run, "write_file", {"path": "src/app.py"}, lambda tool, args: None, intent_matches=True)
    executed = [record for record in guard.ledger.records() if record.decision == "execute"]
    assert executed[-1].decided_by == "reviewer:ravi"
    assert executed[-1].ts


def test_untrusted_output_taints_the_run_and_dispatch_errors_are_recorded(tmp_path: Path) -> None:
    spec = ToolSpec("read", {"path": ArgSpec("path")}, "repo:read", True, "never", output_trust="untrusted")
    guard = gateway(tmp_path, spec)
    run = context()
    guard.execute(run, "write_file", {"path": "README.md"}, lambda tool, args: "issue text", intent_matches=True)
    assert run.provenance.untrusted

    def broken(tool: str, args: dict[str, Any]) -> None:
        raise OSError("disk full")

    with pytest.raises(OSError):
        guard.execute(run, "write_file", {"path": "README.md"}, broken, intent_matches=True)
    assert guard.ledger.records()[-1].rule == "dispatch.error"


def test_gateway_applies_the_egress_profile(tmp_path: Path) -> None:
    spec = ToolSpec("read", {"url": ArgSpec("string")}, "repo:read", True, "never")
    guard = gateway(tmp_path, spec)
    guard.egress_profile = {"egress": {"allow": [{"host": "api.github.com", "paths": ["/repos/*"]}]}}
    guard.execute(
        context(), "write_file", {"url": "https://api.github.com/repos/x"}, lambda t, a: None, intent_matches=True
    )
    with pytest.raises(ActionDenied, match="egress"):
        guard.execute(
            context(), "write_file", {"url": "https://evil.example/x"}, lambda t, a: None, intent_matches=True
        )
