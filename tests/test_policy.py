from pathlib import Path

from guardrails.policy import ActionRequest, Verdict, evaluate
from guardrails.registry import ArgSpec, ToolSpec, validate_args
from guardrails.taint import Provenance, taint


def request_for(spec: ToolSpec, **overrides: object) -> ActionRequest:
    values: dict[str, object] = {
        "run_id": "test-run",
        "step": 1,
        "principal": "speaker",
        "original_request": "read src/app.py",
        "tool": "read_file",
        "args": {"path": "src/app.py"},
        "scopes": frozenset({spec.scope}),
        "provenance": Provenance.trusted(),
        "spec": spec,
        "workspace": Path.cwd(),
    }
    values.update(overrides)
    return ActionRequest(**values)  # type: ignore[arg-type]


def test_direct_call_is_denied_without_scope() -> None:
    spec = ToolSpec("read", {"path": ArgSpec("path")}, "repo:read", True, "never")
    decision = evaluate(request_for(spec, scopes=frozenset()))
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "policy.scope"


def test_tainted_write_requires_approval() -> None:
    spec = ToolSpec("write", {"body": ArgSpec("string")}, "external:write", True, "when_tainted")
    decision = evaluate(
        request_for(
            spec,
            tool="post_comment",
            args={"body": taint("send data", "issue_body")},
            provenance=Provenance.untrusted_source("issue_body"),
        )
    )
    assert decision.verdict is Verdict.ASK
    assert decision.rule_id == "policy.taint_write"


def test_symlink_escape_is_denied(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "link").symlink_to(outside, target_is_directory=True)
    spec = ToolSpec("read", {"path": ArgSpec("path")}, "repo:read", True, "never")
    decision = evaluate(request_for(spec, workspace=workspace, args={"path": "link/secret"}))
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "policy.arguments"


def test_missing_provenance_never_allows() -> None:
    spec = ToolSpec("read", {}, "repo:read", True, "never")
    assert evaluate(request_for(spec, args={}, provenance=None)).verdict is not Verdict.ALLOW


def test_non_finite_numbers_cannot_slip_past_bounds() -> None:
    spec = ToolSpec("write", {"amount": ArgSpec("number", maximum=500)}, "refunds:write", True, "never")
    for value in (float("nan"), float("inf"), float("-inf")):
        assert validate_args(spec, {"amount": value}, Path.cwd()) == "argument amount must be a finite number"
    assert validate_args(spec, {"amount": 12.5}, Path.cwd()) is None
    assert validate_args(spec, {"amount": 501}, Path.cwd()) is not None


def test_boolean_is_not_an_integer() -> None:
    spec = ToolSpec("read", {"count": ArgSpec("integer")}, "repo:read", True, "never")
    decision = evaluate(request_for(spec, args={"count": True}))
    assert decision.verdict is Verdict.DENY


def test_path_can_be_bounded_to_multiple_roots(tmp_path: Path) -> None:
    for directory in ("src", ".github/seed", "secrets"):
        (tmp_path / directory).mkdir(parents=True)
    spec = ToolSpec("read", {"path": ArgSpec("path", roots=("src", ".github/seed"))}, "repo:read", True, "never")
    assert evaluate(request_for(spec, workspace=tmp_path, args={"path": "src/app.py"})).verdict is Verdict.ALLOW
    assert (
        evaluate(request_for(spec, workspace=tmp_path, args={"path": ".github/seed/issue.md"})).verdict is Verdict.ALLOW
    )
    assert evaluate(request_for(spec, workspace=tmp_path, args={"path": "secrets/key"})).verdict is Verdict.DENY


def test_string_pattern_uses_full_match() -> None:
    spec = ToolSpec("read", {"branch": ArgSpec("string", pattern=r"agent/[a-z0-9-]+")}, "repo:read", True, "never")
    assert evaluate(request_for(spec, args={"branch": "agent/fix-1043"})).verdict is Verdict.ALLOW
    assert evaluate(request_for(spec, args={"branch": "x-agent/fix-1043"})).verdict is Verdict.DENY


def test_trifecta_blocks_untrusted_sensitive_egress() -> None:
    from guardrails.policy import ActionRequest, Verdict, evaluate
    from guardrails.registry import ArgSpec, ToolSpec
    from guardrails.taint import Provenance

    spec = ToolSpec("write", {"code": ArgSpec("string")}, "run", True, "never", egress=True)
    provenance = Provenance(("ticket", "db"), untrusted=True, sensitive=True)
    request = ActionRequest(
        "r",
        0,
        "p",
        "triage ticket",
        "run_diagnostic_script",
        {"code": "x"},
        frozenset({"run"}),
        provenance,
        spec,
        Path.cwd(),
    )
    decision = evaluate(request)
    assert decision.verdict is Verdict.DENY and decision.rule_id == "policy.trifecta"


def test_ask_above_threshold_requires_approval() -> None:
    from guardrails.policy import ActionRequest, Verdict, evaluate
    from guardrails.registry import ArgSpec, ToolSpec
    from guardrails.taint import Provenance

    spec = ToolSpec("write", {"amount": ArgSpec("number", ask_above=50, maximum=500)}, "refunds", True, "never")
    request = ActionRequest(
        "r",
        0,
        "p",
        "refund the charge",
        "issue_refund",
        {"amount": 120},
        frozenset({"refunds"}),
        Provenance.trusted(),
        spec,
        Path.cwd(),
    )
    assert evaluate(request).verdict is Verdict.ASK
