"""Enforced transaction boundary for agent tool side effects."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from guardrails.approval import ApprovalRequest, ApprovalStore
from guardrails.budget import Budget
from guardrails.intent_check import matches_original_intent
from guardrails.ledger import Ledger
from guardrails.policy import ActionRequest, Decision, Verdict, apply_egress, evaluate
from guardrails.registry import ToolSpec
from guardrails.taint import Provenance


class ActionDenied(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(f"{decision.rule_id}: {decision.rationale}")
        self.decision = decision


class ApprovalRequired(PermissionError):
    def __init__(self, approval_id: str, decision: Decision) -> None:
        super().__init__(f"approval {approval_id} required: {decision.rationale}")
        self.approval_id = approval_id
        self.decision = decision


@dataclass(frozen=True)
class Check:
    """A deterministic per-tool predicate; `test` returns a denial reason or None."""

    rule: str
    asi: tuple[str, ...]
    test: Callable[[dict[str, Any]], str | None]


@dataclass
class RunContext:
    run_id: str
    principal: str
    scopes: frozenset[str]
    original_request: str
    provenance: Provenance
    budget: Budget
    step: int = 0
    bindings: dict[str, str] = field(default_factory=dict)


class ExecutionGateway:
    """Evaluate and dispatch one action without a check-to-use gap in application code."""

    def __init__(
        self,
        *,
        registry: dict[str, ToolSpec],
        workspace: Path,
        ledger: Ledger,
        approvals: ApprovalStore,
        egress_profile: dict[str, Any] | None = None,
        checks: Mapping[str, Check] | None = None,
    ) -> None:
        self.registry = registry
        self.workspace = workspace.resolve()
        self.ledger = ledger
        self.approvals = approvals
        self.egress_profile = egress_profile
        self.checks = dict(checks or {})

    def execute(
        self,
        context: RunContext,
        tool: str,
        args: dict[str, Any],
        dispatch: Callable[[str, dict[str, Any]], Any],
        *,
        literal_diff: str = "",
        destination: str = "",
        intent_matches: bool | None = None,
    ) -> Any:
        spec = self.registry.get(tool)
        if spec is None:
            self._deny(context, tool, args, "policy.unregistered_tool", "Tool is not registered.")
        intent = (
            matches_original_intent(context.original_request, tool, args) if intent_matches is None else intent_matches
        )
        decision = evaluate(
            ActionRequest(
                run_id=context.run_id,
                step=context.step,
                principal=context.principal,
                original_request=context.original_request,
                tool=tool,
                args=args,
                scopes=context.scopes,
                provenance=context.provenance,
                spec=spec,
                workspace=self.workspace,
                actions_used=context.budget.actions_used,
                action_limit=context.budget.action_limit,
                intent_matches=intent,
                bindings=tuple(sorted(context.bindings.items())),
            )
        )
        decision = apply_egress(decision, args, self.egress_profile)
        check = self.checks.get(tool)
        if check and decision.verdict is not Verdict.DENY and (reason := check.test(args)):
            decision = Decision(Verdict.DENY, check.rule, reason, check.asi, decision.evidence_ref)
        if decision.verdict in {Verdict.DENY, Verdict.TRANSFORM}:
            self._record(context, tool, args, decision, "deny")
            raise ActionDenied(decision)
        approver = "policy"
        approval_id = ""
        if decision.verdict is Verdict.ASK:
            approval_id = _approval_id(context, tool, args)
            approver = self._approved_by(
                approval_id, context, tool, args, decision, literal_diff=literal_diff, destination=destination
            )
        if not context.budget.consume(write=spec.effect == "write"):
            self._deny(context, tool, args, "policy.budget", "Run budget exhausted.")
        if approval_id:
            self.approvals.consume(approval_id)
        self._record(context, tool, args, decision, "execute", decided_by=approver)
        context.step += 1
        try:
            result = dispatch(tool, args)
        except Exception as error:
            failure = Decision(decision.verdict, "dispatch.error", type(error).__name__, (), _ref(context))
            self._record(context, tool, args, failure, "error", decided_by=approver)
            raise
        context.provenance = context.provenance.after_output(tool, spec.output_trust)
        return result

    def _approved_by(
        self,
        approval_id: str,
        context: RunContext,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
        *,
        literal_diff: str,
        destination: str,
    ) -> str:
        """Return the approving principal, or suspend the run until a person decides."""
        try:
            approval = self.approvals.load(approval_id)
        except FileNotFoundError:
            self.approvals.gate(ApprovalRequest(approval_id, context.run_id, tool, args, destination, literal_diff))
            self._record(context, tool, args, decision, "suspend")
            raise ApprovalRequired(approval_id, decision) from None
        if approval.decision == "approved" and approval.decided_by:
            return approval.decided_by
        self._record(context, tool, args, decision, approval.decision)
        if approval.decision == "pending":
            raise ApprovalRequired(approval_id, decision)
        raise ActionDenied(
            Decision(
                Verdict.DENY,
                "approval.unavailable",
                f"Approval is {approval.decision}.",
                decision.asi_refs,
                decision.evidence_ref,
            )
        )

    def _deny(self, context: RunContext, tool: str, args: dict[str, Any], rule: str, rationale: str) -> NoReturn:
        decision = Decision(Verdict.DENY, rule, rationale, ("ASI02",), _ref(context))
        self._record(context, tool, args, decision, "deny")
        raise ActionDenied(decision)

    def _record(
        self,
        context: RunContext,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
        outcome: str,
        *,
        decided_by: str = "policy",
    ) -> None:
        self.ledger.append(
            args=args,
            run=context.run_id,
            step=context.step,
            principal=context.principal,
            tool=tool,
            provenance=context.provenance.origins,
            taint=context.provenance.labels,
            verdict=decision.verdict.value,
            rule=decision.rule_id,
            asi=decision.asi_refs,
            rationale=decision.rationale,
            decided_by=decided_by,
            decision=outcome,
        )


def _approval_id(context: RunContext, tool: str, args: dict[str, Any]) -> str:
    value = json.dumps([context.run_id, context.step, tool, args], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def _ref(context: RunContext) -> str:
    return f"{context.run_id}:{context.step}"


LIMITATIONS = (
    "Dispatchers must expose every side effect through this gateway; subprocesses can create unobserved effects.",
)
