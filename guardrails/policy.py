"""Deterministic execution-time authorisation. Model calls do not belong here."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from guardrails.registry import ToolSpec, exceeds_threshold, validate_args
from guardrails.sandbox import egress_allowed
from guardrails.taint import Provenance, is_tainted

URL_ARGUMENTS = ("url", "destination")


class Verdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK = "ASK"
    TRANSFORM = "TRANSFORM"


@dataclass(frozen=True)
class ActionRequest:
    run_id: str
    step: int
    principal: str
    original_request: str
    tool: str
    args: dict[str, Any]
    scopes: frozenset[str]
    provenance: Provenance | None
    spec: ToolSpec
    workspace: Path
    cwd: Path | None = None
    bindings: tuple[tuple[str, str], ...] = ()
    actions_used: int = 0
    action_limit: int = 20
    intent_matches: bool = True


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    rule_id: str
    rationale: str
    asi_refs: tuple[str, ...]
    evidence_ref: str


def _decision(
    verdict: Verdict,
    rule_id: str,
    rationale: str,
    asi_refs: tuple[str, ...],
    request: ActionRequest,
) -> Decision:
    return Decision(verdict, rule_id, rationale, asi_refs, f"{request.run_id}:{request.step}")


def evaluate(request: ActionRequest) -> Decision:
    """Authorise a proposed action immediately before execution, failing closed."""
    try:
        if request.provenance is None:
            return _decision(Verdict.ASK, "policy.provenance_missing", "Provenance is required.", ("ASI01",), request)
        if not request.principal.strip():
            return _decision(Verdict.DENY, "policy.identity", "A principal is required.", ("ASI03",), request)
        if request.spec.scope not in request.scopes:
            return _decision(
                Verdict.DENY, "policy.scope", f"Principal lacks {request.spec.scope}.", ("ASI03",), request
            )
        argument_error = validate_args(request.spec, request.args, request.workspace, cwd=request.cwd)
        if argument_error:
            return _decision(Verdict.DENY, "policy.arguments", argument_error, ("ASI02",), request)
        for name, bound in request.bindings:
            if name in request.args and request.args[name] != bound:
                return _decision(
                    Verdict.DENY,
                    "policy.capsule",
                    f"argument {name} differs from the value bound at turn 0.",
                    ("ASI01", "ASI03"),
                    request,
                )
        if request.actions_used >= request.action_limit:
            return _decision(Verdict.DENY, "policy.budget", "Action budget exhausted.", ("ASI02",), request)
        if not request.intent_matches:
            # The intent check is a signal, not a verdict. Off-task writes are denied;
            # off-task reads go to a person, since reading context is often legitimate.
            verdict = Verdict.DENY if request.spec.effect == "write" else Verdict.ASK
            return _decision(
                verdict, "policy.intent", "Action does not match the original request.", ("ASI01",), request
            )
        tainted = request.provenance.untrusted or is_tainted(request.args)
        if request.spec.egress and tainted and request.provenance.sensitive:
            return _decision(
                Verdict.DENY,
                "policy.trifecta",
                "Untrusted input and sensitive data cannot reach an egress tool in one run.",
                ("ASI01", "ASI02"),
                request,
            )
        if request.spec.effect == "write" and tainted:
            return _decision(
                Verdict.ASK,
                "policy.taint_write",
                "Untrusted data is crossing a write boundary.",
                ("ASI01", "ASI02"),
                request,
            )
        if request.spec.approval == "always":
            return _decision(
                Verdict.ASK, "policy.approval_always", "This tool always requires approval.", ("ASI02",), request
            )
        if request.spec.approval == "when_tainted" and tainted:
            return _decision(
                Verdict.ASK, "policy.approval_tainted", "Tainted input requires approval.", ("ASI01",), request
            )
        if threshold := exceeds_threshold(request.spec, request.args):
            return _decision(Verdict.ASK, "policy.threshold", threshold, ("ASI02", "ASI09"), request)
        if request.spec.effect == "write" and not request.spec.reversible:
            return _decision(
                Verdict.ASK, "policy.irreversible", "Irreversible writes require approval.", ("ASI02",), request
            )
        return _decision(Verdict.ALLOW, "policy.allow", "All deterministic checks passed.", (), request)
    except Exception:
        return _decision(Verdict.DENY, "policy.internal_error", "Policy evaluation failed closed.", ("ASI02",), request)


def apply_egress(decision: Decision, args: dict[str, Any], profile: dict[str, Any] | None) -> Decision:
    """Deny any URL argument that the path-scoped egress profile does not allow."""
    if decision.verdict is Verdict.DENY or profile is None:
        return decision
    for name in URL_ARGUMENTS:
        value = args.get(name)
        if isinstance(value, str) and not egress_allowed(value, profile):
            return Decision(
                Verdict.DENY,
                "sandbox.egress_path",
                f"{name} is not on the path-scoped egress allowlist.",
                ("ASI02",),
                decision.evidence_ref,
            )
    return decision


LIMITATIONS = ("Policy correctness depends on complete tool schemas and adapters enforcing every side effect.",)
