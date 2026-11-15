import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from guardrails.approval import ApprovalRequest, ApprovalStore
from guardrails.identity import RunIdentity, issue, verify
from guardrails.ledger import Ledger
from guardrails.registry import load_registry


def test_template_registry_loads() -> None:
    registry = load_registry("templates/tools.yaml")
    assert registry["export_http"].approval == "always"


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("effect", "execute", "effect"),
        ("approval", "sometimes", "approval"),
        ("reversible", "false", "reversible"),
    ],
)
def test_registry_rejects_invalid_security_fields(tmp_path: Path, field: str, value: object, error: str) -> None:
    policy = {
        "tools": {
            "unsafe": {
                "effect": "read",
                "args": {},
                "scope": "repo:read",
                "reversible": True,
                "approval": "never",
                field: value,
            }
        }
    }
    path = tmp_path / "tools.yaml"
    import yaml

    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        load_registry(path)


def test_run_token_rejects_tampering_and_expiry() -> None:
    key = b"FAKE-DO-NOT-USE-test-signing-key-32-bytes"
    token = issue(RunIdentity("user-1", frozenset({"repo:read"}), 100), key)
    assert verify(token, key, now=99).principal == "user-1"
    with pytest.raises(ValueError, match="signature"):
        verify(token + "x", key, now=99)
    with pytest.raises(ValueError, match="expired"):
        verify(token, key, now=100)
    with pytest.raises(ValueError, match="32 bytes"):
        issue(RunIdentity("user-1", frozenset(), 100), b"short")


def test_ledger_detects_tampering(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    fields = {
        "run": "run-1",
        "step": 1,
        "principal": "user-1",
        "tool": "read_file",
        "provenance": ("user_request",),
        "verdict": "ALLOW",
        "rule": "policy.allow",
        "asi": (),
        "rationale": "checks passed",
        "decided_by": "policy",
        "decision": "execute",
    }
    ledger.append(args={"path": "README.md"}, **fields)
    assert ledger.verify()
    raw = ledger.path.read_text(encoding="utf-8").replace("checks passed", "checks bypassed")
    ledger.path.write_text(raw, encoding="utf-8")
    assert not ledger.verify()
    ledger.path.write_text("not-json\n", encoding="utf-8")
    assert not ledger.verify()


def test_approval_persists_across_instances(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    request = ApprovalRequest("approval-1", "run-1", "write_file", {"path": "a"}, "a", "+literal")
    store.gate(request)
    assert "Literal diff" in ApprovalStore(tmp_path).render("approval-1")
    ApprovalStore(tmp_path).decide("approval-1", approve=True, principal="reviewer")
    assert ApprovalStore(tmp_path).resume("approval-1")
    assert json.loads((tmp_path / "approval-1.json").read_text())["decided_by"] == "reviewer"


def test_approval_decision_and_consumption_are_single_use(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    store.gate(ApprovalRequest("approval-race", "run-1", "write_file", {}, "a", "+literal"))
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(store.decide, "approval-race", approve=value, principal=f"reviewer-{value}")
            for value in (True, False)
        ]
    assert sum(future.exception() is None for future in futures) == 1
    if store.load("approval-race").decision == "approved":
        assert store.consume("approval-race").decision == "consumed"
        with pytest.raises(ValueError, match="not available"):
            store.consume("approval-race")


def test_concurrent_ledger_appends_preserve_chain(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    fields = {
        "run": "run-1",
        "principal": "user-1",
        "tool": "read_file",
        "provenance": (),
        "verdict": "ALLOW",
        "rule": "policy.allow",
        "asi": (),
        "rationale": "passed",
        "decided_by": "policy",
        "decision": "execute",
    }
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(ledger.append, args={"index": index}, step=index, **fields) for index in range(20)]
        for future in futures:
            future.result()
    assert len(ledger.records()) == 20
    assert ledger.verify()


def test_intent_capsule_binding_travels_in_the_run_token() -> None:
    from guardrails.identity import RunIdentity, issue, verify

    key = b"k" * 32
    token = issue(RunIdentity("agent", frozenset({"refunds:write"}), 100, {"customer_id": "CUST-101"}), key)
    assert verify(token, key, now=99).bindings == {"customer_id": "CUST-101"}


def test_ledger_records_taint_labels_and_timestamp(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    fields = dict(
        run="r",
        step=0,
        principal="p",
        tool="read",
        provenance=("issue",),
        taint=("untrusted", "sensitive"),
        verdict="ALLOW",
        rule="policy.allow",
        asi=(),
        rationale="ok",
        decided_by="policy",
        decision="execute",
    )
    record = ledger.append(args={}, **fields)
    assert record.taint == ("untrusted", "sensitive")
    assert record.ts and ledger.verify()
