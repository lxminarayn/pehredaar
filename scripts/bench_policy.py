"""Local micro-benchmark behind the latency numbers on the slides. Not a production benchmark.

    uv run python scripts/bench_policy.py

Measures policy.evaluate() alone, and a full ExecutionGateway.execute() including the fsync'd
ledger append and a no-op dispatch. Results depend on the machine and its disk.
"""

from __future__ import annotations

import platform
import tempfile
import time
from pathlib import Path

from guardrails.approval import ApprovalStore
from guardrails.budget import Budget
from guardrails.gateway import ExecutionGateway, RunContext
from guardrails.ledger import Ledger
from guardrails.policy import ActionRequest, evaluate
from guardrails.registry import load_registry
from guardrails.taint import Provenance

ROOT = Path(__file__).resolve().parent.parent
SCOPES = frozenset({"customers:read"})
ARGS = {"customer_id": "CUST-101"}


def main(evaluations: int = 20_000, executions: int = 2_000) -> None:
    registry = load_registry(ROOT / "examples" / "ops_triage" / "tools.yaml")
    request = ActionRequest(
        run_id="bench",
        step=0,
        principal="agent:bench",
        original_request="bench",
        tool="query_customer_db",
        args=ARGS,
        scopes=SCOPES,
        provenance=Provenance.trusted(),
        spec=registry["query_customer_db"],
        workspace=ROOT,
        bindings=(("customer_id", "CUST-101"),),
    )
    start = time.perf_counter()
    for _ in range(evaluations):
        evaluate(request)
    evaluate_us = (time.perf_counter() - start) / evaluations * 1e6

    state = Path(tempfile.mkdtemp(prefix="pehredaar-bench-"))
    gateway = ExecutionGateway(
        registry=registry,
        workspace=state,
        ledger=Ledger(state / "ledger.jsonl"),
        approvals=ApprovalStore(state / "approvals"),
    )
    context = RunContext(
        "bench", "agent:bench", SCOPES, "bench", Provenance.trusted(), Budget(action_limit=executions + 1)
    )
    start = time.perf_counter()
    for _ in range(executions):
        gateway.execute(context, "query_customer_db", ARGS, lambda tool, args: "ok", intent_matches=True)
    execute_ms = (time.perf_counter() - start) / executions * 1e3

    print(f"machine: {platform.platform()} {platform.machine()}  python {platform.python_version()}")
    print(f"policy.evaluate():                       {evaluate_us:8.1f} us/call  ({evaluations} calls)")
    print(f"gateway.execute() incl. fsync'd ledger:  {execute_ms:8.2f} ms/call  ({executions} calls)")
    print(f"ledger intact after run: {gateway.ledger.verify()}")


if __name__ == "__main__":
    main()
