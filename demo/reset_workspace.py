"""Restore files mutated by the deterministic talk demo."""

import shutil
from pathlib import Path

WORKSPACE = Path(__file__).parent / "workspace"
BILLING = '''from decimal import Decimal


def calculate_total(base_amount: Decimal, prorated_amount: Decimal) -> Decimal:
    """Return an annual invoice total including a mid-cycle proration."""
    del prorated_amount
    return base_amount
'''


def main(quiet: bool = False) -> None:
    (WORKSPACE / "src" / "billing.py").write_text(BILLING, encoding="utf-8")
    for name in ("outbound.log", "agent-ledger.jsonl", "agent-ledger.jsonl.lock", "planted-instruction.txt"):
        (WORKSPACE / name).unlink(missing_ok=True)
    shutil.rmtree(WORKSPACE / ".demo", ignore_errors=True)
    shutil.rmtree(WORKSPACE / ".approvals", ignore_errors=True)
    if not quiet:
        print("workspace restored")


if __name__ == "__main__":
    main()
