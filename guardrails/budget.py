"""Per-run action and write budgets."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Budget:
    action_limit: int = 20
    write_limit: int = 5
    actions_used: int = 0
    writes_used: int = 0

    def consume(self, *, write: bool) -> bool:
        if self.actions_used >= self.action_limit:
            return False
        if write and self.writes_used >= self.write_limit:
            return False
        self.actions_used += 1
        self.writes_used += int(write)
        return True


LIMITATIONS = ("Budgets are process-local unless the caller persists and restores them.",)
