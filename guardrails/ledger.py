"""Append-only, hash-chained action ledger."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardrails._locking import file_lock, private_file

TAIL_BYTES = 65_536


@dataclass(frozen=True)
class LedgerRecord:
    ts: str
    run: str
    step: int
    principal: str
    tool: str
    args_hash: str
    provenance: tuple[str, ...]
    verdict: str
    rule: str
    asi: tuple[str, ...]
    rationale: str
    decided_by: str
    decision: str
    prev_hash: str
    record_hash: str
    taint: tuple[str, ...] = ()


class Ledger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, *, args: dict[str, Any], **fields: Any) -> LedgerRecord:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(self._lock_path()):
            record = LedgerRecord(
                ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
                **fields,
                args_hash=_hash_json(args),
                prev_hash=self._tail_hash_unlocked(),
                record_hash="",
            )
            body = asdict(record)
            del body["record_hash"]
            record = replace(record, record_hash=_hash_json(body))
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(asdict(record), sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            private_file(self.path)
            return record

    def records(self) -> list[LedgerRecord]:
        with file_lock(self._lock_path()):
            return self._records_unlocked()

    def verify(self) -> bool:
        try:
            with file_lock(self._lock_path()):
                previous = "GENESIS"
                for record in self._records_unlocked():
                    body = asdict(record)
                    claimed = body.pop("record_hash")
                    if body["prev_hash"] != previous or _hash_json(body) != claimed:
                        return False
                    previous = claimed
                return True
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return False

    def _lock_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".lock")

    def _tail_hash_unlocked(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        with self.path.open("rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            stream.seek(max(0, size - TAIL_BYTES))
            last = stream.read().rstrip(b"\n").rsplit(b"\n", 1)[-1]
        return str(json.loads(last)["record_hash"]) if last else "GENESIS"

    def _records_unlocked(self) -> list[LedgerRecord]:
        if not self.path.exists():
            return []
        return [LedgerRecord(**json.loads(line)) for line in self.path.read_text(encoding="utf-8").splitlines()]


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


LIMITATIONS = ("Hash chaining exposes edits and reordering; tail truncation or deletion needs an external checkpoint.",)
