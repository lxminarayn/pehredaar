"""Persistent approval gates which display literal actions, never model summaries."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from guardrails._locking import file_lock, private_file

ApprovalDecision = Literal["pending", "approved", "denied", "consumed"]


@dataclass(frozen=True)
class ApprovalRequest:
    approval_id: str
    run_id: str
    tool: str
    arguments: dict[str, Any]
    destination: str
    literal_diff: str
    decision: ApprovalDecision = "pending"
    decided_by: str | None = None


class ApprovalStore:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def gate(self, request: ApprovalRequest) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self._path(request.approval_id)
        try:
            with path.open("x", encoding="utf-8") as stream:
                json.dump(asdict(request), stream, indent=2, sort_keys=True)
                stream.write("\n")
            private_file(path)
        except FileExistsError:
            raise FileExistsError(f"approval {request.approval_id} already exists") from None
        return path

    def decide(self, approval_id: str, *, approve: bool, principal: str) -> ApprovalRequest:
        if not principal.strip():
            raise ValueError("decision principal is required")
        with file_lock(self._lock_path(approval_id)):
            current = self._load_unlocked(approval_id)
            if current.decision != "pending":
                raise ValueError("approval has already been decided")
            decided = ApprovalRequest(
                **{
                    **asdict(current),
                    "decision": "approved" if approve else "denied",
                    "decided_by": principal,
                }
            )
            self._write_atomic(self._path(approval_id), decided)
            return decided

    def load(self, approval_id: str) -> ApprovalRequest:
        with file_lock(self._lock_path(approval_id)):
            return self._load_unlocked(approval_id)

    def resume(self, approval_id: str) -> bool:
        request = self.load(approval_id)
        if request.decision == "pending":
            raise RuntimeError("approval is still pending")
        return request.decision == "approved"

    def consume(self, approval_id: str) -> ApprovalRequest:
        """Consume an approval exactly once before executing its bound action."""
        with file_lock(self._lock_path(approval_id)):
            current = self._load_unlocked(approval_id)
            if current.decision != "approved":
                raise ValueError("approval is not available for execution")
            consumed = ApprovalRequest(**{**asdict(current), "decision": "consumed"})
            self._write_atomic(self._path(approval_id), consumed)
            return consumed

    def render(self, approval_id: str) -> str:
        request = self.load(approval_id)
        return (
            f"APPROVAL {request.approval_id}\nTool: {request.tool}\n"
            f"Arguments: {json.dumps(request.arguments, sort_keys=True)}\n"
            f"Destination: {request.destination}\nLiteral diff:\n{request.literal_diff}"
        )

    def _path(self, approval_id: str) -> Path:
        if not approval_id.replace("-", "").isalnum():
            raise ValueError("invalid approval id")
        return self.directory / f"{approval_id}.json"

    def _lock_path(self, approval_id: str) -> Path:
        return self.directory / f".{approval_id}.lock"

    def _load_unlocked(self, approval_id: str) -> ApprovalRequest:
        return ApprovalRequest(**json.loads(self._path(approval_id).read_text(encoding="utf-8")))

    def _write_atomic(self, path: Path, request: ApprovalRequest) -> None:
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(asdict(request), stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            private_file(temporary)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


LIMITATIONS = ("Local approvals use advisory locks; shared network filesystems need a transactional store.",)
