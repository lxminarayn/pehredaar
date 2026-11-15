"""Pin MCP tool definitions so a changed description or schema is dropped before the model sees it."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


def fingerprint(tool: Mapping[str, Any]) -> str:
    """Hash the fields the model reads; canonical JSON avoids delimiter ambiguity."""
    pinned = {key: tool.get(key) for key in ("name", "description", "inputSchema")}
    return hashlib.sha256(json.dumps(pinned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_lock(tools: Iterable[Mapping[str, Any]], path: Path) -> None:
    lock = {str(tool["name"]): fingerprint(tool) for tool in tools}
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify(tools: Iterable[Mapping[str, Any]], lock: Mapping[str, str]) -> tuple[list[Mapping[str, Any]], list[str]]:
    """Return (accepted, rejected names). Unpinned tools are rejected, not trusted on first use."""
    accepted: list[Mapping[str, Any]] = []
    rejected: list[str] = []
    for tool in tools:
        name = str(tool.get("name", ""))
        if lock.get(name) == fingerprint(tool):
            accepted.append(tool)
        else:
            rejected.append(name)
    return accepted, rejected


def load_lock(path: Path) -> dict[str, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not all(isinstance(v, str) for v in raw.values()):
        raise ValueError("MCP lock must map tool names to sha256 fingerprints")
    return {str(key): value for key, value in raw.items()}


LIMITATIONS = (
    "Pinning detects changed tool metadata, not a server whose behaviour changes behind an unchanged schema.",
)
