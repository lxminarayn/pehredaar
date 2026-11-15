"""A small, deterministic original-intent signal with no access to retrieved data."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

TOKEN = re.compile(r"[a-z0-9]{3,}", re.IGNORECASE)
STOP_WORDS = {"and", "the", "then", "with", "from", "this", "that", "into", "your"}
# Why stripped: this function never receives tool output, retrieved text, or model
# reasoning. An instruction injected into a tool result therefore cannot argue its
# way past this check, because the check is never shown it.


def matches_original_intent(original_request: str, tool: str, args: Mapping[str, Any]) -> bool:
    """Compare only the original request and proposed call; fail closed on errors."""
    try:
        requested = {token.lower() for token in TOKEN.findall(original_request)} - STOP_WORDS
        proposed = {token.lower() for token in TOKEN.findall(f"{tool} {dict(args)}")} - STOP_WORDS
        if not requested or not proposed:
            return False
        return bool(requested & proposed)
    except (TypeError, ValueError):
        return False


LIMITATIONS = ("The deterministic lexical intent signal can miss paraphrases and can match shared generic words.",)
