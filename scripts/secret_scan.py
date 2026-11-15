"""Fail if anything that looks like a real credential enters the repository.

Demo decoys are allowed only when prefixed FAKE-DO-NOT-USE-. Standard library only so
it runs on any platform without installing gitleaks.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9_-]{32,}"),
    "slack_token": re.compile(r"xox[abpr]-[A-Za-z0-9-]{10,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "assignment": re.compile(r"(?i)(token|secret|password|api_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+_-]{16,})"),
}
SKIP = {".git", ".venv", "node_modules", "graphify-out", "__pycache__", ".mypy_cache", ".ruff_cache"}


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    findings: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or SKIP & set(path.relative_to(root).parts) or path.stat().st_size > 1_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if "FAKE-DO-NOT-USE-" in line or "re.compile" in line:
                continue
            for name, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(f"{path.relative_to(root)}:{number}: {name}")
    for finding in findings:
        print(f"SECRET? {finding}")
    print(f"secret scan: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
