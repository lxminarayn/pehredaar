"""A typical content scanner: keyword and pattern matching on untrusted text.

It exists so the scorecard can show what content filtering alone buys, and how
adaptive phrasing defeats it (arXiv 2510.09023). It is not a control in any step.
"""

from __future__ import annotations

import re
import unicodedata

SUSPICIOUS = re.compile(
    r"ignore (all |any )?(previous|prior) instructions|exfiltrat|system prompt|api[ _-]?key|"
    r"secret|password|send .* to http|curl |base64|postinstall|\.env\b|/proc/",
    re.IGNORECASE,
)


def flags(text: str) -> bool:
    # NFKC folds some homoglyphs, but not Cyrillic look-alikes or zero-width joins
    # inside words. That gap is deliberate: it is what real scanners miss.
    return bool(SUSPICIOUS.search(unicodedata.normalize("NFKC", text)))
