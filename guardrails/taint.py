"""Coarse-grained provenance propagation for values derived from untrusted data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, SupportsIndex


@dataclass(frozen=True)
class Provenance:
    origins: tuple[str, ...]
    untrusted: bool
    sensitive: bool = False

    @classmethod
    def trusted(cls, origin: str = "user_request") -> Provenance:
        return cls((origin,), False)

    @classmethod
    def untrusted_source(cls, origin: str) -> Provenance:
        return cls((origin,), True)

    def merge(self, other: Provenance) -> Provenance:
        return Provenance(
            tuple(dict.fromkeys(self.origins + other.origins)),
            self.untrusted or other.untrusted,
            self.sensitive or other.sensitive,
        )

    def after_output(self, tool: str, trust: str) -> Provenance:
        """Record what a successful tool output adds to the run's context."""
        if trust == "trusted":
            return self
        return self.merge(Provenance((tool,), trust == "untrusted", trust == "sensitive"))

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(label for label, on in (("untrusted", self.untrusted), ("sensitive", self.sensitive)) if on)


class TaintedStr(str):
    """A string which preserves provenance through common Python operations."""

    provenance: Provenance

    def __new__(cls, value: str, provenance: Provenance) -> TaintedStr:
        instance = super().__new__(cls, value)
        instance.provenance = provenance
        return instance

    def __getitem__(self, key: SupportsIndex | slice) -> TaintedStr:
        return TaintedStr(super().__getitem__(key), self.provenance)

    def __add__(self, other: object) -> TaintedStr:
        provenance = self.provenance
        if isinstance(other, TaintedStr):
            provenance = provenance.merge(other.provenance)
        return TaintedStr(super().__add__(str(other)), provenance)

    def __radd__(self, other: object) -> TaintedStr:
        provenance = self.provenance
        if isinstance(other, TaintedStr):
            provenance = provenance.merge(other.provenance)
        return TaintedStr(str(other) + str(self), provenance)

    def format(self, *args: object, **kwargs: object) -> TaintedStr:
        provenance = self.provenance
        for value in (*args, *kwargs.values()):
            if isinstance(value, TaintedStr):
                provenance = provenance.merge(value.provenance)
        return TaintedStr(super().format(*args, **kwargs), provenance)


def taint(value: str, origin: str) -> TaintedStr:
    return TaintedStr(value, Provenance.untrusted_source(origin))


def is_tainted(value: Any) -> bool:
    if isinstance(value, TaintedStr):
        return value.provenance.untrusted
    if isinstance(value, dict):
        return any(is_tainted(key) or is_tainted(item) for key, item in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(is_tainted(item) for item in value)
    return False


LIMITATIONS = ("Taint is coarse grained and cannot follow values through native extensions or serialization.",)
