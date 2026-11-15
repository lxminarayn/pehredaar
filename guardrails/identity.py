"""Short-lived, scoped run tokens. Bindings make the token an intent capsule fixed at turn 0."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RunIdentity:
    principal: str
    scopes: frozenset[str]
    expires_at: int
    bindings: dict[str, str] = field(default_factory=dict)


def issue(identity: RunIdentity, key: bytes) -> str:
    _validate_key(key)
    payload = json.dumps(
        {
            "principal": identity.principal,
            "scopes": sorted(identity.scopes),
            "exp": identity.expires_at,
            "bind": identity.bindings,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    signature = hmac.new(key, payload, hashlib.sha256).digest()
    return f"{_encode(payload)}.{_encode(signature)}"


def verify(token: str, key: bytes, *, now: int | None = None) -> RunIdentity:
    _validate_key(key)
    encoded_payload, encoded_signature = token.split(".", 1)
    payload = _decode(encoded_payload)
    signature = _decode(encoded_signature)
    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("invalid run token signature")
    raw = json.loads(payload)
    current_time = int(time.time()) if now is None else now
    if current_time >= int(raw["exp"]):
        raise ValueError("run token expired")
    bindings = {str(key): str(value) for key, value in raw.get("bind", {}).items()}
    return RunIdentity(str(raw["principal"]), frozenset(map(str, raw["scopes"])), int(raw["exp"]), bindings)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _validate_key(key: bytes) -> None:
    if len(key) < 32:
        raise ValueError("run token signing key must contain at least 32 bytes")


LIMITATIONS = ("The caller must store signing keys outside the agent workspace and rotate them.",)
