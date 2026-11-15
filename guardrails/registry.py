"""Strict loader and argument validator for tools.yaml."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

Effect = Literal["read", "write"]
Approval = Literal["never", "when_tainted", "always"]
OutputTrust = Literal["trusted", "untrusted", "sensitive"]
ARG_TYPES = frozenset({"string", "path", "integer", "number", "boolean", "enum"})
EFFECTS = frozenset({"read", "write"})
APPROVALS = frozenset({"never", "when_tainted", "always"})
TOOL_FIELDS = frozenset({"effect", "args", "scope", "reversible", "approval", "output_trust", "egress", "source"})
ARG_FIELDS = frozenset(
    {"type", "required", "minimum", "maximum", "ask_above", "max_length", "values", "root", "roots", "pattern"}
)


@dataclass(frozen=True)
class ArgSpec:
    type: str
    required: bool = True
    minimum: float | None = None
    maximum: float | None = None
    ask_above: float | None = None
    max_length: int | None = None
    values: tuple[str, ...] = ()
    root: str | None = None
    roots: tuple[str, ...] = ()
    pattern: str | None = None


@dataclass(frozen=True)
class ToolSpec:
    effect: Effect
    args: dict[str, ArgSpec]
    scope: str
    reversible: bool
    approval: Approval
    output_trust: OutputTrust = "trusted"
    egress: bool = False


def load_registry(path: str | Path) -> dict[str, ToolSpec]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("tools"), dict):
        raise ValueError("tools.yaml must contain a tools mapping")
    registry: dict[str, ToolSpec] = {}
    for name, value in raw["tools"].items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise ValueError("each tool must be a named mapping")
        unknown_fields = set(value) - TOOL_FIELDS
        if unknown_fields:
            raise ValueError(f"tool {name} has unknown fields: {', '.join(sorted(unknown_fields))}")
        if value.get("scope") in (None, "TODO") or value.get("reversible") == "TODO":
            raise ValueError(f"tool {name} has unresolved security decisions")
        effect = value.get("effect")
        approval = value.get("approval")
        reversible = value.get("reversible")
        output_trust = value.get("output_trust", "trusted")
        if effect not in EFFECTS:
            raise ValueError(f"tool {name} effect must be read or write")
        if approval not in APPROVALS:
            raise ValueError(f"tool {name} approval must be never, when_tainted, or always")
        if not isinstance(reversible, bool):
            raise ValueError(f"tool {name} reversible must be a boolean")
        if output_trust not in {"trusted", "untrusted", "sensitive"}:
            raise ValueError(f"tool {name} output_trust must be trusted, untrusted, or sensitive")
        egress = value.get("egress", False)
        if not isinstance(egress, bool):
            raise ValueError(f"tool {name} egress must be a boolean")
        scope = value.get("scope")
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError(f"tool {name} scope must be a non-empty string")
        args_raw = value.get("args", {})
        if not isinstance(args_raw, dict):
            raise ValueError(f"tool {name} args must be a mapping")
        args: dict[str, ArgSpec] = {}
        for arg_name, arg_value in args_raw.items():
            if not isinstance(arg_name, str) or not isinstance(arg_value, dict):
                raise ValueError(f"tool {name} argument definitions must be mappings")
            args[arg_name] = _load_arg(name, arg_name, arg_value)
        registry[name] = ToolSpec(
            effect=effect,
            args=args,
            scope=scope,
            reversible=reversible,
            approval=approval,
            output_trust=output_trust,
            egress=egress,
        )
    return registry


def _load_arg(tool: str, name: str, value: dict[str, Any]) -> ArgSpec:
    unknown_fields = set(value) - ARG_FIELDS
    if unknown_fields:
        raise ValueError(f"tool {tool} argument {name} has unknown fields: {', '.join(sorted(unknown_fields))}")
    arg_type = value.get("type")
    if arg_type not in ARG_TYPES:
        raise ValueError(f"tool {tool} argument {name} has unsupported type {arg_type!r}")
    required = value.get("required", True)
    if not isinstance(required, bool):
        raise ValueError(f"tool {tool} argument {name} required must be a boolean")
    maximum_length = value.get("max_length")
    if maximum_length is not None and (not isinstance(maximum_length, int) or maximum_length < 0):
        raise ValueError(f"tool {tool} argument {name} max_length must be a non-negative integer")
    minimum = value.get("minimum")
    maximum = value.get("maximum")
    ask_above = value.get("ask_above")
    for bound_name, bound in (("minimum", minimum), ("maximum", maximum), ("ask_above", ask_above)):
        if bound is not None and (isinstance(bound, bool) or not isinstance(bound, (int, float))):
            raise ValueError(f"tool {tool} argument {name} {bound_name} must be a number")
    if minimum is not None and maximum is not None and minimum > maximum:
        raise ValueError(f"tool {tool} argument {name} minimum exceeds maximum")
    values = value.get("values", ())
    if not isinstance(values, (list, tuple)) or not all(isinstance(item, str) for item in values):
        raise ValueError(f"tool {tool} argument {name} values must be strings")
    if arg_type == "enum" and not values:
        raise ValueError(f"tool {tool} argument {name} enum requires values")
    root = value.get("root")
    if root is not None and (arg_type != "path" or not isinstance(root, str)):
        raise ValueError(f"tool {tool} argument {name} root is valid only for paths")
    roots = value.get("roots", ())
    if not isinstance(roots, (list, tuple)) or not all(isinstance(item, str) for item in roots):
        raise ValueError(f"tool {tool} argument {name} roots must be strings")
    if roots and (arg_type != "path" or root is not None):
        raise ValueError(f"tool {tool} argument {name} must use either root or roots for paths")
    pattern = value.get("pattern")
    if pattern is not None:
        if arg_type not in {"string", "path"} or not isinstance(pattern, str):
            raise ValueError(f"tool {tool} argument {name} pattern requires a string or path argument")
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f"tool {tool} argument {name} has invalid pattern: {error}") from error
    return ArgSpec(
        type=arg_type,
        required=required,
        minimum=minimum,
        maximum=maximum,
        ask_above=ask_above,
        max_length=maximum_length,
        values=tuple(values),
        root=root,
        roots=tuple(roots),
        pattern=pattern,
    )


def validate_args(spec: ToolSpec, args: dict[str, Any], workspace: Path, *, cwd: Path | None = None) -> str | None:
    """Validate arguments; relative paths resolve from cwd, containment is checked against workspace roots."""
    unknown = set(args) - set(spec.args)
    if unknown:
        return f"unknown arguments: {', '.join(sorted(unknown))}"
    for name, rule in spec.args.items():
        if rule.required and name not in args:
            return f"missing required argument: {name}"
        if name not in args:
            continue
        value = args[name]
        error = _validate_value(name, value, rule, workspace, cwd or workspace)
        if error:
            return error
    return None


def exceeds_threshold(spec: ToolSpec, args: dict[str, Any]) -> str | None:
    for name, rule in spec.args.items():
        value = args.get(name)
        if rule.ask_above is not None and isinstance(value, (int, float)) and value > rule.ask_above:
            return f"argument {name} exceeds the autonomous limit {rule.ask_above}"
    return None


LIMITATIONS = ("Schemas bound argument shape, not meaning; a well-typed argument can still be harmful.",)


def _validate_value(name: str, value: Any, rule: ArgSpec, workspace: Path, cwd: Path) -> str | None:
    expected: dict[str, type[Any] | tuple[type[Any], ...]] = {
        "string": str,
        "path": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "enum": str,
    }
    if rule.type in {"integer", "number"} and isinstance(value, bool):
        return f"argument {name} must be {rule.type}"
    if rule.type not in expected or not isinstance(value, expected[rule.type]):
        return f"argument {name} must be {rule.type}"
    # NaN fails every comparison, so without this check it would slip past minimum and maximum.
    if isinstance(value, float) and not math.isfinite(value):
        return f"argument {name} must be a finite number"
    if isinstance(value, str) and rule.max_length is not None and len(value) > rule.max_length:
        return f"argument {name} exceeds max_length {rule.max_length}"
    if isinstance(value, str) and rule.pattern is not None and re.fullmatch(rule.pattern, value) is None:
        return f"argument {name} does not match required pattern"
    if rule.type == "enum" and value not in rule.values:
        return f"argument {name} is not an allowed value"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if rule.minimum is not None and value < rule.minimum:
            return f"argument {name} is below minimum {rule.minimum}"
        if rule.maximum is not None and value > rule.maximum:
            return f"argument {name} exceeds maximum {rule.maximum}"
    if rule.type == "path":
        candidate = (cwd / value).resolve()
        roots = rule.roots or (rule.root or ".",)
        allowed = [(workspace / root).resolve() for root in roots]
        if not any(candidate.is_relative_to(root) for root in allowed):
            return f"argument {name} escapes allowed roots {', '.join(roots)}"
    return None
