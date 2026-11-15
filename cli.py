"""Pehredaar command-line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from guardrails import (
    approval,
    budget,
    gateway,
    hook,
    identity,
    integrations,
    intent_check,
    ledger,
    manifest,
    policy,
    registry,
    sandbox,
    taint,
)
from guardrails import scaffold as scaffold_module
from guardrails.hook import HookRuntime, adapt_output, decision_output
from guardrails.policy import Verdict
from guardrails.scaffold import scaffold

LIMITATION_MODULES = (
    approval,
    budget,
    identity,
    integrations,
    intent_check,
    ledger,
    manifest,
    policy,
    gateway,
    hook,
    registry,
    sandbox,
    scaffold_module,
    taint,
)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="agent-guardrails", description="Deterministic guardrails for agent tools")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="scaffold guardrails into an existing agent")
    init.add_argument("--path", type=Path, required=True)
    init.add_argument("--force", action="store_true")
    init.add_argument("--harness", choices=("generic", "claude", "vscode-local", "copilot"), default="generic")
    threat = commands.add_parser("threat-model", help="interactive, writes THREAT-MODEL.md")
    threat.add_argument("--path", type=Path, default=Path("THREAT-MODEL.md"))
    threat.add_argument("--force", action="store_true")
    demo = commands.add_parser("demo", help="run the talk demo")
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)
    demo_sub.add_parser("inspect", help="show agent, tools, trifecta count")
    step = demo_sub.add_parser("step", help="run one demo step")
    step.add_argument("number", type=int, choices=range(7))
    step.add_argument("--explain", action="store_true")
    step.add_argument("--no-color", action="store_true")
    demo_all = demo_sub.add_parser("all", help="run the full sequence")
    demo_all.add_argument("--no-color", action="store_true")
    demo_sub.add_parser("reset", help="restore demo/workspace")
    attack = commands.add_parser("attack", help="run the attack corpus")
    attack.add_argument("attack_id", nargs="?")
    attack.add_argument("--all", action="store_true")
    attack.add_argument("--report", action="store_true")
    attack.add_argument("--explain", action="store_true")
    attack.add_argument("--no-color", action="store_true")
    record = commands.add_parser("record", help="capture deterministic recordings")
    record.add_argument("--all", action="store_true")
    record.add_argument("--out", type=Path, default=None)
    replay = commands.add_parser("replay", help="replay a recording")
    replay.add_argument("step")
    replay.add_argument("--speed", type=float, default=1.0)
    replay.add_argument("--instant", action="store_true")
    commands.add_parser("verify-recordings", help="live run diffed against recordings")
    book = commands.add_parser("ledger", help="human readable audit trail")
    book.add_argument("--run", required=True, help="run id, or 'all'")
    book.add_argument("--path", type=Path, default=None)
    commands.add_parser("limitations", help="print every LIMITATIONS constant")
    doctor = commands.add_parser("doctor", help="validate a project installation")
    doctor.add_argument("--path", type=Path, default=Path.cwd())
    hook_command = commands.add_parser("hook", help="process one command-hook event from stdin")
    hook_command.add_argument("--harness", choices=("common", "copilot"), default="common")
    hook_command.add_argument("--policy", type=Path, default=Path("tools.yaml"))
    hook_command.add_argument("--state-dir", type=Path, default=Path(".pehredaar"))
    hook_command.add_argument("--sandbox", type=Path, default=None)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "init":
        try:
            actions = scaffold(args.path, force=args.force, harness=args.harness)
        except (FileExistsError, FileNotFoundError, ValueError) as error:
            print(f"ERROR: {error}")
            return 2
        print(f"Scaffolded Pehredaar into {args.path.resolve()}")
        for number, action in enumerate(actions, 1):
            print(f"action {number}  {action}")
        return 0
    if args.command == "limitations":
        for module in LIMITATION_MODULES:
            for item in module.LIMITATIONS:
                print(f"- {module.__name__}: {item}")
        return 0
    if args.command == "doctor":
        return run_doctor(args.path)
    if args.command == "threat-model":
        return write_threat_model(args.path, force=args.force)
    if args.command == "hook":
        return run_hook(args.policy, args.state_dir, args.sandbox, args.harness)
    # Demo commands need a repository checkout; import lazily so `init` works from pipx.
    try:
        from demo import commands as demo_cmds
    except ImportError:
        print("ERROR: demo commands need a checkout of the pehredaar repository.")
        return 2
    if args.command == "demo":
        color = sys.stdout.isatty() and not getattr(args, "no_color", False)
        if args.demo_command == "inspect":
            print(demo_cmds.inspect_demo())
        elif args.demo_command == "reset":
            from demo.reset_workspace import main as reset

            reset()
        elif args.demo_command == "step":
            print(demo_cmds.render_step(args.number, color=color))
        else:
            print("\n\n".join(demo_cmds.render_step(n, color=color) for n in range(7)))
        return 0
    if args.command == "attack":
        color = sys.stdout.isatty() and not args.no_color
        return demo_cmds.run_attack(
            args.attack_id,
            all_attacks=args.all,
            report=args.report,
            explain=args.explain,
            color=color,
        )
    if args.command == "record":
        out = args.out or demo_cmds.RECORDINGS
        demo_cmds.record_all(out)
        print(f"recorded steps 0-6 into {out}")
        return 0
    if args.command == "replay":
        return demo_cmds.replay_step(args.step, speed=args.speed, instant=args.instant)
    if args.command == "verify-recordings":
        return demo_cmds.verify_recordings()
    if args.command == "ledger":
        path = args.path or demo_cmds.WORKSPACE / "agent-ledger.jsonl"
        return demo_cmds.print_ledger(path, args.run)
    return 2


def run_hook(policy_path: Path, state_directory: Path, sandbox_path: Path | None, harness: str) -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("hook input must be a JSON object")
        output = HookRuntime(
            policy_path=policy_path,
            state_directory=state_directory,
            sandbox_path=sandbox_path,
        ).handle(payload)
    except Exception as error:
        output = decision_output(Verdict.DENY, f"Pehredaar failed closed: {error}")
    print(json.dumps(adapt_output(output, harness), separators=(",", ":")))
    return 0


def run_doctor(target: Path) -> int:
    target = target.resolve()
    failures = 0
    checks: list[tuple[str, bool, str]] = []
    policy_path = target / "tools.yaml"
    try:
        loaded = registry.load_registry(policy_path)
        checks.append(("PASS", True, f"tools.yaml: {len(loaded)} tools loaded"))
    except (OSError, ValueError) as error:
        checks.append(("FAIL", False, f"tools.yaml: {error}"))
    sandbox_path = target / "sandbox.yaml"
    try:
        sandbox.load_profile(sandbox_path)
        checks.append(("PASS", True, "sandbox.yaml: path-scoped URL rules valid"))
    except (OSError, ValueError) as error:
        checks.append(("FAIL", False, f"sandbox.yaml: {error}"))
    hook_files = [
        target / ".claude" / "settings.json",
        target / ".github" / "hooks" / "pehredaar.json",
        target / ".github" / "hooks" / "pehredaar-copilot.json",
    ]
    installed = [path for path in hook_files if path.exists()]
    checks.append(
        (
            "PASS" if installed else "WARN",
            True,
            f"hooks: {len(installed)} hook file(s) found (run one known denial to prove they fire)",
        )
    )
    state_directory = target / ".pehredaar"
    try:
        state_directory.mkdir(parents=True, exist_ok=True)
        probe = state_directory / ".doctor"
        probe.write_text("ok\n", encoding="utf-8")
        probe.unlink()
        checks.append(("PASS", True, ".pehredaar: writable"))
    except OSError as error:
        checks.append(("FAIL", False, f".pehredaar: {error}"))
    executable = shutil.which("agent-guardrails") or (sys.argv[0] if Path(sys.argv[0]).exists() else None)
    checks.append(
        (
            "PASS" if executable else "WARN",
            True,
            "command: agent-guardrails is on PATH"
            if executable
            else "command: use `uv run agent-guardrails` or install with `uv tool install .`",
        )
    )
    for label, passed, message in checks:
        print(f"{label:<4}  {message}")
        failures += int(not passed)
    return 1 if failures else 0


def write_threat_model(path: Path, *, force: bool) -> int:
    if path.exists() and not force:
        print(f"ERROR: refusing to overwrite {path}; pass --force")
        return 2
    questions = {
        "PRIVATE_DATA": "Can the agent read private data? ",
        "UNTRUSTED_CONTENT": "Does it read untrusted content (issues, web, email)? ",
        "EXTERNAL_COMMUNICATION": "Can it send data outside (HTTP, comments, email)? ",
        "RESIDUAL_RISK": "Name one attack that still succeeds: ",
    }
    interactive = sys.stdin.isatty()
    answers = {k: (input(q).strip() if interactive else "") or "TODO" for k, q in questions.items()}
    legs = sum(answers[k].lower().startswith("y") for k in list(questions)[:3])
    template = (Path(__file__).resolve().parent / "templates" / "THREAT-MODEL.md").read_text(encoding="utf-8")
    values = {**answers, "TRIFECTA_COUNT": str(legs), "EXTERNAL_CONTROLS": "TODO"}
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    path.write_text(template, encoding="utf-8")
    print(f"wrote {path}  trifecta legs present: {legs}/3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
