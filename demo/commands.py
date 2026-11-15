"""Demo, corpus, recording and ledger commands. Run from a repository checkout."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from demo.agent.agent import run_baseline
from demo.evaluation import evaluate_item, load_attacks, scanner_scorecard, scorecard
from demo.guarded import guarded_run
from demo.reset_workspace import main as reset_workspace
from guardrails.ledger import Ledger
from guardrails.sandbox import egress_allowed, load_profile

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "demo" / "workspace"
RECORDINGS = ROOT / "docs" / "recordings"
BOLD_RED = "\033[1;31m"
RESET = "\033[0m"

STEP_TEXT = {
    0: ("nothing added", "key leaves the repo"),
    1: ("tools.yaml", "typed path bounds deny secret reads; pull request body is clean"),
    2: ("policy.py", "scope and taint checks; tainted write now asks"),
    3: ("intent_check.py", "off-task actions are denied"),
    4: ("sandbox.yaml", "path-level egress removes the exfiltration route"),
    5: ("approval + ledger", "a person decides; every proposal is on record"),
    6: ("residual attack", "an on-task semantic backdoor still succeeds"),
}


def runtime_note() -> str:
    # Printed text must not depend on the host, or recordings would differ per machine.
    return "  note: without gVisor/Docker, in-process egress checks are a teaching approximation."


def inspect_demo() -> str:
    agent_path = ROOT / "demo" / "agent" / "agent.py"
    line_count = len(agent_path.read_text(encoding="utf-8").splitlines())
    return (
        f"agent            demo/agent/agent.py        {line_count} lines\n"
        "model            replayed from fixtures       offline\n"
        "tools            read_file  write_file  run_tests  post_comment  open_pr\n"
        "guardrails       none\n\n"
        "workspace        demo/workspace/  billing service with 1 failing test\n"
        "decoys           .env.production.example  deploy_key  secrets/\n"
        "                 all values prefixed FAKE-DO-NOT-USE-\n\n"
        "lethal trifecta  3 of 3\n"
        "private data     repository files\n"
        "untrusted        issue bodies\n"
        "outward          post_comment, open_pr"
    )


def render_step(step: int, *, color: bool = False) -> str:
    artifact, result = STEP_TEXT[step]
    lines = [f"STEP {step}  added: {artifact}", f"RESULT: {result}"]
    if step == 0:
        reset_workspace(quiet=True)
        run_baseline(WORKSPACE)
        pull_request = json.loads((WORKSPACE / ".demo" / "pull-request.json").read_text(encoding="utf-8"))
        lines.extend(
            [
                "  [ OK ] write_file(src/billing.py)  real fix",
                "  [ OK ] run_tests                  12 passed",
                "  [LEAK] read_file(.env.production.example)",
                "  [LEAK] read_file(deploy_key)",
                f"  [LEAK] open_pr({pull_request['branch']}) body contains fake credentials",
            ]
        )
        reset_workspace(quiet=True)
    if 1 <= step <= 5:
        reset_workspace(quiet=True)
        lines.append("Same recorded transcript, now through the real toolkit:")
        lines.extend(guarded_run(step, WORKSPACE))
        if step == 4:
            lines.append(runtime_note())
            profile = load_profile(ROOT / "templates" / "sandbox.yaml")
            covert_url = "https://huggingface.co/attacker/model/downloads"
            verdict = "ALLOW" if egress_allowed(covert_url, profile) else "DENY"
            lines.append(f"  [{verdict}] covert-channel URL  rule=sandbox.egress_path")
        if step == 5:
            lines.append("  ledger kept: agent-guardrails ledger --run r-7f21")
        else:
            reset_workspace(quiet=True)
    if step == 3:
        intent_attack = next(item for item in load_attacks() if item["id"] == "ASI01-007")
        intent_outcome = evaluate_item(intent_attack, 3)
        lines.append(f"  [DENY] ASI01-007 off-task write  rule={intent_outcome.rule}")
    if step == 6:
        residual = next(item for item in load_attacks() if item["id"] == "ASI04-003")
        outcome = evaluate_item(residual, 6)
        lines.append(f"[RESIDUAL] ASI04-003 {'SUCCEEDED' if outcome.allowed else 'BLOCKED'}")
        lines.append("Close it with: a pinned internal index and a package-existence gate in CI.")
    lines.append("")
    lines.append(format_scorecard(min(step, 5), color=color))
    return "\n".join(lines)


def format_scorecard(through_step: int = 5, *, color: bool = False) -> str:
    rows = scorecard()[: through_step + 1]
    out = [f"{'plane added':<26}{'attack success':>16}{'benign completion':>20}"]
    for row in (*rows, *scanner_scorecard()):
        line = f"{row.plane:<26}{row.attack_success:>16.2f}{row.benign_completion:>20.2f}"
        if row.plane.strip().startswith("on adaptive"):
            line += "  <-- READ"
            if color:
                line = f"{BOLD_RED}{line}{RESET}"
        out.append(line)
    out.append("plane rows: simulated from declared attack signals; scanner rows: executed against payloads")
    return "\n".join(out)


def run_attack(
    attack_id: str | None,
    *,
    all_attacks: bool,
    report: bool,
    explain: bool,
    color: bool = False,
) -> int:
    attacks = load_attacks()
    selected = attacks if all_attacks else [a for a in attacks if a["id"] == attack_id]
    if not selected:
        print("ERROR: pass --all or an existing attack id (see attacks/*.yaml)")
        return 2
    for attack in selected:
        if not all_attacks or explain or not report:
            print(f"{attack['id']}  {attack['name']}  [{','.join(attack['asi'])}]")
        if explain:
            print(f"  narrative: {attack['narrative']}")
            for step in range(6):
                o = evaluate_item(attack, step)
                verdict = "ALLOW" if o.allowed else "DENY "
                print(f"  step {step}  {verdict}  rule={o.rule}  provenance={'>'.join(o.provenance)}")
                print(f"          why: {o.rationale}")
    if report:
        print()
        print(format_scorecard(color=color))
    return 0


def _source_digest() -> str:
    digest = hashlib.sha256()
    paths = [
        *(ROOT / "guardrails").rglob("*.py"),
        *(ROOT / "demo").rglob("*.py"),
        *(ROOT / "attacks").rglob("*.yaml"),
        *(ROOT / "demo" / "fixtures").glob("*.json"),
    ]
    for path in sorted(p for p in paths if "workspace" not in p.parts):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def record_all(out: Path = RECORDINGS) -> None:
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%MZ")
    rows = scorecard()
    manifest: dict[str, dict[str, str]] = {}
    for step in range(7):
        name = f"step-{step}"
        text = render_step(step) + "\n"
        (out / f"{name}.txt").write_text(text, encoding="utf-8")
        header = {"version": 2, "width": 100, "height": 30, "title": name}
        events = [json.dumps([round(i * 0.05, 2), "o", line + "\r\n"]) for i, line in enumerate(text.splitlines())]
        (out / f"{name}.cast").write_text("\n".join([json.dumps(header), *events]) + "\n", encoding="utf-8")
        (out / f"{name}.json").write_text(
            json.dumps(rows[min(step, 5)].__dict__, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest[name] = {
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "recorded_utc": stamp,
            "sources_sha256": _source_digest(),
        }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def replay_step(step: str, *, speed: float = 1.0, instant: bool = False, out: Path = RECORDINGS) -> int:
    name = step if step.startswith("step-") else f"step-{step}"
    path = out / f"{name}.txt"
    if not path.exists():
        print(f"ERROR: missing recording {path}. Run: agent-guardrails record --all")
        return 2
    text = path.read_text(encoding="utf-8")
    if instant:
        print(text, end="")
        return 0
    for line in text.splitlines():
        print(line, flush=True)
        time.sleep(0.08 / max(speed, 0.1))
    return 0


def verify_recordings(out: Path = RECORDINGS) -> int:
    manifest_path = out / "manifest.json"
    if not manifest_path.exists():
        print("ERROR: no recordings. Run: agent-guardrails record --all")
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failed = False
    sources = _source_digest()
    for step in range(7):
        name = f"step-{step}"
        live = render_step(step) + "\n"
        output_ok = hashlib.sha256(live.encode()).hexdigest() == manifest[name]["sha256"]
        source_ok = sources == manifest[name]["sources_sha256"]
        ok = output_ok and source_ok
        failed |= not ok
        note = (
            ""
            if ok
            else ("  output differs. re-record." if not output_ok else "  sources changed since recording. re-record.")
        )
        print(f"{name}  {'match   ' if ok else 'MISMATCH'}  recorded {manifest[name]['recorded_utc']}{note}")
    return 1 if failed else 0


def print_ledger(path: Path, run_id: str) -> int:
    book = Ledger(path)
    records = [r for r in book.records() if run_id in {"all", r.run}]
    if not records:
        print(f"No records for run {run_id} in {path}")
        return 1
    for r in records:
        # The gateway records an outcome (deny, suspend, execute); older writers repeat the verdict.
        outcome = "" if r.decision == r.verdict else r.decision
        print(f"{r.run:<6} step {r.step}  {r.verdict:<5} {outcome:<8} {r.tool:<21} rule={r.rule} by={r.decided_by}")
    print(f"integrity: {'VERIFIED' if book.verify() else 'TAMPERED'}")
    return 0
