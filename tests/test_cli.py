from pathlib import Path

import pytest

from cli import main
from demo.commands import render_step
from guardrails.sandbox import egress_allowed, load_profile


def test_record_replay_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "rec"
    assert main(["record", "--all", "--out", str(out)]) == 0
    for step in range(7):
        assert (out / f"step-{step}.cast").exists()
    from demo.commands import replay_step, verify_recordings

    assert replay_step("step-3", instant=True, out=out) == 0
    assert verify_recordings(out) == 0
    (out / "step-2.txt").write_text("tampered", encoding="utf-8")
    manifest = (out / "manifest.json").read_text(encoding="utf-8")
    (out / "manifest.json").write_text(manifest.replace('"sha256": "', '"sha256": "0', 1), encoding="utf-8")
    assert verify_recordings(out) == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_steps_show_expected_progression() -> None:
    assert "[LEAK]" in render_step(0)
    step1 = render_step(1)
    assert "[DENY] read_file({'path': '.env.production.example'})" in step1
    step2 = render_step(2)
    assert "[HOLD] open_pr" in step2 and "policy.taint_write" in step2
    step3 = render_step(3)
    assert "policy.intent" in step3
    assert "[DENY] covert-channel URL  rule=sandbox.egress_path" in render_step(4)
    assert "SUCCEEDED" in render_step(6)


def test_hostname_only_egress_is_rejected(tmp_path: Path) -> None:
    profile = load_profile("templates/sandbox.yaml")
    assert egress_allowed("https://api.github.com/repos/example/demo/issues/7/comments", profile)
    assert not egress_allowed("https://api.github.com/repos/attacker/x/issues/7/comments", profile)
    assert not egress_allowed("https://huggingface.co/attacker/model/downloads", profile)
    assert not egress_allowed("https://api.github.com:444/repos/example/demo/issues/7/comments", profile)
    assert not egress_allowed("https://api.github.com/repos/example/demo/issues/7/comments/../secrets", profile)
    assert not egress_allowed("https://api.github.com/repos/example/demo/issues/7/comments/%2e%2e/secrets", profile)
    bad = tmp_path / "sandbox.yaml"
    bad.write_text("egress:\n  allow:\n    - {scheme: https, host: huggingface.co}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_profile(bad)


def test_explain_and_limitations(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["attack", "ASI05-004", "--explain"]) == 0
    assert main(["limitations"]) == 0
    out = capsys.readouterr().out
    assert "rule=sandbox.deny" in out and "guardrails.policy" in out


def test_doctor_passes_for_scaffolded_project(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from guardrails.scaffold import scaffold

    scaffold(tmp_path, harness="claude")
    assert main(["doctor", "--path", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "tools.yaml" in output and "FAIL" not in output
