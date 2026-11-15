from examples.quickstart import main


def test_quickstart_shows_every_verdict() -> None:
    log = main()
    assert log[0].startswith("ALLOW  read_file")
    assert "policy.arguments" in log[1]
    assert "policy.taint_write" in log[2]
    assert "approved by reviewer:ravi" in log[3]
    assert "sandbox.egress_path" in log[4]
    assert "policy.unregistered_tool" in log[5]
    assert log[-2].endswith("intact=True")
    assert log[-1].endswith("intact=False")
