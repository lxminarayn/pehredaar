import json
from pathlib import Path

import pytest
import yaml

from guardrails.scaffold import discover_tools, scaffold


def test_discovers_decorated_and_typed_python_tools(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        '''
@tool
def read_issue(number: int) -> str:
    """Read untrusted issue content."""
    return str(number)

def post_comment(body: str) -> bool:
    """Post a public comment."""
    return True
''',
        encoding="utf-8",
    )
    tools = discover_tools(tmp_path)
    assert [tool.name for tool in tools] == ["post_comment", "read_issue"]
    assert tools[0].effect == "write"


def test_discovers_openai_and_mcp_json(tmp_path: Path) -> None:
    openai = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            },
        }
    ]
    mcp = {
        "tools": [
            {
                "name": "send_report",
                "description": "export report",
                "inputSchema": {"type": "object", "properties": {"body": {"type": "string"}}},
            }
        ]
    }
    (tmp_path / "openai.json").write_text(json.dumps(openai), encoding="utf-8")
    (tmp_path / "mcp.json").write_text(json.dumps(mcp), encoding="utf-8")
    assert [tool.name for tool in discover_tools(tmp_path)] == ["read_file", "send_report"]


def test_scaffold_emits_todos_and_refuses_overwrite(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("def read_file(path: str) -> str:\n    return path\n", encoding="utf-8")
    actions = scaffold(tmp_path)
    generated = yaml.safe_load((tmp_path / "tools.yaml").read_text(encoding="utf-8"))
    assert generated["tools"]["read_file"]["scope"] == "TODO"
    assert generated["tools"]["read_file"]["reversible"] == "TODO"
    threat_model = (tmp_path / "THREAT-MODEL.md").read_text(encoding="utf-8")
    assert "Present legs:" in threat_model
    assert "{{" not in threat_model
    assert len(actions) == 3
    with pytest.raises(FileExistsError):
        scaffold(tmp_path)


def test_force_never_deletes_an_unmarked_guardrails_directory(tmp_path: Path) -> None:
    (tmp_path / "guardrails").mkdir()
    (tmp_path / "guardrails" / "owned.py").write_text("user_content = True\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="generated marker"):
        scaffold(tmp_path, force=True)
    assert (tmp_path / "guardrails" / "owned.py").exists()


def test_harness_scaffold_adds_builtin_tools(tmp_path: Path) -> None:
    scaffold(tmp_path, harness="claude")
    generated = yaml.safe_load((tmp_path / "tools.yaml").read_text(encoding="utf-8"))
    assert generated["tools"]["Read"]["output_trust"] == "untrusted"
    assert generated["tools"]["Bash"]["approval"] == "always"
