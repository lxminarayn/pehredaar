import ast
from pathlib import Path


def test_policy_path_has_no_llm_or_demo_imports() -> None:
    forbidden = ("openai", "anthropic", "langchain", "agent", "demo")
    for path in Path("guardrails").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        names = [alias.name for node in imports for alias in node.names]
        assert not any(name.startswith(forbidden) for name in names), (path, names)
        assert "demo." not in path.read_text(encoding="utf-8"), path


def test_guardrail_modules_stay_projector_readable() -> None:
    for path in Path("guardrails").rglob("*.py"):
        assert len(path.read_text(encoding="utf-8").splitlines()) < 300, path
