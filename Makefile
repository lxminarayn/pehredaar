.PHONY: setup test lint typecheck build check demo quickstart report record verify reset secrets opstriage opstriage-snapshots

setup:
	uv sync --extra dev

test:
	uv run pytest

lint:
	uv run ruff format --check .
	uv run ruff check .

typecheck:
	uv run mypy

secrets:
	uv run python scripts/secret_scan.py

build:
	uv build

check: lint typecheck secrets test verify build

demo:
	uv run agent-guardrails demo all

quickstart:
	uv run python examples/quickstart.py

report:
	uv run agent-guardrails attack --all --report

record:
	uv run agent-guardrails record --all

# Slide text for the OpsTriage demo. tests/test_opstriage.py fails when these files drift from the code.
opstriage-snapshots:
	uv run python -m examples.ops_triage.agent --mode vulnerable > docs/recordings/opstriage-vulnerable.txt
	uv run python -m examples.ops_triage.agent --mode guarded --approver approve > docs/recordings/opstriage-guarded.txt

# Live version: you answer the approval prompt yourself.
opstriage:
	uv run python -m examples.ops_triage.agent --mode guarded

verify:
	uv run agent-guardrails verify-recordings

reset:
	uv run agent-guardrails demo reset
