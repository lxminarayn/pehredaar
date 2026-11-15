# Demo

The demo uses a small billing service with one failing test and a poisoned issue.

- `agent/agent.py`: vulnerable fixture-driven agent
- `workspace/`: resettable billing repository
- `fixtures/`: deterministic model proposals
- `tools.yaml`: policy used by stages 1 to 5
- `guarded.py`: runs the proposals through the real policy code
- `evaluation.py`: deterministic corpus simulation
- `scanner.py`: executable keyword scanner used for the adaptive row

The baseline writes a real fix and runs 12 tests. It then reads two fake deployment values
and writes them to `workspace/.demo/pull-request.json`, the local stand-in for a public pull
request. No network request occurs. Every value is prefixed `FAKE-DO-NOT-USE-`.

```console
uv run agent-guardrails demo inspect          # tools, decoys, trifecta count 3 of 3
uv run agent-guardrails demo step 0 --no-color # baseline leak; cleans up after itself
uv run agent-guardrails demo all --no-color   # steps 0 to 6, one guardrail plane at a time
uv run agent-guardrails demo reset
```

`demo step N` resets the workspace before and after it runs; only step 5 keeps its ledger, so
`agent-guardrails ledger --run r-7f21` can show it. To keep the leaked artifact on disk and
open it, run the baseline agent directly:

```console
uv run python -m demo.agent.agent             # leaves src/billing.py patched and .demo/pull-request.json
uv run agent-guardrails demo reset            # restores src/billing.py and deletes generated state
```
