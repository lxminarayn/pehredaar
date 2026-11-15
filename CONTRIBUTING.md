# Contributing

## Setup

```console
uv sync --extra dev
```

## Before a pull request

```console
make check
```

This runs formatting checks, lint, strict typing, tests, the secret scan, recording
verification, and package build.

## Change rules

- Keep toolkit modules below 300 lines.
- Keep `guardrails/` independent of `demo/` and model SDKs.
- Add a regression test for every security fix.
- Add a benign twin for every attack corpus entry.
- Correct corpus YAML when observed behavior differs from an expected claim.
- Re-run `agent-guardrails record --all` after changing code, attacks, or fixtures.
- Do not commit credentials. Demo values must start with `FAKE-DO-NOT-USE-`.
- Use primary sources in security documentation.

## Security reports

Use a private repository advisory for bypasses or credential exposure. See `SECURITY.md`.
