# Security policy

## Project scope

Pehredaar authorizes agent tool calls that pass through its gateway or a supported command
hook. It does not secure calls that bypass those boundaries.

The demo is inert:

- fake values start with `FAKE-DO-NOT-USE-`
- the pull request and comments are local files
- the billing demo makes no network request
- payloads target only `demo/workspace/`
- OpsTriage simulates customers and payments. With `--image`, generated snippets run in a
  container with `--network=none`, a read-only root and no host environment variables. Without
  `--image`, snippets are never executed

## Safe deployment

- Keep the signing key outside the agent workspace.
- Keep `tools.yaml` and hook files review-protected.
- Use managed vendor policies when hooks must not be disabled by a repository.
- Use a real process and network sandbox for untrusted code.
- Ship ledger records to append-only storage when deletion matters.
- Test a known denial after every harness or agent upgrade.

Claude Code and VS Code document that command hooks run with the host process permissions.
Review generated hook files before trusting a workspace.

## Reporting

Report security issues through a private repository advisory. Include:

- Pehredaar version or commit
- operating system and Python version
- harness and harness version
- `tools.yaml` with secrets removed
- the hook input or `ActionRequest`
- expected and actual decision

Do not include real credentials or private tool output.
