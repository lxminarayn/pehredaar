# Adoption guide

## 1. Install the command

From a checkout:

```console
uv tool install .
agent-guardrails --help
```

The command is the same on macOS, Linux, Windows PowerShell, and WSL. Restart the
terminal if the tool directory was added to PATH during installation.

## 2. Choose an integration

Claude Code:

```console
agent-guardrails init --path /path/to/project --harness claude
```

This merges three command hooks into `.claude/settings.json`. Existing settings remain.
Claude Code must be able to find `agent-guardrails` on PATH.

VS Code Local harness:

```console
agent-guardrails init --path /path/to/project --harness vscode-local
```

This writes `.github/hooks/pehredaar.json`. Select the Local session target. VS Code agent
hooks are in Preview, and VS Code has announced that the Local harness is deprecated and will
be removed in February 2027; plan to move to the Copilot harness. This file does not configure Copilot Agent Host, Claude, or Codex
session targets.

GitHub Copilot CLI or Agent Host:

```console
agent-guardrails init --path /path/to/project --harness copilot
```

This writes `.github/hooks/pehredaar-copilot.json` using Copilot hook format version 1.
Event names are PascalCase (`PreToolUse`), which selects Copilot's VS Code-compatible mode
with snake_case payloads; Copilot's native names are camelCase (`preToolUse`). Test it with Copilot CLI or the selected Agent Host session. For a cloud
agent job, install `agent-guardrails` in the job environment; an ASK decision becomes DENY
because the job has no user to approve it.

Generic Python agent:

```console
agent-guardrails init --path /path/to/project
```

Use `ExecutionGateway` around dispatch. See the example in the README.

## 3. Resolve the policy

Open `tools.yaml`. Resolve each `TODO`:

```diff
-    scope: TODO
-    reversible: TODO
+    scope: email:send
+    reversible: false
```

Also review:

- inferred read or write effect
- path roots and regex patterns
- maximum string and numeric bounds
- approval rule
- `output_trust`
- `runtime.scopes`
- action limit

Do not mark a tool output untrusted only because its name looks risky. Decide from who can
control the returned data.

## 4. Validate

```console
agent-guardrails doctor --path /path/to/project
```

Then run a known denial.

For Claude Code, ask it to read a path outside every configured root. Confirm the tool is
denied and inspect `/hooks`.

For VS Code Local, select the Local session target, run the same test, and inspect the hook
output channel if it does not fire.

For Copilot, run the same test in Copilot CLI or Agent Host and inspect the hook log. A
Copilot command-hook timeout is fail-open, so keep timeout work small and use policy hooks
for CLI enforcement where administrators manage the host.

## 5. Protect the boundary

- Review-protect `tools.yaml` and hook files.
- Add `.pehredaar/` to `.gitignore`.
- Keep hook commands on PATH for every user and CI runner.
- Use vendor-managed policy when a repository must not disable the hook.
- Add an OS sandbox or network proxy for hard filesystem and egress limits.
- Export the ledger to durable storage when deletion matters.

## Generic hook protocol

Other runtimes can call the hook command if they provide the same documented fields:

- `UserPromptSubmit`: `session_id`, `hook_event_name`, `prompt`
- `PreToolUse`: `session_id`, `cwd`, `tool_name`, `tool_input`
- `PostToolUse`: `session_id`, `tool_name`, `tool_input`, `tool_response`

The output uses `hookSpecificOutput.permissionDecision` with `ask` or `deny`. ALLOW is an
empty object. A runtime adapter must be tested because timeout and failure behavior varies
by host.
