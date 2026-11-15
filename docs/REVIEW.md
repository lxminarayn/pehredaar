# Security assumptions

## Trusted

- policy files after human review
- the Python package and installed hook command
- the host's event fields
- the caller that supplies Python gateway identity and scopes
- the local filesystem locking implementation

## Untrusted

- model output
- user and issue content
- repository instructions
- tool output marked `output_trust: untrusted`
- tool names not present in `tools.yaml`
- paths before canonicalization
- URLs before canonicalization

## Fail-closed behavior

- malformed or unknown tool schemas fail loading
- unresolved `scope` or `reversible` fields fail loading
- missing principal denies
- missing provenance asks
- unknown tools deny
- a cross-tenant argument that breaks a turn-0 capsule binding denies
- untrusted input plus sensitive data reaching an egress tool denies (lethal trifecta)
- an argument over its `ask_above` threshold asks
- a failing per-tool `Check` (IBAN match, AST gate) denies
- malformed hook JSON returns a deny decision
- policy exceptions deny

## Host-dependent behavior

Generated Claude Code hooks set `onFailure: block` (Claude Code 2.1.295+), so a crashed or
timed-out pre-tool hook denies the call. Copilot command-hook timeouts remain fail-open, and
older hosts fall back to normal processing. Use managed deny rules for controls that must
survive hook failure on every host.

## Test evidence

Tests cover:

- direct execution without scope
- path traversal and symlink escape, including host `cwd` that cannot widen policy roots
- invalid YAML security fields
- boolean and numeric type confusion
- regex full match and multiple allowed roots
- turn-0 capsule bindings in the signed run token
- the lethal-trifecta deny and `ask_above` threshold ask
- URL port and path canonicalization and the gateway egress profile
- concurrent approval decisions and single-use approval consumption
- the approver named in the ledger and budget checked before an approval is spent
- untrusted and sensitive output tainting the run; dispatch errors recorded
- concurrent ledger append with taint labels and timestamps
- MCP manifest pinning and the AST static gate
- the OpsTriage demo blocking every attack by its named control, and running it unguarded
- a pinned-out MCP tool being uncallable, a rejected approval causing no side effect, and the
  console approver failing closed when no person answers
- slide snapshots matching what the OpsTriage code prints today
- an OpsTriage `--state-dir` ledger that reruns reset and a one-line edit marks as tampered
- non-finite numbers (NaN, infinity) rejected by argument bounds
- a new hook prompt keeping taint while starting a new budget
- the step-5 ledger recording every proposal, including schema denials
- a locked container removed after a timeout, and snippets that pass the static gate still
  stopped by the container (skipped when no container engine is running)
- a locked container running clean code and denying network (skipped without an engine)
- Claude Code, VS Code Local, and Copilot hook installation and argument bounds
- corpus claims, benign twins, and deterministic recordings

## Deployment review

Before production use, verify:

- every side effect reaches the gateway or hook
- vendor upgrades preserve event schemas
- the policy directory is protected from the agent
- the CLI is on PATH for all harness processes
- the state directory has suitable access controls
- an OS sandbox enforces filesystem, process, credential, and network limits
- ledger checkpoints are stored outside the agent account
