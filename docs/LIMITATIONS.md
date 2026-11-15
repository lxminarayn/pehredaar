# Limitations

## Enforcement

- Only calls routed through `ExecutionGateway` or a supported hook are checked.
- A subprocess can create side effects that are not visible as separate tool calls.
- Generated Claude Code hooks set `onFailure: block` (Claude Code 2.1.295+), so a crashed or
  timed-out pre-tool hook denies the call rather than failing open. Older Claude versions
  and any hook without the field fall back to normal processing.
- VS Code agent hooks are Preview, and the VS Code Local harness is deprecated (removal
  announced for February 2027).
- GitHub Copilot CLI and Agent Host are supported. Copilot cloud jobs need the command in
  the job image and treat ASK as DENY because no user is present.
- Copilot command-hook timeouts are fail-open, including pre-tool hooks. Its CLI policy
  hooks are the stronger option for administrator-controlled machines.
- Codex and other provider schemas are not implemented in this release.
- Claude Code `PreToolUse` does not cover files attached with `@`. Use vendor read-deny
  rules for sensitive paths.
- "Fail-open" on a hook timeout means the call falls through to the harness's normal
  permission flow, not that Pehredaar allowed it.

## Identity and scope

- The Python gateway accepts scopes from a caller. The caller must authenticate that data.
- The policy checks that a principal is present and that its scopes include the tool's scope. It
  does not look the principal up in a registry.
- Generated hook policies use a local static principal. They do not forward enterprise
  identity or prove user delegation.
- Signed run tokens do not provide revocation or replay storage. Keep lifetimes short. The
  OpsTriage demo passes scopes directly and does not verify a token.
- The hook records the latest `UserPromptSubmit` as the original request. In Claude Code that
  event also fires for scheduled tasks, background subagent reports and messages from other
  sessions, so the original-request binding trusts whatever the harness calls a prompt.

## Provenance and intent

- Taint is coarse. Once a configured untrusted or sensitive tool succeeds, later calls keep
  that label for the rest of the run. A new prompt in the same hook session starts a new action
  budget but keeps the labels, because earlier output may still be in the model's context.
- Taint does not survive arbitrary serialization, native extensions, or model paraphrasing.
- The intent-capsule binding is an exact-match check on bound arguments. It stops a changed
  customer id or account, not a semantically equivalent value expressed differently.
- The lexical intent signal is a weak heuristic. It misses paraphrases and can match generic
  terms, so it is off by default in generated hook policies and never the only control.
- The trifecta rule is per-run and depends on tools declaring `output_trust` and `egress`
  honestly. It does not track data laundered through an intermediate trusted tool.
- Pehredaar does not inspect hidden model reasoning.

## Arguments and URLs

- Typed schemas constrain shape, not business meaning.
- Path validation has a check-to-use race if another process swaps a filesystem object.
  Mount allowed roots read-only or execute through an OS sandbox when this matters.
- URL checks cover HTTP and HTTPS tool arguments routed through the adapter. They do not
  control DNS rebinding, proxy behavior, redirects, or subprocess sockets.
- Path-scoped URL rules require enforcement again at the network proxy for a hard boundary.

## Supply chain and code execution

- MCP pinning detects changed tool metadata. It does not detect a server that misbehaves
  behind an unchanged schema, and the lock file must be reviewed and version controlled.
- `static_gate` is a cheap AST pre-filter, not a sandbox. It is bypassable by design; the
  container is the boundary.
- `run_python` needs Docker or Podman and shares the host kernel. Use gVisor
  (`runtime="runsc"`) or a microVM for genuinely hostile code. The container keeps the
  image's own baked environment; only host environment variables are withheld. Pin the image
  by digest, because a tag can move.
- The output cap limits what the agent sees, not what the container writes. Memory, process and
  time limits bound the container itself.

## Persistence

- Local approvals and ledgers use advisory locks. Network filesystems may not honor them.
- The ledger detects record edits, reordering, and broken chains. It is unkeyed, so anyone who
  can rewrite the file can recompute the chain. It cannot detect deletion of the whole ledger or
  truncation at the tail without an external checkpoint.
- Approval files contain literal arguments. Protect the state directory from other users.
- Approval storage is local JSON, not a multi-user workflow service. An approval is bound to the
  run, step, tool and arguments, and can be consumed once. It is not a signed decision from an
  authenticated approver.

## Isolation

- `sandbox.yaml` is a profile, not a container launcher.
- In-process URL checks are not process isolation.
- Docker, gVisor, microVM, credential broker, and egress proxy setup remain deployment work.

## Evaluation

- The attack corpus scorecard is a deterministic simulation over declared signals. It does not
  run attacks against a live agent.
- The demo transcript and content scanner execute real code. The scanner result (20 of 26 cases
  flagged, 0 of 6 adaptive variants) is for a toy keyword scanner on a corpus written for this
  repository. It is an illustration, not a measurement of any real product.
- OpsTriage replays fixed model proposals and simulates customers, payments and the network. The
  policy, approval store, ledger and (with `--image`) container are real.
- No latency or throughput benchmark is published. Do not quote one without measuring.
- Token multipliers for dual-LLM designs are estimates.
- The corpus is not a compliance test or OWASP certification.

## OWASP coverage gaps

- ASI06: untrusted tool outputs are tainted, but long-term memory stores are not wrapped.
- ASI07: no authenticated inter-agent message protocol is included.
- ASI08: action and write budgets limit one run, but distributed cascade control is absent.
- ASI09: literal approvals reduce summary deception; approval fatigue remains.
- ASI10: unregistered tools fail closed, but rogue process containment needs
  the host and OS sandbox.
