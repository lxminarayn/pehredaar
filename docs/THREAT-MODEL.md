# Demo threat model

## Lethal trifecta

| Leg | Present | Evidence |
| --- | --- | --- |
| Private data | Yes | `read_file` can read repository files in the baseline |
| Untrusted content | Yes | anyone can file the seeded issue |
| Outward action | Yes | `open_pr` and `post_comment` write external-style artifacts |

Count: 3 of 3.

The demo removes or constrains each leg in stages. The local pull-request sink keeps the
payload inert.

## Controls

| Risk | Surface | Control |
| --- | --- | --- |
| ASI01 Goal hijack | issue and repository text | provenance, intent signal, approval |
| ASI02 Tool misuse | paths, strings, numeric bounds | strict `tools.yaml` validation |
| ASI03 Privilege abuse | principal and scopes | identity check and delegated scopes |
| ASI04 Supply chain | dependency manifest | residual; close in CI and package policy |
| ASI05 Code execution | shell and network tools | approval, URL policy, external OS sandbox |

## Residual risk

ASI04-003 adds a plausible dependency during an in-scope, reversible edit. The agent policy
cannot prove that the package is approved or exists in the internal index.

Owner: repository and CI policy.

Required controls:

- pinned internal package index
- lockfile or hashes
- approved package inventory
- CI check that rejects unknown package names

## Out-of-scope system controls

- durable memory policy for ASI06
- authenticated inter-agent messages for ASI07
- distributed cascade limits for ASI08
- product design for approval fatigue in ASI09
- OS containment for rogue processes in ASI10

## OpsTriage (the live demo)

A support agent with four tools. The model is simulated with fixed proposals; the policy,
approval store, ledger and (with `--image`) container are real.

| Leg | Present | Evidence |
| --- | --- | --- |
| Private data | Yes | `query_customer_db` returns billing records and PII (`output_trust: sensitive`) |
| Untrusted content | Yes | anyone can file a ticket (`read_support_ticket`, `output_trust: untrusted`) |
| Outward action | Yes | `run_diagnostic_script` is an egress tool; `issue_refund` moves money |

Count: 3 of 3.

| Scene | Risk | Control that stops it | Where it lives |
| --- | --- | --- | --- |
| A1 | ASI01 goal hijack, ASI02 | turn-0 customer binding (`policy.capsule`), trifecta rule (`policy.trifecta`) | `guardrails/policy.py` |
| A2 | ASI04 supply chain | MCP pin mismatch removes the tool from the registry (`policy.unregistered_tool`); destination check on the refund (`policy.iban`) | `guardrails/manifest.py`, the example's `Check` |
| A3 | ASI02, ASI03, ASI09 | destination check; tainted write asks a person who sees the exact action | `guardrails/gateway.py`, `guardrails/approval.py` |
| A4 | ASI05 | `sandbox.static_gate` (a speed bump) | `guardrails/sandbox.py` |
| A5 (`--image`) | ASI05 | the container: no network, read-only root, no host environment | `guardrails/sandbox.py` |

Residual risk the demo does not cover: a refund to the customer's own verified account for a
fabricated reason passes every check except the human, and the human can be persuaded. Backend
authorization (is this charge refundable, by this user, once) must live in the payment system.
Owner: the team that owns the refund service.
