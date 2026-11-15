# Threat Model

## Lethal trifecta

- Private data access: {{PRIVATE_DATA}}
- Untrusted content exposure: {{UNTRUSTED_CONTENT}}
- External communication: {{EXTERNAL_COMMUNICATION}}
- Present legs: {{TRIFECTA_COUNT}} / 3

Remove at least one leg before deployment.

## Controls

| Risk | Attack surface | Control | Status |
| --- | --- | --- | --- |
| ASI01 | Goal and context hijack | intent signal, provenance, approval | Review |
| ASI02 | Tool misuse | typed arguments, gateway, budgets | Review |
| ASI03 | Privilege abuse | principal and delegated scopes | Review |
| ASI04 | Supply chain | package and MCP policy outside the agent | Review |
| ASI05 | Code execution | hook or gateway plus an OS sandbox | Review |
| ASI06 | Memory and context poisoning | output trust and memory-store policy | Review |
| ASI07 | Inter-agent communication | authenticated sender and message policy | Review |
| ASI08 | Cascading failures | action and write budgets; distributed limits | Review |
| ASI09 | Human-agent trust | literal approval details and fatigue controls | Review |
| ASI10 | Rogue agents | registered identity and OS containment | Review |

## Residual risk

Name one attack that still succeeds: {{RESIDUAL_RISK}}

State which controls live outside Pehredaar: {{EXTERNAL_CONTROLS}}
