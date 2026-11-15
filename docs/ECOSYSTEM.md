# Ecosystem fit

Pehredaar overlaps with established open-source policy and AI safety projects. It should be
used with them when their stronger feature set fits the deployment.

| Project | Primary role | Relation to Pehredaar |
| --- | --- | --- |
| OpenAI Agents SDK | Native input, output, and per-tool guardrails | Prefer native tool guardrails for OpenAI function tools. Hosted and built-in tool coverage differs. |
| NVIDIA NeMo Guardrails | Input, dialog, retrieval, execution, and output rails | Broader model and conversation safety. More dependencies and configuration. |
| Meta LlamaFirewall | Prompt, alignment, regex, and generated-code scanners | Detection layer. Pehredaar is a deterministic authorization layer. |
| Invariant Guardrails (now part of Snyk) | Contextual policies over LLM and MCP traces, with a gateway | Closest overlap. Prefer it for transparent MCP and trace policy enforcement. Active work continues as `snyk/agent-scan`. |
| OPA | General policy engine using Rego | Prefer it for mature organization-wide policy distribution and tooling. |
| Cedar | Analyzable authorization language and SDK | Prefer it for RBAC or ABAC at scale and formal policy analysis. |
| MCP Context Protector | MCP server pinning and response quarantine | Prefer it when MCP configuration drift and response quarantine are the main risks. |
| Guardrails AI | Input and output validators and structured model data | Complements tool authorization; it does not replace execution enforcement. |
| Structured outputs (`strict` JSON schemas) | Guarantee the shape of a tool call at generation time | Complementary. A schema cannot know the turn-0 binding, the run's taint, or whether a value belongs to this customer. The gateway re-validates arguments anyway. |
| gVisor, Firecracker, E2B, Daytona, Modal Sandboxes | Stronger isolation for generated code: user-space kernel, microVMs, managed sandboxes | Replace `run_python`'s Docker runner for hostile code. Check each service's isolation layer and network default; E2B sandboxes have internet access unless you disable it. |
| RAGAS, DeepEval, promptfoo | Offline evaluation of answer quality and behaviour | Measurement, not enforcement. Add known denials to the eval suite. |
| garak, PyRIT | Red-team scanners that probe for failures | Run them against the guarded agent before each release. |

## Pehredaar's scope

Pehredaar combines these items in one small local reference:

- typed tool capabilities
- delegated scopes
- coarse output provenance
- action and write budgets
- persisted single-use approvals
- hash-chained audit records
- Claude Code, VS Code Local, and GitHub Copilot hooks
- a talk demo that reports both attack success and benign completion

That combination is useful for learning, prototypes, and small self-hosted agents. It is not
proof that the project is unique or more complete than the projects above.

## Primary sources

- [Claude Code hooks reference](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [VS Code agent hooks](https://code.visualstudio.com/docs/copilot/customization/hooks)
- [VS Code Local hooks reference](https://code.visualstudio.com/docs/agents/reference/hooks-reference)
- [GitHub Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [OpenAI Agents SDK guardrails](https://openai.github.io/openai-agents-python/guardrails/)
- [NVIDIA NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails)
- [Meta LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
- [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant)
- [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/)
- [Cedar](https://www.cedarpolicy.com/)
- [MCP Context Protector](https://github.com/trailofbits/mcp-context-protector)
- [Guardrails AI](https://www.guardrailsai.com/docs)
- [gVisor](https://gvisor.dev/docs/), [Firecracker](https://firecracker-microvm.github.io/),
  [E2B](https://e2b.dev/docs), [Daytona](https://www.daytona.io/),
  [Modal Sandboxes](https://modal.com/docs/guide/sandboxes)
- [garak](https://github.com/NVIDIA/garak), [PyRIT](https://github.com/Azure/PyRIT)

## Guidance this maps to

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [*Careful adoption of agentic AI services*](https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-release-guide-secure-adoption-agentic-ai)
  (ASD's ACSC with CISA, NSA and partners, May 2026). It calls least privilege critical and asks
  for prior human approval of high-impact actions.
- [Meta, Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)

The mapping is the author's reading, not a certification.

Sources were checked on 15 November 2026.
