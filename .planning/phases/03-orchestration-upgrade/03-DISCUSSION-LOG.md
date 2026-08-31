# Phase 3: Orchestration Upgrade - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-09-01
**Phase:** 03-orchestration-upgrade
**Areas discussed:** LLM provider constraint conflict, OmX/OmO/clawhip reconstruction scope, agent-loop wiring, session persistence backend, multi-provider LLM task mapping, OmX plan generation, PHASE_FAILED granularity, OmO dispatch model, clawhip CollabWebSocket exclusion, not-yet-built dependency handling (StrategyEvolutionEngine/Research-daemon/TaskRegistry)

---

## LLM provider constraint (pre-discuss-phase, resolved via direct clarification)

| Option | Description | Selected |
|--------|-------------|----------|
| Keep Claude + Ollama, drop DeepSeek | Honor the existing hard constraint | |
| DeepSeek via Ollama only | Feasibility-dependent | |
| Update the constraint instead | Mentor recommendation supersedes original constraint | |
| Multi-model (operator's own framing) | Extend to explicit multi-provider, not swap off Claude | ✓ |

**User's choice:** Option 2 of the follow-up clarification — actually add DeepSeek/other cloud providers alongside Claude and Ollama, updating the constraint.
**Notes:** CLAUDE.md and PROJECT.md's "LLM providers" constraint line was rewritten to explicitly allow multi-provider routing (API-metered spend only, no rented GPU infra). Committed as `b502bcb` before this discussion began.

---

## OmX/OmO/clawhip reconstruction scope

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal DAG planner + coordinator | Just enough to satisfy ROADMAP's success criteria | |
| Full architecture reconstruction | Per OPTIMUS_PRIME_ARCHITECTURE.md §3, larger scope | ✓ |

**User's choice:** Full architecture reconstruction
**Notes:** Flagged that OmX/OmO don't exist (deleted Phase 1) and must be built from scratch, not upgraded — orchestrator.py never calls EngineRouter/InstructionParser/ToolSelector/sub-agents at all today.

---

## Wire the real agent loop

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — wire it as part of OmO | Reconciles instruction_parser.py's SessionState/EngagementSession mismatch and duplicate EngineRouter | ✓ |
| No — OmO stays a logging/status shell | Defers real dispatch wiring to a later phase | |

**User's choice:** Yes — wire it as part of OmO

---

## Session persistence backend (PERSIST-01)

| Option | Description | Selected |
|--------|-------------|----------|
| SQLite | Matches Phase 2's WAL-mode pattern | ✓ |
| JSON file per session | Simpler but no WAL/concurrency story | |

**User's choice:** SQLite

---

## Multi-provider LLMRouter task mapping

| Option | Description | Selected |
|--------|-------------|----------|
| Claude=orchestration, Ollama/Qwen=compaction, DeepSeek=optional extra | Keeps current behavior, adds two new modes | ✓ |
| Fully config-driven, no hardcoded defaults | More flexible, more upfront design | |

**User's choice:** Claude=orchestration, Ollama/Qwen=compaction, DeepSeek=optional extra

---

## clawhip inclusion in reconstruction scope

| Option | Description | Selected |
|--------|-------------|----------|
| Just OmX + OmO for now | ROADMAP.md only names these two | |
| Include clawhip in this phase | All 3 layers built together | ✓ |

**User's choice:** Include clawhip in this phase

---

## OmX plan generation mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| LLM-driven | Claude decomposes request into directive DAG | ✓ |
| Rule/template-based | Reuses InstructionParser's regex patterns, no LLM call | |

**User's choice:** LLM-driven

---

## PHASE_FAILED granularity

| Option | Description | Selected |
|--------|-------------|----------|
| One OmX directive | Whole-directive failure unit | ✓ |
| Every individual tool call | Finer-grained, more WS traffic | |

**User's choice:** One OmX directive

---

## OmO dispatch model

| Option | Description | Selected |
|--------|-------------|----------|
| Sequential only | Simplest correct behavior this phase | ✓ |
| Parallel where DAG allows | Needs concurrency-safety work now | |

**User's choice:** Sequential only

---

## clawhip CollabWebSocket delivery target

| Option | Description | Selected |
|--------|-------------|----------|
| Drop CollabWebSocket delivery | Consistent with existing single-operator exclusion | ✓ |
| Build it anyway | Dead code for an out-of-scope feature | |

**User's choice:** Drop CollabWebSocket delivery
**Notes:** Caught a direct conflict between the architecture doc's clawhip spec (lists CollabWebSocket/RBAC as a delivery target) and PROJECT.md's Out of Scope section (real-time collaboration excluded, matches the v1.1 milestone's F4 drop decision).

---

## Not-yet-built dependency handling (StrategyEvolutionEngine, Research-daemon, TaskRegistry)

| Option | Description | Selected |
|--------|-------------|----------|
| Stub/skip the unbuilt ones, build TaskRegistry for real | Smaller scope | |
| Build minimal stubs for all three now | Larger scope, more speculative code | ✓ |

**User's choice:** Build minimal stubs for all three now
**Notes:** StrategyEvolutionEngine and Research-daemon delivery are v1.1 Phase 9 scope (orphaned today) — stubs only, no real integration. TaskRegistry is core to this phase's own OmO handoff protocol and is built for real either way.

---

## Claude's Discretion

- Exact TaskRegistry schema (in-memory vs. SQLite-backed)
- Exact WebSocket message schema for PHASE_FAILED
- Whether clawhip is a distinct module or a thin layer inside the existing ConnectionManager

## Deferred Ideas

- Parallel OmO dispatch for independent DAG directives — later phase
- Full StrategyEvolutionEngine/ResearchDaemon wiring beyond stubs — v1.1 Phase 9
- CollabWebSocket / multi-user RBAC — explicitly out of scope project-wide
