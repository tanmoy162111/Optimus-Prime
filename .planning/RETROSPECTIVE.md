# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.0 — Foundation Stabilization

**Shipped:** 2026-09-05
**Phases:** 4 | **Plans:** 24 | **Timeline:** 2026-05-12 → 2026-09-05 (116 days, 170 commits)

### What Was Built
- Fixed the platform's core defect (wrong Claude model ID causing silent 404→Ollama fallback) and deleted the entire dead legacy backend system
- Closed the RCE risk in generated-tool execution (host subprocess → isolated Docker container), added per-engagement Kali workdir isolation and SQLite WAL mode
- Built the real orchestration pipeline: OmX (validated planning DAG) → OmO (sequential dispatch with PHASE_FAILED guarantees) → wired end-to-end into the Orchestrator, plus disk-backed session persistence
- Componentized the frontend: `App.jsx` monolith → slim composition root, protocol-correct `ChatPane`, 9 fault-isolated panels, context-based session state

### What Worked
- Wave-based parallel execution with git worktree isolation scaled cleanly across Phase 4's 7 plans — independent plans (panel extractions) ran genuinely in parallel with zero merge conflicts across 3 separate 3-way waves
- The `gate="blocking-human"` checkpoint pattern for package-legitimacy audits (Phase 04-01) correctly resisted `workflow.auto_advance`'s normal auto-approve behavior, forcing real human sign-off on a slopcheck false-positive rather than silently trusting it
- Verbatim-extraction plans (04-05, 04-06) with an explicit "PATTERNS.md rates all five 'exact'" contract kept high-risk refactors (extracting 8 stateful panels from a 1505-line file) low-risk in practice
- When the Chrome browser extension wasn't connected for a browser-verification checkpoint, falling back to Playwright and doing genuine React-fiber-tree inspection (not just visual screenshotting) caught real signal: confirmed `ChatPane` in the live tree, confirmed 9 `ErrorBoundary` instances, and actually forced+reverted a panel crash to prove isolation — rather than rubber-stamping the checkpoint

### What Was Inefficient
- `REQUIREMENTS.md` traceability went stale after Phase 3 closed (ORCH-01/02/03, PERSIST-01 stayed marked "Pending" despite Phase 3's own VERIFICATION.md independently confirming all 4 complete) and wasn't caught until milestone close — the per-phase `update_roadmap` step's requirements-traceability update apparently didn't fire or was skipped between sessions
- This sandbox environment cannot run the project's own backend (Python 3.14 incompatible with pinned `pydantic-core`/`tiktoken` build requirements) or the full docker-compose stack (Kali + ML-runtime, ~25GB combined), which meant two phases in a row (01, 04) ended in `human_needed` verification status for the same underlying reason — a recurring, architecturally-inherent gap for this project (operator-managed Kali/backend) rather than a one-off

### Patterns Established
- Manifest-scoped worktree cleanup with a pre-merge deletion-diff guard (flag any branch that deletes files outside the plan's declared scope) caught nothing wrong in this milestone but is now standard practice — cheap insurance against a wayward parallel agent
- Explicit sandbox-limitation disclosure (rather than silently skipping or silently claiming success) for anything requiring the operator's live Kali/backend — logged in `*-HUMAN-UAT.md`, `*-VERIFICATION.md`, and `STATE.md`'s Deferred Items consistently across phases

### Key Lessons
1. Don't trust per-phase automated requirements-traceability updates blindly — cross-check `REQUIREMENTS.md` against each phase's own `*-VERIFICATION.md` at milestone close; the two can drift silently across session boundaries.
2. A `gate="blocking-human"` (or similarly hard-coded non-auto-approvable) checkpoint type is worth its overhead specifically for package-legitimacy and other supply-chain-adjacent decisions — `workflow.auto_advance=true` should never quietly wave those through.
3. For a project whose core value depends on an operator-managed external system (Kali over SSH), expect recurring "verified in code/tests, pending live confirmation" splits at every phase boundary that touches that integration — build the HUMAN-UAT tracking habit early rather than treating each occurrence as a one-off surprise.

### Cost Observations
- Not tracked with per-model granularity in this session; no reliable data to report without fabricating numbers.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Sessions | Phases | Key Change |
|-----------|----------|--------|------------|
| v1.0 | multiple (2026-05-12 → 2026-09-05) | 4 | Established wave-based worktree execution, `gate="blocking-human"` package-legitimacy checkpoints, explicit HUMAN-UAT tracking for backend-dependent verification |

### Cumulative Quality

| Milestone | Tests | Coverage | Zero-Dep Additions |
|-----------|-------|----------|---------------------|
| v1.0 | 144 (backend) + 36 (frontend Vitest) | Not measured | Frontend Vite/Vitest/Testing-Library toolchain corrected (was silently broken) |

### Top Lessons (Verified Across Milestones)

1. Cross-check automated tracking artifacts (REQUIREMENTS.md, ROADMAP.md) against each phase's own VERIFICATION.md at milestone boundaries — don't assume per-phase automation always fires correctly.
