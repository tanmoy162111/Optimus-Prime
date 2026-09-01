# Deferred Items — Phase 03: Orchestration Upgrade

## From Plan 03-07 (instruction_parser.py reconciliation)

- **`tests/api/test_auth.py::test_chat_without_token_returns_401` fails** — asserts `response.status_code == 401` but gets `403`. This is a pre-existing failure unrelated to `backend/agent/instruction_parser.py` or `backend/agent/engine_router.py` (the files touched by plan 03-07). Root cause is almost certainly a FastAPI/Starlette `HTTPBearer` version behavior change (missing-credentials now returns 403 rather than 401) — out of scope for this plan's dedupe/retype task. Not fixed here per the executor's scope-boundary rule (only auto-fix issues directly caused by the current task's changes). Logged for future triage.
