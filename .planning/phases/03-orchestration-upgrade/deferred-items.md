# Deferred Items — Phase 03: Orchestration Upgrade

Issues discovered during execution that are out of scope for the current plan/task
(pre-existing, unrelated to files touched by this plan). Logged per executor scope
boundary rules — not fixed here.

## `tests/api/test_auth.py::test_chat_without_token_returns_401` — FAILING (pre-existing)

Asserts `response.status_code == 401` when no `Authorization` header is sent to
`POST /api/chat`, but FastAPI's `HTTPBearer` dependency returns `403 Forbidden`
(not `401 Unauthorized`) when the header is entirely absent — 401 is only returned
when a bearer token is present but invalid. Root cause is almost certainly a
FastAPI/Starlette `HTTPBearer` version behavior change. Unrelated to any files
touched by Wave 1 plans. Candidate fix (future plan): either update the test's
expectation to 403, or configure `HTTPBearer(auto_error=False)` with a custom
401-raising check in `backend/auth.py`.

Independently observed and logged by:
- Plan 03-01 (full-suite verification, Task 1-3 completion check)
- Plan 03-07 (instruction_parser.py reconciliation)
