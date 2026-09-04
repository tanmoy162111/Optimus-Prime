---
status: partial
phase: 04-frontend-split
source: [04-VERIFICATION.md]
started: 2026-09-05T00:45:00Z
updated: 2026-09-05T00:45:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Live chat round-trip against a real backend
expected: ChatPane transitions from "disconnected" to session-acked (dot-live) after the {type:'session'} frame; a typed message produces a streamed assistant response; App.jsx's sessionId/chatConnected state (and therefore SessionContext) reflect the live session.
result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
