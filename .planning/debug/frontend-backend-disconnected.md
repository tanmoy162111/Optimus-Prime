---
status: fixing
trigger: "After committing Task 10 (frontend proxy + relative path fix), the frontend shows 'backend disconnected' and no dashboard options work."
created: 2026-04-08T00:00:00Z
updated: 2026-04-08T00:10:00Z
---

## Current Focus

hypothesis: CONFIRMED — backend container is not on the optimus_default network. Docker DNS cannot resolve `backend` from within the frontend container. docker-compose.yml had no explicit `networks:` key, and the backend container ended up with `"Networks": {}` (no network attachment). The Vite proxy target `http://backend:8000` raises `getaddrinfo ENOTFOUND backend` on every request.

test: Confirmed via `docker network inspect optimus_default` — backend container absent. Confirmed via `docker inspect optimus-backend-1` — `"Networks": {}`.
expecting: Fix = add explicit `networks: [optimus_net]` to all non-isolated services + `networks: optimus_net: driver: bridge` at top level. Then `docker compose up -d --force-recreate` to rebuild network assignments.
next_action: Apply fix (done) — user needs to run `docker compose up -d --force-recreate`

## Symptoms

expected: Dashboard connects to backend, directives load, all options work
actual: "Backend disconnected" state, no options respond
errors: None visible in browser console or backend terminal (Vite swallows proxy errors; App.jsx swallows fetch errors)
reproduction: Open the frontend after docker compose up
started: After commits 4909b85 and 5f3c1af (Task 10)

## Eliminated

- hypothesis: Backend crashes on startup due to new module wiring
  evidence: Backend logs show "startup complete" with no errors. All imports resolve. ResearchKB, StrategyEngine, source adapters all instantiate cleanly.
  timestamp: 2026-04-08T00:05:00Z

- hypothesis: Wrong Docker service name in proxy target (`backend` might be named differently)
  evidence: docker-compose.yml line 20 confirms service is named `backend`
  timestamp: 2026-04-08T00:00:00Z

- hypothesis: Vite proxy format change (shorthand → object) broke something
  evidence: Both formats are valid Vite 5.x proxy config. `changeOrigin: true` is a no-op for same-origin Docker service calls but not harmful.
  timestamp: 2026-04-08T00:00:00Z

- hypothesis: WS_BASE construction using window.location.host is wrong
  evidence: `ws://localhost:3000/ws` goes to Vite dev server → Vite WS proxy → `ws://backend:8000`. Architecturally correct. The failure is DNS resolution before the proxy even tries.
  timestamp: 2026-04-08T00:05:00Z

## Evidence

- timestamp: 2026-04-08T00:00:00Z
  checked: docker-compose.yml service definitions
  found: No explicit `networks:` section in the file. Docker Compose assigns default network implicitly.
  implication: Normally safe, but can fail if containers are created/recreated across sessions without proper network re-attachment.

- timestamp: 2026-04-08T00:05:00Z
  checked: frontend container Vite logs
  found: Continuous `Error: getaddrinfo ENOTFOUND backend` on every `/health` REST call and every WS connection attempt. Vite logs these as proxy errors, but App.jsx catch blocks swallow them silently — explaining "no visible browser errors".
  implication: The proxy target hostname `backend` is unresolvable from the frontend container.

- timestamp: 2026-04-08T00:07:00Z
  checked: `docker network inspect optimus_default` — container membership
  found: Network contains: optimus-ollama-1, optimus-kali-1, optimus-frontend-1, optimus-tor-1, optimus-sandbox-1. Backend is ABSENT.
  implication: Backend container was never attached to the compose network. Docker DNS only works within a shared network — `backend` is invisible to other containers.

- timestamp: 2026-04-08T00:08:00Z
  checked: `docker inspect optimus-backend-1` — NetworkSettings.Networks
  found: `"Networks": {}` — the backend container has no network attachments at all.
  implication: Root cause confirmed. Backend is running (responds on 8000/tcp via host port mapping) but is network-isolated from all sibling containers. The Vite proxy inside the frontend container cannot reach it by hostname.

- timestamp: 2026-04-08T00:09:00Z
  checked: Why the OLD code worked (before Task 10 commits)
  found: The old App.jsx used `API_BASE = 'http://localhost:8000'`. The browser made REST calls directly from the host browser to `localhost:8000` → Docker host port mapping → backend. This bypassed the Vite proxy entirely. The Vite proxy config `localhost:8000` was also broken (same DNS issue) but was never exercised because App.jsx sent requests to the absolute URL.
  implication: The Task 10 switch to relative paths + Vite proxy is architecturally correct for Docker — it just exposed the pre-existing network misconfiguration that was always latent.

## Resolution

root_cause: The `optimus-backend-1` container has `"Networks": {}` — it is attached to no Docker network. When the Vite dev server (running inside `optimus-frontend-1`, which IS on `optimus_default`) tries to proxy REST and WS requests to `http://backend:8000`, Docker DNS cannot resolve the hostname `backend` because backend is not a member of any shared network. The error `getaddrinfo ENOTFOUND backend` fires on every request, but App.jsx and the WebSocket hook silently swallow all errors, producing the "backend disconnected" symptom with no visible console output.

The underlying trigger: docker-compose.yml had no explicit `networks:` section. When the backend container was last created (23+ hours ago), it ended up without network attachment — possibly due to a compose version behavior difference or a stale container from before the compose file was established. The missing network assignment was never noticed because the old absolute-URL approach bypassed the proxy.

fix: Added explicit `networks: [optimus_net]` to all 6 non-isolated services (frontend, backend, kali, ollama, tor, sandbox) and added `networks: optimus_net: driver: bridge` declaration at the top-level of docker-compose.yml. The `ml-runtime` and `ics-runtime` services retain `network_mode: "none"` as intentionally isolated. User must run `docker compose up -d --force-recreate` to recreate containers with correct network assignments.

verification: Pending human verification
files_changed:
  - docker-compose.yml
