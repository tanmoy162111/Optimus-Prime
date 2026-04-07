# Optimus Pipeline Resilience & Exploitation Mode Design
**Date:** 2026-04-07  
**Status:** Approved  
**Scope:** Findings pipeline, exploitation modes, scope discovery, tool resilience, backend error handling

---

## 1. Problem Summary

| # | Problem | Symptom |
|---|---------|---------|
| 1 | Findings pipeline drops findings | 90-112 findings generated, only 3-4 in report with LOW risk |
| 2 | Scope discovery produces 0 findings | OSINT tools fail silently for internal/IP targets |
| 3 | Exploitation ends too fast | CONTROLLED mode has no confirmed findings to work with |
| 4 | No two-phase exploitation | No escalation path from CONTROLLED to FULL within same engagement |
| 5 | Tool failures abort agents | tool_not_found, timeouts, LLM JSON errors propagate unhandled |
| 6 | Blanket 300s SSH timeout | Slow tools (nmap, nikto) hit timeout before completing |

---

## 2. Root Causes

**Finding pipeline:**  
`VerificationLoop._classify_result()` returns `FALSE_POSITIVE` whenever the verification tool itself fails (Kali unreachable, tool not installed, SSH timeout). This is incorrect — a tool failure does not prove the finding is false. Only 3-4 findings whose verification tools happened to work become CONFIRMED; the reporter uses only those.

**Scope discovery 0 findings:**  
OSINT tools (crt_sh, whois, shodan, dns_enum, github_scan) make outbound HTTP calls from inside the Kali container. For RFC-1918 targets (10.x, 172.16-31.x, 192.168.x) these tools return nothing useful. No fallback generates findings from the seed target itself.

**Exploitation ends fast:**  
ExploitAgent CONTROLLED mode calls `_load_confirmed_findings()` from EventBus. With 3-4 confirmed findings, the fallback runs only 4 generic steps. LLM may also decide `is_terminal: true` after the first step.

**No two-phase exploitation:**  
A single `exploit` phase exists. CONTROLLED and FULL are mutually exclusive per engagement. No escalation gate between them.

**Tool failures:**  
`BaseAgent.run_loop()` does not handle `tool_not_found` status specially — it just logs and continues. No alternative tool lookup, no auto-install, no command correction.

**Timeout:**  
`COMMAND_TIMEOUT = 300` applies to every tool equally via the Python-side SSH channel. Tools like nmap, nikto, and masscan frequently need more than 300s for thorough scans. There is no Kali-side enforcement via `timeout` prefix.

---

## 3. Design

### 3.1 Findings Pipeline Fix

#### 3.1.1 VerificationLoop — Fix Classification Logic

**File:** `backend/verification/verification_loop.py`

Change `_classify_result()` to distinguish *tool failure* from *finding absence*:

```
Tool failure (error from Kali infrastructure):
  - status == "error" AND error contains: "not found", "connection", "timeout", "unreachable"
  → MANUAL_REVIEW  (tool could not run — finding neither confirmed nor refuted)

Finding absence (tool ran, produced no evidence):
  - status == "success" but output empty or no matching indicators
  → FALSE_POSITIVE

Finding confirmed:
  - status == "success" + output contains port/open/HTTP indicators
  → CONFIRMED
```

#### 3.1.2 IntelligentReporter — All Findings with Verification Status

**File:** `backend/intelligence/intelligent_reporter.py`

- `_on_finding_event` stores verification status on each cached finding as it arrives:
  - FINDING_CREATED → status = "unverified"
  - FINDING_CLASSIFIED(confirmed) → status = "confirmed"
  - FINDING_CLASSIFIED(false_positive) → status = "false_positive"
  - FINDING_CLASSIFIED(manual_review) → status = "manual_review"
- `get_findings_for_report()` returns `_all_findings` (full set), each annotated with `verification_status`
- All 6 report generators include `verification_status` per finding
- Executive summary severity calculation uses the full finding set (90-112), producing accurate risk levels
- False positives are included in report but visually flagged; operators can filter them

#### 3.1.3 Report Schema Change

Every finding dict in all report generators gains:
```json
{
  "finding_id": "...",
  "title": "...",
  "severity": "...",
  "verification_status": "confirmed | manual_review | unverified | false_positive",
  ...
}
```

---

### 3.2 Scope Discovery — Target Auto-detection

**File:** `backend/agents/scope_discovery_agent.py`

#### 3.2.1 Target Type Detection

New method `_detect_target_type(target: str) -> str`:
- RFC 1918 IP (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) → `"internal"`
- Routable IP → `"public_ip"`
- Domain name (contains letters, no CIDR) → `"public_domain"`

#### 3.2.2 Tool Routing by Target Type

`_plan_fallback()` selects tool set by target type:

| Target Type | Tools Used |
|-------------|-----------|
| `internal` | `nmap` (full port), `whatweb`, `dns_enum` |
| `public_ip` | `shodan` (InternetDB), `nmap`, `whatweb`, `whois` |
| `public_domain` | `crt_sh`, `whois`, `shodan`, `dns_enum`, `github_scan` |

#### 3.2.3 Scope Anchor Finding (guaranteed minimum)

After all tools run (even if all return empty), `execute()` generates a "scope anchor" finding:
```json
{
  "finding_id": "scope-anchor-<hash>",
  "title": "Target in scope: <target>",
  "severity": "info",
  "tool": "scope_discovery",
  "description": "Seed target confirmed in engagement scope"
}
```
This guarantees scope discovery always produces ≥ 1 finding.

---

### 3.3 Two-Phase Exploitation with Human Escalation Gate

**File:** `backend/core/omx.py`

#### 3.3.1 Phase Structure

`_pentest_phases()` splits the single `exploit` phase into two sequential phases:

```
exploit_controlled:
  agent: ExploitAgent
  mode: CONTROLLED (confirmed findings only)
  gate: human — "Operator approval required before controlled exploitation"
  depends_on: ["scan"]
  metadata: {exploit_mode: "controlled"}

exploit_full:
  agent: ExploitAgent
  mode: FULL (all discovered services, aggressive)
  gate: human — "CONTROLLED exploitation complete. Escalate to FULL freehand mode? 
                  Type confirm-exploit_full to proceed or skip-exploit_full to abort."
  depends_on: ["exploit_controlled"]
  metadata: {exploit_mode: "full"}
```

#### 3.3.2 Operator Flow

1. Operator runs `$pentest <target>`
2. Gate fires before `exploit_controlled` — operator types `confirm-exploit_controlled`
3. CONTROLLED exploitation runs — results appear in terminal
4. Gate fires before `exploit_full` — operator sees full CONTROLLED results, decides
5. Operator types `confirm-exploit_full` (escalate) or `skip-exploit_full` (skip to verify)
6. Engagement continues to verification phase either way

#### 3.3.3 `--freehand` Flag Behavior (preserved)

`$pentest --freehand <target>`:
- Skips `exploit_controlled` phase entirely
- Runs only `exploit_full` (FULL mode) with its human gate
- Existing behavior fully preserved

#### 3.3.4 ExploitAgent — Confirmed Findings Fallback

**File:** `backend/agents/exploit_agent.py`

In CONTROLLED mode, if `_confirmed_findings` is empty after loading from EventBus, fall back to all FINDING_CREATED findings (unverified) rather than running 4 generic steps. This ensures the controlled run has meaningful targets even when verification classified everything as MANUAL_REVIEW.

---

### 3.4 Tool Resilience — ToolFallbackResolver

**New file:** `backend/core/tool_fallback.py`

#### 3.4.1 Class: `ToolFallbackResolver`

Called from `BaseAgent.run_loop()` when a tool returns `tool_not_found` status or a command error (non-zero exit with unexpected stderr).

Resolution priority order:

**Step 1 — Alternative tool table**
```python
TOOL_ALTERNATIVES = {
    "sublist3r":  ["amass", "dnsrecon"],
    "amass":      ["sublist3r", "dnsrecon"],
    "dalfox":     ["nuclei"],  # with XSS templates
    "masscan":    ["nmap"],    # with -T4 -p-
    "wpscan":     ["nikto", "nuclei"],
    "commix":     ["sqlmap"],
    "payload_crafter": ["msfvenom"],
    "dnsrecon":   ["dig", "host"],
    "whatweb":    ["curl"],    # basic HTTP probe
    "github_scan": [],         # no alternative
    "crt_sh":     [],          # no alternative (OSINT only)
}
```
Returns the first available alternative that hasn't already been tried in this iteration.

**Step 2 — Auto-install**
If no alternative exists (or all alternatives also not found):
```bash
apt-get install -y -q <tool> 2>/dev/null || pip3 install <tool> 2>/dev/null
```
Timeout: 120s. On success, retry original tool. On failure, continue to Step 3.

**Step 3 — Pattern-based command correction**
For command errors (tool exists but exits non-zero), apply known fixes:
```python
COMMAND_FIXES = {
    "masscan":    lambda cmd: cmd + " --rate=500" if "--rate" not in cmd else cmd,
    "msfconsole": lambda cmd: cmd.replace("msfconsole", "msfconsole -q"),
    "nuclei":     lambda cmd: cmd + " -t cves/" if "-t " not in cmd else cmd,
    "ffuf":       lambda cmd: cmd + " -mc 200,301,302" if "-mc" not in cmd else cmd,
    "sqlmap":     lambda cmd: cmd + " --batch" if "--batch" not in cmd else cmd,
}
```

**Step 4 — LLM correction**
Send failed command + stderr to LLM:
> "This command failed on Kali Linux: `<command>`\nError: `<stderr[:300]>`\nSuggest a corrected command. Return only the command, no explanation."

Parse response as plain text command string. Retry once.

**Step 5 — ResearchKB query**
Query `ResearchKB` with `tool_name + error_substring` to find known issues/fixes from indexed NVD/ExploitDB/GitHub PoC data.

**Step 6 — Live web query via Kali**
```bash
timeout 10 curl -s "https://api.github.com/search/code?q=<tool>+kali+linux+install&per_page=3" 2>/dev/null
```
Parse response for install commands or usage hints. Log result to terminal.

#### 3.4.2 BaseAgent Integration

`BaseAgent.run_loop()` change:
```
After _execute_with_permissions():
  if result.output is dict and result.output.get("status") == "tool_not_found":
    resolution = await tool_fallback_resolver.resolve(tool_name, tool_input, error)
    if resolution.alternative_tool:
      retry result with alternative tool
      log: "⚠ [tool_name] not found → using [alternative] instead"
    elif resolution.install_succeeded:
      retry original tool
      log: "⚠ [tool_name] auto-installed, retrying"
    else:
      log: "✗ [tool_name] unavailable — skipping"
      continue loop (skip this iteration)
```

---

### 3.5 Dynamic Kali-Side Timeouts

**File:** `backend/tools/backends/kali_ssh.py`

#### 3.5.1 Remove Python-side Hard Cap

`COMMAND_TIMEOUT` raised from 300s to 3600s — true last-resort only for catastrophic SSH channel hangs. Per-tool enforcement moves to the Kali shell level.

#### 3.5.2 Per-Tool Timeout Table

Applied in `_build_command()` via `timeout <N>` prefix or tool-native flags:

| Tool | Timeout | Method |
|------|---------|--------|
| `nikto` | 90s | `-maxtime 90` flag |
| `nuclei` | 60s | `timeout 60 nuclei` |
| `nmap` | 180s | `timeout 180 nmap` |
| `masscan` | 120s | `timeout 120 masscan` |
| `sqlmap` | 180s | `timeout 180 sqlmap` |
| `dalfox` | 60s | `timeout 60 dalfox` |
| `ffuf` | 90s | `timeout 90 ffuf` |
| `commix` | 120s | `timeout 120 commix` |
| `msfconsole` | 300s | `timeout 300 msfconsole` |
| `dnsrecon` | 60s | `timeout 60 dnsrecon` |
| `sublist3r` | 60s | `timeout 60 sublist3r` |
| `amass` | 120s | `timeout 120 amass` |
| `whatweb` | 30s | `timeout 30 whatweb` |
| `crt_sh` (curl) | 15s | `timeout 15 curl` |
| `whois` | 15s | `timeout 15 whois` |
| `shodan` (curl) | 15s | `timeout 15 curl` |
| `dns_enum` | 30s | `timeout 30` prefix |
| `github_scan` (curl) | 15s | `timeout 15 curl` |
| `wpscan` | 90s | `timeout 90 wpscan` |
| `testssl` | 60s | `timeout 60 testssl` |

When Kali kills the process via `timeout`, the channel closes cleanly — no Python-side blocking.

---

### 3.6 LLM JSON Hardening

**File:** `backend/agents/scan_agent.py` — `_extract_json_from_llm_response()`

Add two more strategies after existing ones:
- **Strategy 4:** Strip single quotes around JSON before parsing (`'{"tool": ...}'`)
- **Strategy 5:** On total failure, return safe default `{"tool": null, "input": {}, "reasoning": "LLM parse failed — fallback", "is_terminal": false}` instead of raising `JSONDecodeError`. The caller's fallback handler then uses `_plan_fallback()`. This prevents the LLM JSON error from propagating as an unhandled exception.

---

## 4. Files Changed

| File | Change |
|------|--------|
| `backend/verification/verification_loop.py` | Fix `_classify_result()` — tool failure → MANUAL_REVIEW |
| `backend/intelligence/intelligent_reporter.py` | All findings with verification_status; full set in report |
| `backend/agents/scope_discovery_agent.py` | Target type detection; tool routing; scope anchor finding |
| `backend/core/omx.py` | Split exploit into two phases; escalation gate |
| `backend/agents/exploit_agent.py` | CONTROLLED fallback to all findings when confirmed is empty |
| `backend/core/tool_fallback.py` | New: ToolFallbackResolver (6-step resolution chain) |
| `backend/core/base_agent.py` | Integrate ToolFallbackResolver in run_loop |
| `backend/tools/backends/kali_ssh.py` | Kali-side timeouts; raise COMMAND_TIMEOUT to 3600s |
| `backend/agents/scan_agent.py` | Harden `_extract_json_from_llm_response()` |

---

## 5. Success Criteria

1. All 90-112 findings appear in the report with `verification_status` field
2. Executive summary risk level reflects actual severity distribution across all findings
3. Scope discovery produces ≥ 1 finding for any target type (IP or domain)
4. OSINT tools skipped automatically for internal/RFC-1918 targets
5. Exploitation runs CONTROLLED first, operator gate fires before FULL escalation
6. `--freehand` flag still goes directly to FULL (no regression)
7. When a tool is not found: alternative tried first, then auto-install, then skip with log message
8. No agent aborts due to tool timeout — slow tools killed by Kali `timeout` prefix, agent continues
9. LLM JSON parse failures produce fallback action, not unhandled exception
10. `$pentest --freehand` memory note updated: triggers FULL mode directly (skip CONTROLLED)
