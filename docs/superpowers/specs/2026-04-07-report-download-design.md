# Report Download Feature — Design Spec
**Date:** 2026-04-07
**Project:** Optimus Prime v2.0
**Status:** Approved

---

## Problem

The `IntelligentReporter` (M3) generates 6 report formats with compliance mapping but is never
exposed via API or UI. Operators completing an engagement with 100+ findings have no way to
deliver a structured report to clients.

---

## Goals

- Expose all 6 report formats via REST endpoints
- Support JSON, HTML, and PDF download from the Findings panel
- Hybrid source of truth: frontend findings override backend-accumulated findings when provided
- Always-visible compliance framework selector enriches all formats

## Non-Goals

- Report scheduling or email delivery
- Report persistence/storage (reports are generated on demand)
- Authentication/access control on report endpoints (out of scope for this milestone)
- Custom branding/logo injection into reports

---

## Architecture

### Backend — New endpoints in `backend/main.py`

```
POST /report/{format}
  Body: { findings?: list[dict], framework?: str }
  Returns: application/json
  Behavior: uses body findings if non-empty, else reporter._confirmed_findings

GET /report/{format}/html
  Query: framework?: str, findings?: str (JSON-encoded array)
  Returns: text/html; Content-Disposition: attachment; filename="report-{format}-{ts}.html"

GET /report/{format}/pdf
  Query: framework?: str, findings?: str (JSON-encoded array)
  Returns: application/pdf; Content-Disposition: attachment; filename="report-{format}-{ts}.pdf"
  Fallback: returns HTML bytes with .pdf extension if WeasyPrint not installed
```

**Validation:**
- `{format}` validated against `REPORT_FORMATS` — 422 on unknown value
- `framework` defaults to `NIST-CSF` if omitted for `compliance_mapping` format
- `findings` query param decoded with `json.loads`; decode error returns 422

**Hybrid logic (shared helper):**
```python
def _resolve_findings(body_findings, reporter):
    if body_findings:
        return body_findings
    return reporter.confirmed_findings
```

### Frontend — `FindingsPanel` in `frontend/src/App.jsx`

Compact report toolbar inserted between the severity badge row and the findings list.
Renders only when `findings.length > 0`.

```
FINDINGS  ● 3 CRITICAL  ● 2 HIGH                      ← existing header
──────────────────────────────────────────────────────
FORMAT [executive ▾]   FRAMEWORK [NIST-CSF ▾]
[↓ JSON]  [↓ HTML]  [↓ PDF]                           ← new toolbar
──────────────────────────────────────────────────────
  finding list...
```

**Format options:** executive, technical, remediation_roadmap, developer_handoff,
compliance_mapping, regression

**Regression format note:** `prior_findings` is not exposed in the UI. The endpoint passes
`prior_findings=[]` when none are provided — the backend handles this gracefully (all current
findings appear as "new", resolved count = 0).

**Framework options:** NIST-CSF, PCI-DSS, GDPR, ISO-27001, SOC2

**Download behaviour:**
- **JSON**: `POST /report/{format}` with `{findings, framework}` → `URL.createObjectURL` blob
- **HTML**: `GET /report/{format}/html?framework=...&findings=<encoded>` → `<a download>` click
- **PDF**: `GET /report/{format}/pdf?framework=...&findings=<encoded>` → `<a download>` click
- If findings array JSON-encoded length > 8KB, all three fall back to POST + blob to avoid
  query string limits
- Buttons show inline spinner during request; error message shown inline in toolbar on failure

---

## Data Flow

```
Engagement completes
    │
    ├─ EventBus → reporter._confirmed_findings (backend accumulation)
    └─ WebSocket FINDING_CREATED → findings[] state (frontend)

Operator clicks download
    │
    ├─ JSON:    POST /report/{format}  { findings, framework }  →  blob download
    ├─ HTML:    GET  /report/{format}/html?findings=...          →  file download
    └─ PDF:     GET  /report/{format}/pdf?findings=...           →  file download
                                                ↑
                        falls back to reporter._confirmed_findings if empty
```

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| Unknown format in URL | 422 with `{"detail": "Unknown format. Valid: executive, technical, ..."}` |
| Malformed `findings` JSON in query | 422 |
| WeasyPrint not installed | PDF returns HTML bytes (existing `export_pdf` fallback) |
| Findings query string > 8KB | Frontend switches to POST + blob automatically |
| Network/server error | Inline error in toolbar: `"Report generation failed — {message}"` |

---

## Testing

New tests added to `backend/tests/test_report_formats.py` using FastAPI `TestClient`:

1. `test_api_json_report_all_formats` — POST /report/{format} for all 6 formats returns valid JSON
2. `test_api_html_download` — GET /report/technical/html returns HTML bytes with correct headers
3. `test_api_pdf_download` — GET /report/executive/pdf returns bytes with attachment header
4. `test_api_hybrid_fallback` — POST with empty findings body uses reporter accumulated findings
5. `test_api_invalid_format` — POST /report/badformat returns 422

---

## Files Changed

| File | Change |
|---|---|
| `backend/main.py` | Add 3 new endpoints + `_resolve_findings` helper |
| `frontend/src/App.jsx` | Add report toolbar to `FindingsPanel` |
| `backend/tests/test_report_formats.py` | Add 5 API-level test functions |
