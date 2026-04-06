# Report Download Feature — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose all 6 report formats as downloadable JSON/HTML/PDF via three new FastAPI endpoints and a compact toolbar in the Findings panel.

**Architecture:** Add `_resolve_findings` helper + three `POST` endpoints to `backend/main.py`. Add report toolbar state and download logic to `FindingsPanel` in `frontend/src/App.jsx`. Tests added to the existing `test_report_formats.py`.

**Tech Stack:** FastAPI (Body, HTTPException, Response), IntelligentReporter (already wired), React useState/fetch, Blob download pattern.

---

## File Map

| File | Change |
|---|---|
| `backend/main.py` | Add imports, `_resolve_findings` helper, 3 POST endpoints |
| `frontend/src/App.jsx` | Add 2 constants, 4 state vars, `triggerDownload`, `downloadReport`, toolbar JSX |
| `backend/tests/test_report_formats.py` | Add `report_client` fixture, `TestResolveFindingsHelper` class, `TestReportAPI` class |

---

## Task 1 — `_resolve_findings` helper (TDD)

**Files:**
- Modify: `backend/tests/test_report_formats.py` (append new class)
- Modify: `backend/main.py` (add helper + imports)

- [ ] **Step 1: Append failing tests to `backend/tests/test_report_formats.py`**

Add at the end of the file (after the existing `TestReportPDFExport` class):

```python
# ---------------------------------------------------------------------------
# _resolve_findings helper
# ---------------------------------------------------------------------------

class TestResolveFindingsHelper:
    """Unit tests for the hybrid findings resolution helper."""

    def test_uses_body_findings_when_provided(self):
        from backend.main import _resolve_findings
        reporter = IntelligentReporter()
        reporter.add_finding({"title": "accumulated", "severity": "low"})
        body = [{"title": "from body", "severity": "high"}]
        result = _resolve_findings(body, reporter)
        assert result == body

    def test_falls_back_to_reporter_when_body_empty(self):
        from backend.main import _resolve_findings
        reporter = IntelligentReporter()
        reporter.add_finding({"title": "accumulated", "severity": "low"})
        result = _resolve_findings([], reporter)
        assert len(result) == 1
        assert result[0]["title"] == "accumulated"

    def test_falls_back_when_body_none(self):
        from backend.main import _resolve_findings
        reporter = IntelligentReporter()
        reporter.add_finding({"title": "accumulated", "severity": "low"})
        result = _resolve_findings(None, reporter)
        assert len(result) == 1
        assert result[0]["title"] == "accumulated"
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest backend/tests/test_report_formats.py::TestResolveFindingsHelper -v
```

Expected: `ImportError: cannot import name '_resolve_findings' from 'backend.main'`

- [ ] **Step 3: Update the FastAPI imports line in `backend/main.py`**

Find:
```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
```

Replace with:
```python
from fastapi import Body, FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
```

- [ ] **Step 4: Update the IntelligentReporter import line in `backend/main.py`**

Find:
```python
from backend.intelligence.intelligent_reporter import IntelligentReporter
```

Replace with:
```python
from backend.intelligence.intelligent_reporter import IntelligentReporter, REPORT_FORMATS
```

- [ ] **Step 5: Add `_resolve_findings` helper to `backend/main.py`**

Find the `_prune_loop` function and add the helper directly before it:

```python
def _resolve_findings(
    body_findings: list[dict[str, Any]] | None,
    reporter: IntelligentReporter,
) -> list[dict[str, Any]]:
    """Return body_findings if non-empty; fall back to reporter accumulated findings."""
    if body_findings:
        return body_findings
    return reporter.confirmed_findings


async def _prune_loop(event_bus: EventBus) -> None:
```

- [ ] **Step 6: Run tests to verify they pass**

```
pytest backend/tests/test_report_formats.py::TestResolveFindingsHelper -v
```

Expected: `3 passed`

- [ ] **Step 7: Commit**

```bash
git add backend/main.py backend/tests/test_report_formats.py
git commit -m "feat: add _resolve_findings helper with tests"
```

---

## Task 2 — `POST /report/{fmt}` JSON endpoint (TDD)

**Files:**
- Modify: `backend/tests/test_report_formats.py` (add fixture + TestReportAPI class)
- Modify: `backend/main.py` (add endpoint after `/gate` endpoint)

- [ ] **Step 1: Add `report_client` fixture and failing JSON tests to `backend/tests/test_report_formats.py`**

Add after the `TestResolveFindingsHelper` class:

```python
# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

@pytest.fixture
def report_client():
    """TestClient with reporter pre-loaded; lifespan skipped."""
    import backend.main as main_module
    from fastapi.testclient import TestClient

    reporter = IntelligentReporter()
    for f in SAMPLE_FINDINGS:
        reporter.add_finding(f)

    original = dict(main_module._state)
    main_module._state["reporter"] = reporter

    client = TestClient(main_module.app, raise_server_exceptions=True, lifespan="off")
    yield client

    main_module._state.clear()
    main_module._state.update(original)


class TestReportAPI:
    """API-level tests for the three report endpoints."""

    def test_json_report_all_formats(self, report_client):
        for fmt in REPORT_FORMATS:
            resp = report_client.post(f"/report/{fmt}", json={})
            assert resp.status_code == 200, f"Failed for format {fmt}: {resp.text}"
            data = resp.json()
            assert data["format"] == fmt
            assert "sections" in data
            assert data["finding_count"] == len(SAMPLE_FINDINGS)

    def test_json_hybrid_fallback_uses_reporter(self, report_client):
        # Empty body findings → reporter accumulated findings are used
        resp = report_client.post("/report/executive", json={})
        assert resp.status_code == 200
        assert resp.json()["finding_count"] == len(SAMPLE_FINDINGS)

    def test_json_body_findings_override_reporter(self, report_client):
        custom = [{"title": "Override finding", "severity": "critical"}]
        resp = report_client.post("/report/technical", json={"findings": custom})
        assert resp.status_code == 200
        assert resp.json()["finding_count"] == 1

    def test_invalid_format_returns_422(self, report_client):
        resp = report_client.post("/report/nonexistent_format", json={})
        assert resp.status_code == 422
        assert "Unknown format" in resp.json()["detail"]
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest backend/tests/test_report_formats.py::TestReportAPI -v
```

Expected: `404 Not Found` for all report endpoint calls (routes don't exist yet).

- [ ] **Step 3: Add `POST /report/{fmt}` endpoint to `backend/main.py`**

Add after the `/gate/{action}/{gate_event_id}` endpoint (after line ~421):

```python
# ---------------------------------------------------------------------------
# Report endpoints (Section 16)
# ---------------------------------------------------------------------------

@app.post("/report/{fmt}")
async def generate_report_json(
    fmt: str,
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    """Generate a report in JSON format.

    Body: { findings?: list[dict], framework?: str }
    Uses body findings if non-empty; falls back to reporter accumulated findings.
    """
    reporter: IntelligentReporter | None = _get("reporter")
    if reporter is None:
        raise HTTPException(status_code=503, detail="Reporter not initialized")
    if fmt not in REPORT_FORMATS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown format. Valid: {', '.join(REPORT_FORMATS)}",
        )
    body = body or {}
    findings = _resolve_findings(body.get("findings") or [], reporter)
    return reporter.generate_report(
        report_format=fmt,
        framework=body.get("framework"),
        findings=findings,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest backend/tests/test_report_formats.py::TestReportAPI::test_json_report_all_formats backend/tests/test_report_formats.py::TestReportAPI::test_json_hybrid_fallback_uses_reporter backend/tests/test_report_formats.py::TestReportAPI::test_json_body_findings_override_reporter backend/tests/test_report_formats.py::TestReportAPI::test_invalid_format_returns_422 -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/main.py backend/tests/test_report_formats.py
git commit -m "feat: add POST /report/{fmt} JSON endpoint"
```

---

## Task 3 — `POST /report/{fmt}/html` endpoint (TDD)

**Files:**
- Modify: `backend/tests/test_report_formats.py` (add HTML test to `TestReportAPI`)
- Modify: `backend/main.py` (add HTML endpoint)

- [ ] **Step 1: Add failing HTML test to `TestReportAPI` in `backend/tests/test_report_formats.py`**

Add inside the `TestReportAPI` class, after `test_invalid_format_returns_422`:

```python
    def test_html_download_content_and_headers(self, report_client):
        resp = report_client.post("/report/technical/html", json={"framework": "PCI-DSS"})
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "attachment" in resp.headers["content-disposition"]
        assert 'filename="report-technical.html"' in resp.headers["content-disposition"]
        assert resp.content.startswith(b"<!DOCTYPE html>")
        assert b"Security Assessment Report" in resp.content
```

- [ ] **Step 2: Run test to verify it fails**

```
pytest backend/tests/test_report_formats.py::TestReportAPI::test_html_download_content_and_headers -v
```

Expected: `404 Not Found`

- [ ] **Step 3: Add `POST /report/{fmt}/html` endpoint to `backend/main.py`**

Add directly after the `generate_report_json` endpoint:

```python
@app.post("/report/{fmt}/html")
async def generate_report_html(
    fmt: str,
    body: dict[str, Any] | None = Body(default=None),
) -> Response:
    """Generate a report and return it as a downloadable HTML file."""
    reporter: IntelligentReporter | None = _get("reporter")
    if reporter is None:
        raise HTTPException(status_code=503, detail="Reporter not initialized")
    if fmt not in REPORT_FORMATS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown format. Valid: {', '.join(REPORT_FORMATS)}",
        )
    body = body or {}
    findings = _resolve_findings(body.get("findings") or [], reporter)
    report = reporter.generate_report(
        report_format=fmt,
        framework=body.get("framework"),
        findings=findings,
    )
    html = reporter._render_html(report)
    return Response(
        content=html.encode("utf-8"),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="report-{fmt}.html"'},
    )
```

- [ ] **Step 4: Run test to verify it passes**

```
pytest backend/tests/test_report_formats.py::TestReportAPI::test_html_download_content_and_headers -v
```

Expected: `1 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/main.py backend/tests/test_report_formats.py
git commit -m "feat: add POST /report/{fmt}/html download endpoint"
```

---

## Task 4 — `POST /report/{fmt}/pdf` endpoint (TDD)

**Files:**
- Modify: `backend/tests/test_report_formats.py` (add PDF test to `TestReportAPI`)
- Modify: `backend/main.py` (add PDF endpoint)

- [ ] **Step 1: Add failing PDF test to `TestReportAPI` in `backend/tests/test_report_formats.py`**

Add inside `TestReportAPI`, after `test_html_download_content_and_headers`:

```python
    def test_pdf_download_content_and_headers(self, report_client):
        resp = report_client.post("/report/executive/pdf", json={})
        assert resp.status_code == 200
        assert "application/pdf" in resp.headers["content-type"]
        assert "attachment" in resp.headers["content-disposition"]
        assert 'filename="report-executive.pdf"' in resp.headers["content-disposition"]
        assert len(resp.content) > 0  # WeasyPrint fallback returns HTML bytes
```

- [ ] **Step 2: Run test to verify it fails**

```
pytest backend/tests/test_report_formats.py::TestReportAPI::test_pdf_download_content_and_headers -v
```

Expected: `404 Not Found`

- [ ] **Step 3: Add `POST /report/{fmt}/pdf` endpoint to `backend/main.py`**

Add directly after `generate_report_html`:

```python
@app.post("/report/{fmt}/pdf")
async def generate_report_pdf(
    fmt: str,
    body: dict[str, Any] | None = Body(default=None),
) -> Response:
    """Generate a report and return it as a downloadable PDF file.

    Falls back to HTML bytes if WeasyPrint is not installed.
    """
    reporter: IntelligentReporter | None = _get("reporter")
    if reporter is None:
        raise HTTPException(status_code=503, detail="Reporter not initialized")
    if fmt not in REPORT_FORMATS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown format. Valid: {', '.join(REPORT_FORMATS)}",
        )
    body = body or {}
    findings = _resolve_findings(body.get("findings") or [], reporter)
    report = reporter.generate_report(
        report_format=fmt,
        framework=body.get("framework"),
        findings=findings,
    )
    pdf_bytes = await reporter.export_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{fmt}.pdf"'},
    )
```

- [ ] **Step 4: Run all API tests to verify they all pass**

```
pytest backend/tests/test_report_formats.py -v
```

Expected: All existing tests + new tests pass. Count will be 30 (existing parametrized) + 3 (`TestResolveFindingsHelper`) + 7 (`TestReportAPI`) = 40 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/main.py backend/tests/test_report_formats.py
git commit -m "feat: add POST /report/{fmt}/pdf download endpoint"
```

---

## Task 5 — Frontend report toolbar in `FindingsPanel`

**Files:**
- Modify: `frontend/src/App.jsx`

- [ ] **Step 1: Add two constants after the `EVENT_ICONS` block in `frontend/src/App.jsx`**

Find the line:
```javascript
const fmtTime = (iso) => {
```

Insert directly before it:
```javascript
const REPORT_FORMATS_UI = [
  'executive', 'technical', 'remediation_roadmap',
  'developer_handoff', 'compliance_mapping', 'regression',
]
const REPORT_FRAMEWORKS = ['NIST-CSF', 'PCI-DSS', 'GDPR', 'ISO27001', 'SOC2']

```

- [ ] **Step 2: Add state and helper functions to `FindingsPanel`**

Find in `FindingsPanel`:
```javascript
function FindingsPanel({ findings }) {
  const [selected, setSelected] = useState(null)

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
```

Replace with:
```javascript
function FindingsPanel({ findings }) {
  const [selected, setSelected] = useState(null)
  const [reportFormat, setReportFormat] = useState('executive')
  const [reportFramework, setReportFramework] = useState('NIST-CSF')
  const [downloading, setDownloading] = useState(null)
  const [reportError, setReportError] = useState(null)

  const triggerDownload = (blob, filename) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const downloadReport = async (type) => {
    setDownloading(type)
    setReportError(null)
    const filename = `report-${reportFormat}.${type}`
    const url = type === 'json'
      ? `${API_BASE}/report/${reportFormat}`
      : `${API_BASE}/report/${reportFormat}/${type}`
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings: findings.length ? findings : undefined,
          framework: reportFramework,
        }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }))
        throw new Error(err.detail || resp.statusText)
      }
      triggerDownload(await resp.blob(), filename)
    } catch (e) {
      setReportError(e.message || 'Report generation failed')
    } finally {
      setDownloading(null)
    }
  }

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
```

- [ ] **Step 3: Insert the toolbar JSX inside `FindingsPanel`'s return**

Find in the `FindingsPanel` return JSX:
```jsx
      </div>

      <div className="flex flex-1 min-h-0">
        {/* Finding list */}
```

Replace with:
```jsx
      </div>

      {/* Report download toolbar — only shown when findings exist */}
      {findings.length > 0 && (
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-zinc-800 shrink-0 flex-wrap">
          <select
            value={reportFormat}
            onChange={e => setReportFormat(e.target.value)}
            className="input-field text-xs h-6 py-0 px-1.5"
          >
            {REPORT_FORMATS_UI.map(f => (
              <option key={f} value={f}>{f.replace(/_/g, ' ')}</option>
            ))}
          </select>
          <select
            value={reportFramework}
            onChange={e => setReportFramework(e.target.value)}
            className="input-field text-xs h-6 py-0 px-1.5"
          >
            {REPORT_FRAMEWORKS.map(fw => (
              <option key={fw} value={fw}>{fw}</option>
            ))}
          </select>
          <div className="flex gap-1 ml-auto">
            {['json', 'html', 'pdf'].map(type => (
              <button
                key={type}
                onClick={() => downloadReport(type)}
                disabled={downloading !== null}
                className="font-mono text-xs px-2 h-6 border border-zinc-700 rounded hover:border-zinc-500 hover:text-zinc-200 text-zinc-400 transition-colors disabled:opacity-40"
              >
                {downloading === type ? '…' : `↓ ${type.toUpperCase()}`}
              </button>
            ))}
          </div>
          {reportError && (
            <span className="font-mono text-xs text-red-400 w-full truncate">{reportError}</span>
          )}
        </div>
      )}

      <div className="flex flex-1 min-h-0">
        {/* Finding list */}
```

- [ ] **Step 4: Run the full backend test suite to confirm no regressions**

```
pytest backend/tests/ -v --tb=short
```

Expected: All tests pass (40+ in test_report_formats.py, plus all other suites).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/App.jsx
git commit -m "feat: add report download toolbar to FindingsPanel"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| POST /report/{fmt} → JSON | Task 2 |
| POST /report/{fmt}/html → HTML file | Task 3 |
| POST /report/{fmt}/pdf → PDF file | Task 4 |
| Hybrid fallback: body wins, empty → reporter | Task 1 + Task 2 test |
| 422 on unknown format | Task 2 test |
| Format dropdown — all 6 formats | Task 5 Step 1 |
| Framework dropdown — always visible, 5 options | Task 5 Step 1 |
| 3 download buttons (JSON/HTML/PDF) | Task 5 Step 3 |
| Toolbar only when findings.length > 0 | Task 5 Step 3 |
| Loading spinner per button | Task 5 Step 3 (`…` text) |
| Inline error in toolbar | Task 5 Step 3 |
| WeasyPrint fallback to HTML bytes | Already in IntelligentReporter.export_pdf |

**Placeholder scan:** No TBDs or incomplete steps found.

**Type consistency:**
- `_resolve_findings(body_findings, reporter)` — used consistently in all 3 endpoints (Tasks 1, 2, 3, 4)
- `REPORT_FORMATS` imported from `intelligent_reporter` and used in all 3 endpoints
- `fmt` (not `format`) used as route param in all 3 endpoints to avoid shadowing built-in
- `reporter.confirmed_findings` (property) used in `_resolve_findings` — matches `IntelligentReporter` definition
- `reporter._render_html(report)` — private method, exists in `IntelligentReporter`
- `reporter.export_pdf(report)` — async method, exists in `IntelligentReporter`
- Frontend: `REPORT_FORMATS_UI`, `REPORT_FRAMEWORKS`, `reportFormat`, `reportFramework`, `downloading`, `reportError` — all consistent across Steps 1–3 of Task 5
