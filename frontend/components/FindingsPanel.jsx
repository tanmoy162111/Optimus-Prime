import { useState } from 'react'
import { AlertTriangle, CheckCircle } from 'lucide-react'
import { SEVERITY_MAP, REPORT_FORMATS_UI, REPORT_FRAMEWORKS } from '../lib/constants'

export default function FindingsPanel({ findings }) {
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
      ? `/report/${reportFormat}`
      : `/report/${reportFormat}/${type}`
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
  const sorted = [...findings].sort((a, b) =>
    (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)
  )

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <AlertTriangle size={13} className="text-zinc-500" />
          <span className="label-xs">Findings</span>
        </div>
        <div className="flex items-center gap-2">
          {['critical','high','medium','low'].map(s => counts[s] ? (
            <span key={s} className={`font-mono text-xs px-1.5 py-0.5 rounded border ${SEVERITY_MAP[s].cls}`}>
              {counts[s]} {s.slice(0,1).toUpperCase()}
            </span>
          ) : null)}
          {findings.length === 0 && <span className="font-mono text-xs text-zinc-600">none</span>}
        </div>
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
        <div className="w-full border-r border-zinc-800 overflow-y-auto">
          {sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center p-4">
              <CheckCircle size={20} className="text-zinc-700 mb-2" />
              <p className="text-xs text-zinc-600 font-mono">No findings yet</p>
            </div>
          ) : (
            sorted.map((f, i) => {
              const sev = SEVERITY_MAP[f.severity] || SEVERITY_MAP.info
              return (
                <button
                  key={f.finding_id || i}
                  onClick={() => setSelected(selected?.finding_id === f.finding_id ? null : f)}
                  className={`w-full text-left flex items-start gap-3 px-3 py-2.5 border-b border-zinc-800/60
                    hover:bg-zinc-800/40 transition-colors
                    ${selected?.finding_id === f.finding_id ? 'bg-zinc-800/60' : ''}`}
                >
                  <span className={`inline-block w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${sev.dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-xs font-medium px-1 rounded border ${sev.cls}`}>
                        {sev.label}
                      </span>
                      <span className={`font-mono text-xs px-1.5 py-0.5 rounded border text-zinc-400 border-zinc-700 ${
                        f.classification === 'confirmed' ? 'text-emerald-400 border-emerald-500/40' :
                        f.classification === 'false_positive' ? 'text-zinc-500' :
                        f.classification === 'manual_review' ? 'text-amber-400 border-amber-500/40' : ''
                      }`}>
                        {f.classification?.toUpperCase() || 'UNVERIFIED'}
                      </span>
                    </div>
                    <div className="text-xs text-zinc-300 mt-1 leading-snug font-medium">{f.title}</div>
                    <div className="flex items-center gap-3 mt-0.5">
                      {f.target && <span className="font-mono text-xs text-zinc-600">{f.target}{f.port ? `:${f.port}` : ''}</span>}
                      {f.tool && <span className="font-mono text-xs text-zinc-600">via {f.tool}</span>}
                    </div>
                    {/* Expanded detail */}
                    {selected?.finding_id === f.finding_id && (
                      <div className="mt-3 p-3 bg-zinc-800/60 rounded border border-zinc-700 text-left animate-fade-in">
                        {f.description && (
                          <p className="text-xs text-zinc-300 leading-relaxed mb-2">{f.description}</p>
                        )}
                        {f.evidence && (
                          <div className="mb-2">
                            <span className="label-xs block mb-1">Evidence</span>
                            <pre className="text-xs text-zinc-400 font-mono whitespace-pre-wrap break-all">{f.evidence}</pre>
                          </div>
                        )}
                        {f.cve_ids?.length > 0 && (
                          <div className="mb-2">
                            <span className="label-xs block mb-1">CVEs</span>
                            <div className="flex flex-wrap gap-1">
                              {f.cve_ids.map(c => (
                                <span key={c} className="font-mono text-xs px-2 py-0.5 bg-zinc-900 border border-zinc-700 rounded text-sky-400">{c}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {f.attack_techniques?.length > 0 && (
                          <div className="mb-2">
                            <span className="label-xs block mb-1">ATT&CK Techniques</span>
                            <div className="flex flex-wrap gap-1">
                              {f.attack_techniques.map(t => (
                                <span key={t} className="font-mono text-xs px-2 py-0.5 bg-zinc-900 border border-zinc-700 rounded text-orange-400">{t}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {f.remediation && (
                          <div>
                            <span className="label-xs block mb-1">Remediation</span>
                            <p className="text-xs text-zinc-400 leading-relaxed">{f.remediation}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </button>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
