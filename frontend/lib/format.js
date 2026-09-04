export const fmtTime = (iso) => {
  const d = new Date(iso || Date.now())
  return d.toLocaleTimeString('en-US', { hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit' })
}

export const fmtElapsed = (start) => {
  const ms = Date.now() - new Date(start).getTime()
  if (ms < 60000) return `${Math.floor(ms/1000)}s`
  return `${Math.floor(ms/60000)}m ${Math.floor((ms%60000)/1000)}s`
}

export const renderPayload = (payload) => {
  const p = payload
  const parts = []

  if (p.message) parts.push(p.message)
  else if (p.directive) parts.push(`directive: ${p.directive}`)
  if (p.phase_name) parts.push(`phase: ${p.phase_name}`)
  if (p.agent_type) parts.push(`agent: ${p.agent_type}`)
  if (p.plan_id) parts.push(`plan: ${p.plan_id.slice(0, 8)}…`)
  if (p.total_findings != null) parts.push(`findings: ${p.total_findings}`)
  if (p.findings_count) parts.push(`new findings: ${p.findings_count}`)
  if (p.status) parts.push(`status: ${p.status}`)
  if (p.tool) parts.push(`tool: ${p.tool}`)
  if (p.confirm_command) parts.push(`→ type: ${p.confirm_command}`)
  if (p.from_model) parts.push(`${p.from_model} → ${p.to_model}`)
  if (p.used != null && p.budget != null) parts.push(`${p.used.toLocaleString()}/${p.budget.toLocaleString()} tokens`)
  if (p.note) parts.push(p.note)
  if (p.error) parts.push(`⚠ ${String(p.error).slice(0, 100)}`)

  return parts.length > 0 ? parts.join('  ·  ') : JSON.stringify(p).slice(0, 120)
}
