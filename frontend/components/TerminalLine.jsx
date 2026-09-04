export default function TerminalLine({ line }) {
  const { type, source, agent, tool, stream, level, data, ts } = line

  const timestamp = ts
    ? new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : ''

  let label = ''
  let labelColor = ''
  let textColor = 'text-zinc-300'

  if (type === 'operator_input') {
    label = '[OPERATOR]'
    labelColor = 'text-cyan-300'
    textColor = 'text-cyan-200 opacity-60'
  } else if (type === 'kali_output' && agent == null) {
    label = '[OPERATOR]'
    labelColor = 'text-cyan-400'
    textColor = stream === 'stderr' ? 'text-red-400' : 'text-cyan-100'
  } else if (type === 'kali_output') {
    label = `[${agent || '?'} › ${tool || '?'}]`
    labelColor = 'text-emerald-400'
    textColor = stream === 'stderr' ? 'text-red-400' : 'text-zinc-200'
  } else if (type === 'backend_log') {
    label = '[backend]'
    if (level === 'WARNING') {
      labelColor = 'text-amber-400'
      textColor = 'text-amber-200'
    } else if (level === 'ERROR') {
      labelColor = 'text-red-400'
      textColor = 'text-red-300'
    } else {
      labelColor = 'text-zinc-500'
      textColor = 'text-zinc-500'
    }
  } else {
    label = `[${source || type}]`
    labelColor = 'text-zinc-600'
  }

  const rows = (data || '').split('\n').filter(Boolean)

  return (
    <>
      {rows.map((row, i) => (
        <div key={i} className="flex items-start gap-2 px-3 py-0.5 hover:bg-zinc-900/40 group">
          <span className="font-mono text-xs text-zinc-700 shrink-0 w-16 select-none">{i === 0 ? timestamp : ''}</span>
          <span className={`font-mono text-xs shrink-0 ${labelColor}`}>{i === 0 ? label : ''}</span>
          <span className={`font-mono text-xs break-all whitespace-pre-wrap ${textColor}`}>{row}</span>
        </div>
      ))}
    </>
  )
}
