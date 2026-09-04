import { Shield, Layers } from 'lucide-react'

export default function ChatMessage({ msg }) {
  const isUser = msg.role === 'user'
  const isError = msg.type === 'error'
  const isPlan  = msg.type === 'plan'

  return (
    <div className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'} animate-fade-in`}>
      {!isUser && (
        <div className="w-6 h-6 rounded-md bg-zinc-800 border border-zinc-700 flex items-center justify-center shrink-0 mt-0.5">
          <Shield size={12} className="text-zinc-400" />
        </div>
      )}
      <div className={`max-w-[85%] rounded-xl px-4 py-3 text-sm leading-relaxed
        ${isUser
          ? 'bg-white text-zinc-950 font-medium rounded-br-sm'
          : isError
            ? 'bg-red-500/10 border border-red-500/30 text-red-300 rounded-bl-sm'
            : isPlan
              ? 'bg-sky-500/10 border border-sky-500/30 text-zinc-200 rounded-bl-sm'
              : 'bg-zinc-800 border border-zinc-700 text-zinc-200 rounded-bl-sm'
        }`}
      >
        {isUser ? (
          <span className="font-mono">{msg.content}</span>
        ) : (
          <div>
            {isPlan && (
              <div className="flex items-center gap-2 mb-2 pb-2 border-b border-sky-500/20">
                <Layers size={12} className="text-sky-400" />
                <span className="font-mono text-xs text-sky-400 font-semibold">ENGAGEMENT PLAN CREATED</span>
              </div>
            )}
            <pre className="font-mono text-xs whitespace-pre-wrap break-words leading-relaxed">
              {msg.content}
            </pre>
            {msg.metadata?.tokens && (
              <span className="font-mono text-xs text-zinc-600 mt-2 block">
                {msg.metadata.tokens} tokens · {msg.metadata.model}
              </span>
            )}
          </div>
        )}
      </div>
      {isUser && (
        <div className="w-6 h-6 rounded-md bg-zinc-700 border border-zinc-600 flex items-center justify-center shrink-0 mt-0.5">
          <span className="font-mono text-xs text-zinc-300 font-semibold">OP</span>
        </div>
      )}
    </div>
  )
}
