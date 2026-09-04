import { useState, useEffect, useRef, useCallback } from 'react'

export function useWebSocket(url, onMessage, enabled = true) {
  const [connected, setConnected] = useState(false)
  const mountedRef = useRef(true)
  const wsRef = useRef(null)
  const timerRef = useRef(null)
  const heartbeatRef = useRef(null)
  const retryCountRef = useRef(0)
  const lastSeq = useRef(0)
  const onMessageRef = useRef(onMessage)
  const enabledRef = useRef(enabled)

  useEffect(() => { onMessageRef.current = onMessage }, [onMessage])
  useEffect(() => { enabledRef.current = enabled }, [enabled])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
      return true
    }
    return false
  }, [])

  useEffect(() => {
    mountedRef.current = true
    retryCountRef.current = 0

    function getBackoffDelay() {
      const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 30000)
      retryCountRef.current += 1
      return delay
    }

    function stopHeartbeat() {
      clearInterval(heartbeatRef.current)
      heartbeatRef.current = null
    }

    function startHeartbeat(ws) {
      stopHeartbeat()
      heartbeatRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          try { ws.send(JSON.stringify({ type: 'ping' })) } catch {}
        }
      }, 25000)
    }

    async function tryConnect() {
      if (!mountedRef.current || !enabledRef.current) return
      // Health-check gate: up to 3 pings, 1 s apart
      let healthy = false
      for (let i = 0; i < 3; i++) {
        try {
          const res = await fetch('/health')
          if (res.ok) { healthy = true; break }
        } catch {}
        if (!mountedRef.current) return
        if (i < 2) await new Promise(r => { timerRef.current = setTimeout(r, 1000) })
      }
      if (!mountedRef.current) return
      if (!healthy) {
        // Backend not ready — retry with exponential backoff
        const delay = getBackoffDelay()
        timerRef.current = setTimeout(() => { if (mountedRef.current) tryConnect() }, delay)
        return
      }
      try {
        const ws = new WebSocket(url)
        wsRef.current = ws
        ws.onopen = () => {
          if (!mountedRef.current) { ws.close(); return }
          retryCountRef.current = 0
          setConnected(true)
          ws.send(JSON.stringify({ type: 'reconnect', last_seq: lastSeq.current }))
          startHeartbeat(ws)
        }
        ws.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data)
            if (data.seq != null) lastSeq.current = data.seq
            onMessageRef.current(data)
          } catch {}
        }
        ws.onclose = () => {
          if (!mountedRef.current) return
          stopHeartbeat()
          setConnected(false)
          const delay = getBackoffDelay()
          timerRef.current = setTimeout(() => { if (mountedRef.current) tryConnect() }, delay)
        }
        ws.onerror = () => ws.close()
      } catch {}
    }

    function handleVisibilityChange() {
      if (
        document.visibilityState === 'visible' &&
        wsRef.current?.readyState !== WebSocket.OPEN &&
        wsRef.current?.readyState !== WebSocket.CONNECTING
      ) {
        clearTimeout(timerRef.current)
        retryCountRef.current = 0
        tryConnect()
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)
    tryConnect()

    return () => {
      mountedRef.current = false
      clearTimeout(timerRef.current)
      clearInterval(heartbeatRef.current)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      wsRef.current?.close()
    }
  }, [url])

  return { connected, send }
}
