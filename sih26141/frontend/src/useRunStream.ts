import { useEffect, useRef } from 'react'
import type { RunEvent } from './api'
import { base } from './api'

/**
 * Subscribes to the backend SSE event stream. `onEvent` is kept in a ref so
 * the connection survives re-renders. Reconnects automatically on drop and
 * re-reads the API base each attempt (covers port-fallback discovery).
 */
export function useRunStream(onEvent: (ev: RunEvent) => void) {
  const handler = useRef(onEvent)
  handler.current = onEvent

  useEffect(() => {
    let es: EventSource | null = null
    let retry: ReturnType<typeof setTimeout> | undefined
    let closed = false

    const connect = () => {
      es = new EventSource(`${base()}/api/events`)
      es.onmessage = (msg) => {
        try {
          handler.current(JSON.parse(msg.data) as RunEvent)
        } catch {
          /* ignore malformed frames */
        }
      }
      es.onerror = () => {
        es?.close()
        if (!closed) retry = setTimeout(connect, 2000)
      }
    }

    connect()
    return () => {
      closed = true
      if (retry) clearTimeout(retry)
      es?.close()
    }
  }, [])
}
