import { useEffect, useRef, useState } from 'react'
import { bytesToB64, docApi, type DocEvent, type TransferResponse, type HopStats } from '../api'

interface LogLine {
  id: number
  stage: string
  node: string
  detail: string
  level: string
}

const STAGE_ICON: Record<string, string> = {
  qkd: 'key',
  sift: 'sift',
  amplify: 'amp',
  hmac: 'mac',
  transmit: 'wire',
  verify: 'test',
}

const LEVEL_COLOR: Record<string, string> = {
  info: 'var(--text-dim)',
  ok: 'var(--green)',
  warn: 'var(--amber)',
  error: 'var(--red)',
}

export function TransferPortal({ onLog }: { onLog: (line: string) => void }) {
  const [file, setFile] = useState<{ name: string; bytes: Uint8Array } | null>(null)
  const [hops, setHops] = useState(2)
  const [noise, setNoise] = useState(0.0)
  const [eveMode, setEveMode] = useState(false)
  const [eveRatio, setEveRatio] = useState(1.0)
  const [busy, setBusy] = useState(false)
  const [lines, setLines] = useState<LogLine[]>([])
  const [result, setResult] = useState<TransferResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const logRef = useRef<HTMLDivElement>(null)
  const lineId = useRef(0)

  // Live SSE log of the transfer pipeline (sifting → PA → HMAC → transmit → verify).
  useEffect(() => {
    const es = new EventSource('/api/doc/events')
    es.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data) as DocEvent
        if (ev.type === 'transfer_log') {
          setLines((prev) =>
            [
              ...prev,
              { id: lineId.current++, stage: ev.stage, node: ev.node, detail: ev.detail, level: ev.level },
            ].slice(-120),
          )
        } else if (ev.type === 'transfer_done') {
          setLines((prev) =>
            [
              ...prev,
              {
                id: lineId.current++,
                stage: 'done',
                node: 'portal',
                detail: ev.summary,
                level: ev.accepted ? 'ok' : 'error',
              },
            ].slice(-120),
          )
        }
      } catch {
        /* ignore malformed frames */
      }
    }
    es.onerror = () => es.close()
    return () => es.close()
  }, [])

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight })
  }, [lines])

  const onFile = (f: File | null) => {
    setError(null)
    setResult(null)
    if (!f) {
      setFile(null)
      return
    }
    if (f.size > 5_000_000) {
      setError('file too large — demo scope is 5 MB')
      return
    }
    f.arrayBuffer().then((buf) => setFile({ name: f.name, bytes: new Uint8Array(buf) }))
  }

  const send = async () => {
    if (!file) return
    setBusy(true)
    setError(null)
    setResult(null)
    setLines([])
    try {
      const resp = await docApi.transfer({
        name: file.name,
        content_b64: bytesToB64(file.bytes),
        hops,
        noise_rate: noise,
        eve_mode: eveMode,
        intercept_ratio: eveMode ? eveRatio : 0,
      })
      setResult(resp)
      onLog(`transfer #${resp.transfer_id}: ${resp.summary}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">P2P Transfer Portal — Alice → Relays → Bob</div>
        {busy && <span className="pulse-dot" aria-label="transferring" />}
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="transfer-controls">
        <label className="dropzone dropzone-sm">
          <input type="file" hidden onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
          {file ? (
            <>
              <span className="dropzone-name">{file.name}</span>
              <span className="dropzone-size">{(file.bytes.length / 1024).toFixed(1)} KB</span>
            </>
          ) : (
            <>
              <span className="dropzone-icon">→</span>
              <span>file to transmit</span>
            </>
          )}
        </label>

        <label className="control">
          <span>
            Relay hops <b>{hops}</b>
          </span>
          <input type="range" min={0} max={4} step={1} value={hops} onChange={(e) => setHops(Number(e.target.value))} />
        </label>
        <label className="control">
          <span>
            Fiber noise <b>{(noise * 100).toFixed(0)}%</b>/link
          </span>
          <input
            type="range"
            min={0}
            max={0.2}
            step={0.01}
            value={noise}
            onChange={(e) => setNoise(Number(e.target.value))}
          />
        </label>
        <label className="control control-toggle">
          <span>Eve on-path</span>
          <input type="checkbox" checked={eveMode} onChange={(e) => setEveMode(e.target.checked)} />
        </label>
        {eveMode && (
          <label className="control">
            <span>
              intercept <b>{(eveRatio * 100).toFixed(0)}%</b>
            </span>
            <input
              type="range"
              min={0.05}
              max={1}
              step={0.05}
              value={eveRatio}
              onChange={(e) => setEveRatio(Number(e.target.value))}
            />
          </label>
        )}
        <button className="btn btn-primary" onClick={send} disabled={!file || busy}>
          {busy ? 'Transmitting…' : 'Transmit →'}
        </button>
      </div>

      <div className="topology" aria-hidden>
        {['Alice', ...Array.from({ length: hops }, (_, i) => `Relay ${i + 1}`), 'Bob'].map((n, i, arr) => (
          <span key={n} className="topology-item">
            <span className={`topology-node ${busy ? 'topology-live' : ''}`}>{n}</span>
            {i < arr.length - 1 && <span className="topology-link" />}
          </span>
        ))}
      </div>

      {result?.relay_stats && result.relay_stats.length > 0 && (
        <div className="hop-strip">
          {result.relay_stats.map((h: HopStats) => (
            <div key={h.hop} className={`hop-chip ${h.interceptions > 0 ? 'hop-bad' : ''}`}>
              <div className="hop-name">
                {h.from}→{h.to}
              </div>
              <div className="hop-stats">
                {h.out_qubits}/{h.in_qubits} sifted · {h.interceptions} intercepted · QBER{' '}
                {(h.qber * 100).toFixed(1)}%
              </div>
            </div>
          ))}
        </div>
      )}

      {result && (
        <div className={`verdict ${result.delivered ? 'verdict-ok' : 'verdict-bad'}`}>
          {result.delivered
            ? `✓ Transfer #${result.transfer_id} delivered & verified — QBER ${((result.qber ?? 0) * 100).toFixed(2)}%`
            : `✗ Transfer #${result.transfer_id} — ${result.summary}`}
        </div>
      )}

      <div className="transfer-log" ref={logRef}>
        {lines.length === 0 && <div className="vault-placeholder">Live pipeline log — stages appear here in real time.</div>}
        {lines.map((l) => (
          <div key={l.id} className="transfer-line" style={{ color: LEVEL_COLOR[l.level] ?? 'var(--text-dim)' }}>
            <span className="transfer-stage">{STAGE_ICON[l.stage] ?? l.stage}</span>
            <span className="transfer-node">{l.node}</span>
            <span className="transfer-detail">{l.detail}</span>
          </div>
        ))}
      </div>
    </section>
  )
}
