import { lazy, Suspense, useMemo } from 'react'
import type { LiveScenario } from '../App'

interface Props {
  live: Record<string, LiveScenario>
  log: string[]
  running: boolean
  /** Base threshold from the slider — drives the dashed reference line. */
  baseThreshold: number
}

const SERIES: Record<string, { color: string; label: string }> = {
  secure: { color: '#86bf9c', label: 'Secure channel' },
  attack: { color: '#d67f72', label: 'Attack (full intercept)' },
  custom: { color: '#c9a45c', label: 'Custom ratio' },
}

type ChartPoint = { processed: number; [key: string]: number | undefined }

const LiveChart = lazy(() => import('./Charts').then((module) => ({ default: module.LiveChart })))

export function LiveMonitor({ live, log, running, baseThreshold }: Props) {
  const names = Object.keys(live)
  const keys = useMemo(
    () => names.filter((name) => live[name].points.length > 0),
    [live],
  )
  const chartData = useMemo(() => {
    const maxLen = Math.max(0, ...keys.map((name) => live[name].points.length))
    return Array.from({ length: maxLen }, (_, index): ChartPoint => {
      const row: ChartPoint = { processed: index }
      for (const name of keys) {
        const point = live[name].points[index]
        if (!point) continue
        row[`${name}_qber`] = point.qber
        row[`${name}_thr`] = point.threshold
        row.processed = point.processed
      }
      return row
    })
  }, [keys, live])

  if (names.length === 0) return null

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">Live Channel Monitor</div>
        {running && <span className="pulse-dot" aria-label="streaming" />}
      </div>
      <div className="monitor-grid">
        {keys.map((n) => {
          const s = live[n]
          const pct = s.total > 0 ? Math.round((s.processed / s.total) * 100) : 0
          const meta = SERIES[n] ?? { color: '#8fb0c9', label: n }
          return (
            <div key={n} className="monitor-stats">
              <div className="stat-line">
                <span className="stat-name" style={{ color: meta.color }}>
                  {meta.label}
                </span>
                <span className={`chip ${s.qber > s.threshold ? 'chip-red' : 'chip-green'}`}>
                  {s.qber > s.threshold ? 'QBER above threshold' : 'channel stable'}
                </span>
              </div>
              <div className="stat-grid">
                <div>
                  <div className="stat-num">{pct}%</div>
                  <div className="stat-label">transmitted</div>
                </div>
                <div>
                  <div className="stat-num">{s.sifted.toLocaleString()}</div>
                  <div className="stat-label">sifted bits</div>
                </div>
                <div>
                  <div className="stat-num">{s.mismatches.toLocaleString()}</div>
                  <div className="stat-label">mismatches</div>
                </div>
                <div>
                  <div className="stat-num">{(s.qber * 100).toFixed(2)}%</div>
                  <div className="stat-label">live QBER</div>
                </div>
              </div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${pct}%`, background: meta.color }} />
              </div>
            </div>
          )
        })}
      </div>
      <div className="chart-wrap">
        <Suspense fallback={<div className="empty-state chart-loading" role="status">Loading live chart…</div>}>
          <LiveChart data={chartData} keys={keys} baseThreshold={baseThreshold} />
        </Suspense>
      </div>
      {log.length > 0 && (
        <div className="event-log">
          <div className="event-log-title">Event log</div>
          {log.map((line, i) => (
            <div key={i} className="event-line">
              {line}
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
