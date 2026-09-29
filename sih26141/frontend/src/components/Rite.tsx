import { useEffect, useState } from 'react'

/**
 * Rites — the ceremony language extended beyond sealing. Three overlays
 * share one stage; each is a short, skippable ritual (~2.4 s) rendered in
 * pure CSS (no canvas, no rAF):
 *
 *   seal    — parchment folds flat, red wax stamp, gold ring blooms
 *   verify  — the sealed document breathes under a scanning gold line,
 *             then a verdigris "verified" ring closes around the wax seal
 *   deliver — a gold star lifts from the document and flies off along an
 *             arc (the document crossing the wire), trailing light
 *
 * All rites auto-dismiss and are skippable by click, so they can never
 * trap the demo. `mode` picks the choreography; `tone` re-colors the
 * verdict ring (ok = verdigris, bad = ember).
 */

export type RiteMode = 'seal' | 'verify' | 'deliver'

interface Props {
  mode: RiteMode
  open: boolean
  fileName: string | null
  /** Commitment hash (seal) or delivery note (deliver) shown beneath. */
  detail: string | null
  /** For verify: whether the verification passed (colors the ring). */
  ok?: boolean
  onFinish: () => void
}

const DURATION_MS = 2800

export function Rite({ mode, open, fileName, detail, ok = true, onFinish }: Props) {
  const [closing, setClosing] = useState(false)

  useEffect(() => {
    if (!open) {
      setClosing(false)
      return
    }
    const t1 = window.setTimeout(() => setClosing(true), DURATION_MS)
    const t2 = window.setTimeout(onFinish, DURATION_MS + 260)
    return () => {
      window.clearTimeout(t1)
      window.clearTimeout(t2)
    }
  }, [open, onFinish, mode])

  if (!open) return null

  const dismiss = () => {
    setClosing(true)
    window.setTimeout(onFinish, 240)
  }

  const caption =
    mode === 'seal'
      ? 'sealed under quantum commitment'
      : mode === 'verify'
        ? ok
          ? 'verification complete — seal intact'
          : 'verification failed — seal broken'
        : 'crossing the wire — encrypted in flight'

  return (
    <div
      className={`ceremony ${closing ? 'ceremony-closing' : ''}`}
      onClick={dismiss}
      role="dialog"
      aria-label={`${mode} ceremony`}
    >
      <div className="ceremony-stage" onClick={(e) => e.stopPropagation()}>
        <div className="ceremony-doc">
          {mode === 'verify' && <div className="ceremony-scanline" aria-hidden />}
          {mode === 'deliver' && (
            <>
              <span className="rite-star rite-star-a" aria-hidden />
              <span className="rite-star rite-star-b" aria-hidden />
            </>
          )}
          <div className="ceremony-seal">
            {/* the QDS sigil: entangled orbit around a committed point */}
            <svg viewBox="0 0 24 24" fill="none" aria-hidden>
              <circle cx="12" cy="12" r="8.6" stroke="currentColor" strokeWidth="1.1" opacity="0.85" />
              <ellipse cx="12" cy="12" rx="8.6" ry="3.2" stroke="currentColor" strokeWidth="0.9" opacity="0.65" />
              <ellipse cx="12" cy="12" rx="3.2" ry="8.6" stroke="currentColor" strokeWidth="0.9" opacity="0.65" />
              <circle cx="12" cy="12" r="1.7" fill="currentColor" />
            </svg>
          </div>
          <div
            className={`ceremony-ring ${mode === 'verify' ? (ok ? 'ring-ok' : 'ring-bad') : ''}`}
            aria-hidden
          />
          {mode === 'deliver' && <div className="rite-flight" aria-hidden />}
        </div>
        <div className="ceremony-caption">{caption}</div>
        {detail && <div className="ceremony-hash">{detail}</div>}
        {fileName && <div className="ceremony-hash" style={{ color: 'var(--text-faint)' }}>{fileName}</div>}
        <button className="ceremony-skip" onClick={dismiss}>
          continue →
        </button>
      </div>
    </div>
  )
}

/** Back-compat: the original seal ceremony entry point. */
export function SealCeremony(props: Omit<Props, 'mode' | 'ok'>) {
  return <Rite mode="seal" {...props} />
}
