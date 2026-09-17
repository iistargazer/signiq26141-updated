import { useState } from 'react'
import {
  b64ToBytes,
  bytesToB64,
  docApi,
  type AttackMode,
  type AttackResponse,
  type TheaterResponse,
} from '../api'

const LEVEL_COLOR: Record<string, string> = {
  info: 'var(--text-dim)',
  ok: 'var(--green)',
  warn: 'var(--amber)',
  error: 'var(--red)',
}

/** Crossed-swords mark, drawn — not an emoji (stroke inherits currentColor). */
function CrossedIcon() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" aria-hidden>
      <path d="M5 4l10.5 10.5M19 4L8.5 14.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M7 17.5L4.5 20M17 17.5l2.5 2.5M14.5 15.5L20 21M9.5 15.5L4 21" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  )
}

/** Live playback of the theater steps (one step every 900 ms). */
function TheaterSteps({ theater }: { theater: TheaterResponse }) {
  const [shown, setShown] = useState(1)
  const total = theater.steps.length
  if (shown < total) {
    setTimeout(() => setShown((s) => Math.min(s + 1, total)), 900)
  }
  return (
    <div className="transfer-log" style={{ maxHeight: 320 }}>
      {theater.steps.slice(0, shown).map((s) => (
        <div key={s.step} className="transfer-line" style={{ color: LEVEL_COLOR[s.level] ?? 'var(--text-dim)' }}>
          <span className="transfer-stage">{s.step}</span>
          <span className="transfer-node">{s.actor}</span>
          <span className="transfer-detail">
            <b>{s.title}</b> — {s.detail}
            {s.evidence?.ciphertext_sample_hex ? (
              <code style={{ display: 'block', wordBreak: 'break-all', marginTop: 2 }}>
                wire: {String(s.evidence.ciphertext_sample_hex).slice(0, 64)}…
              </code>
            ) : null}
          </span>
        </div>
      ))}
      {shown >= total && (
        <div className={`verdict ${theater.rejected ? 'verdict-ok' : 'verdict-bad'}`} style={{ marginTop: 8 }}>
          {theater.rejected
            ? `${theater.victim} REJECTED the ${theater.mode} attack — ${theater.victim_verdict.note}`
            : `container was ACCEPTED — investigate!`}
        </div>
      )}
    </div>
  )
}

const MODES: { id: AttackMode; label: string; hint: string }[] = [
  {
    id: 'tamper_bytes',
    label: 'Tamper bytes',
    hint: 'flip ciphertext bytes — AES-GCM authentication must fail',
  },
  {
    id: 'swap_meta',
    label: 'Swap metadata',
    hint: 'rename the document — metadata is GCM associated data',
  },
  {
    id: 'reseal',
    label: 'Re-seal (forge)',
    hint: 'replace the commitment and tag with Mallory\u2019s own key',
  },
  {
    id: 'truncate',
    label: 'Truncate payload',
    hint: 'cut the container short — hash and tag must fail',
  },
]

const MAX_BYTES = 5_000_000

/**
 * Mallory's workbench: capture an intercepted .qsig container, mangle it
 * with one of four attack modes, forward the result to Bob's verification
 * — and watch it be REJECTED with a precise reason. Every attempt is
 * recorded in the shared Merkle audit ledger as an `attack` event.
 */
export function AttackLab({ onLog }: { onLog: (line: string) => void }) {
  const [containerB64, setContainerB64] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [mode, setMode] = useState<AttackMode>('tamper_bytes')
  const [label, setLabel] = useState('mallory')
  const [recipient, setRecipient] = useState('bob')
  const [busy, setBusy] = useState(false)
  const [attack, setAttack] = useState<AttackResponse | null>(null)
  const [theater, setTheater] = useState<TheaterResponse | null>(null)
  const [forwarded, setForwarded] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const onFile = (f: File | null) => {
    setError(null)
    setAttack(null)
    setTheater(null)
    setForwarded(false)
    if (!f) {
      setFileName(null)
      setContainerB64('')
      return
    }
    if (f.size > MAX_BYTES) {
      setError('container too large — demo scope is 5 MB')
      return
    }
    f.arrayBuffer().then((buf) => {
      setContainerB64(bytesToB64(new Uint8Array(buf)))
      setFileName(f.name)
    })
  }

  const runAttack = async () => {
    if (!containerB64) return
    setBusy(true)
    setError(null)
    setAttack(null)
    setTheater(null)
    setForwarded(false)
    try {
      const resp = await docApi.attack({
        container_b64: containerB64,
        mode,
        from_label: label.trim() || 'mallory',
      })
      setAttack(resp)
      onLog(`attack [${resp.mode}] → ${resp.description}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  // The real-time theater: interception → failed decryption → tamper →
  // forward → victim's live rejection → audit entry, streamed step by step.
  const runTheater = async () => {
    if (!containerB64) return
    setBusy(true)
    setError(null)
    setAttack(null)
    setTheater(null)
    setForwarded(false)
    try {
      const resp = await docApi.attackTheater({
        container_b64: containerB64,
        mode,
        victim: recipient.trim() || 'bob',
        attacker: label.trim() || 'mallory',
      })
      setTheater(resp)
      onLog(
        `theater #${resp.theater_id}: ${resp.mode} vs ${resp.victim} — ${
          resp.rejected ? 'REJECTED' : 'NOT rejected'
        }`,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const forwardToBob = async () => {
    if (!attack) return
    setBusy(true)
    setError(null)
    try {
      // On a shared deployed server the ATTACKER has no session key (by
      // design), so "forward" must go through the recipient's inbox via
      // /api/doc/send — the recipient's own verify then rejects the forgery
      // under THEIR key. That is exactly the real-world attack path.
      const resp = await docApi.peerSend({
        container_b64: attack.container_b64,
        to_user: recipient.trim(),
        from_label: label.trim() || 'mallory',
      })
      setForwarded(true)
      onLog(`mallory forwarded her ${attack.mode} forgery → ${resp.destination}: ${resp.summary}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const downloadTampered = () => {
    if (!attack) return
    const bytes = b64ToBytes(attack.container_b64)
    const blob = new Blob([bytes as BlobPart], { type: 'application/octet-stream' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `tampered-${fileName ?? 'container.qsig'}`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const selected = MODES.find((m) => m.id === mode)!

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">Attack Lab — Mallory vs the seal</div>
        {busy && <span className="pulse-dot" aria-label="working" />}
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="p2p-controls">
        <label className="dropzone dropzone-sm">
          <input type="file" hidden onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
          {fileName ? (
            <>
              <span className="dropzone-name">{fileName}</span>
              <span className="dropzone-size">captured container</span>
            </>
          ) : (
            <>
              <span className="dropzone-icon"><CrossedIcon /></span>
              <span>capture a .qsig container</span>
            </>
          )}
        </label>

        <label className="control">
          <span>Attack mode</span>
          <select
            className="text-input"
            value={mode}
            onChange={(e) => setMode(e.target.value as AttackMode)}
          >
            {MODES.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        </label>
        <label className="control">
          <span>Attacker label</span>
          <input className="text-input" value={label} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <label className="control">
          <span>Forward forgery to (recipient)</span>
          <input
            className="text-input"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            placeholder="bob"
            spellCheck={false}
          />
        </label>
        <button className="btn btn-primary" onClick={runTheater} disabled={!containerB64 || busy}>
          {busy ? 'Staging…' : 'Run attack theater (live)'}
        </button>
        <button className="btn" onClick={runAttack} disabled={!containerB64 || busy}>
          {busy ? 'Working…' : 'Attack only (no forward)'}
        </button>
      </div>

      {theater && (
        <div className="attack-result">
          <div className="dim" style={{ marginBottom: 6 }}>
            theater #{theater.theater_id} — wire entropy {theater.wire.ciphertext_entropy.toFixed(2)} bits/byte ·{' '}
            {theater.wire.qds_signature_attached ? 'QDS-signed container' : 'unsigned container'}
          </div>
          <TheaterSteps theater={theater} />
        </div>
      )}

      <div className="dim" style={{ margin: '4px 0 10px' }}>
        {selected.hint}. Pick up the .qsig container Bob sealed (from the Document Vault download or
        the peer transfer) — then <b>Run attack theater</b> to watch the whole story live:
        interception on the wire (unreadable ciphertext shown), Mallory's tamper, the forward, and
        the victim's cryptographic REJECTION with the exact failed check — every step audit-logged.
      </div>

      {attack && (
        <div className="attack-result">
          <div className="verdict verdict-amber">
            <b>Mallory:</b> {attack.description}
          </div>
          <div className="attack-actions">
            <button className="btn btn-sm" onClick={downloadTampered}>
              save forged container
            </button>
            <button
              className="btn btn-sm btn-primary"
              onClick={forwardToBob}
              disabled={forwarded || busy || !recipient.trim()}
            >
              forward to {recipient.trim() || '…'} →
            </button>
          </div>
          {forwarded && (
            <div className="dim">
              The forged container is now in {recipient.trim()}'s inbox. When they verify it, the
              seal rejects it under <b>their</b> session key — watch their screen for the ✗
              REJECTED verdict, and the audit ledger for the recorded attempt.
            </div>
          )}
        </div>
      )}
    </section>
  )
}
