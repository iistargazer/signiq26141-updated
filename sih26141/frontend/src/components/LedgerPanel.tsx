import { useCallback, useEffect, useRef, useState } from 'react'
import { auditApi, auditClearApi, type AuditEntry, type InclusionProof } from '../api'

/** Row budget rendered on first paint; expansion renders the rest. Keeps
 * the panel light when the ledger grows into the hundreds of entries. */
const INITIAL_ROWS = 60

/**
 * The Merkle audit ledger as a first-class section: hash-chained events,
 * chain-integrity badge, per-entry inclusion proofs, and the developer-only
 * ledger reset (requires the server's DEV_TOKEN). Previously this lived at
 * the bottom of the Doc Vault; it now anchors the `#ledger` nav section.
 */
export function LedgerPanel({ onLog }: { onLog: (line: string) => void }) {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [root, setRoot] = useState<string | null>(null)
  const [chainOk, setChainOk] = useState<boolean | null>(null)
  const [proof, setProof] = useState<InclusionProof | null>(null)
  const [devToken, setDevToken] = useState('')
  const [cleared, setCleared] = useState(false)
  const [busy, setBusy] = useState(false)
  const [showAll, setShowAll] = useState(false)

  const refresh = useCallback(() => {
    auditApi
      .events(200)
      .then((r) => {
        setEntries(r.entries)
        setRoot(r.root ?? null)
      })
      .catch(() => {})
    auditApi
      .verifyChain()
      .then((v) => setChainOk(v.ok))
      .catch(() => {})
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 8000)
    return () => clearInterval(t)
  }, [refresh])

  // DocVault (and other panels) refresh the shared ledger after their own
  // actions via this ref — keep that channel alive so every panel's action
  // instantly shows up here too.
  const refreshRef = useRef(refresh)
  refreshRef.current = refresh
  useEffect(() => {
    ;(window as unknown as { __ledgerRefresh?: () => void }).__ledgerRefresh = () =>
      refreshRef.current()
    return () => {
      delete (window as unknown as { __ledgerRefresh?: () => void }).__ledgerRefresh
    }
  }, [])

  const showProof = (seq: number) => {
    auditApi
      .proof(seq)
      .then(setProof)
      .catch(() => setProof(null))
  }

  return (
    <section className="panel section-anchor" id="ledger-panel">
      <div className="panel-title-row">
        <div className="panel-title">Merkle Audit Ledger</div>
        <div className="ledger-badges">
          <span className={`chip ${chainOk === null ? 'chip-gray' : chainOk ? 'chip-green' : 'chip-red'}`}>
            {chainOk === null ? 'chain …' : chainOk ? '✓ chain intact' : '✗ chain broken'}
          </span>
          <span className="chip chip-blue" title={root ?? undefined}>
            root {root ? `${root.slice(0, 12)}…` : '—'}
          </span>
          <span className="chip chip-gray">{entries.length} entries</span>
        </div>
      </div>
      <p className="panel-hint">
        Append-only, hash-chained event log — every seal, delivery, rejection and attack. Click
        <b> proof</b> to recompute an entry's inclusion proof against the published root.
      </p>

      {entries.length === 0 ? (
        <div className="empty-state">No audit events yet — seal, verify, or transfer a document.</div>
      ) : (
        <div className="ledger-table ledger-scroll">
          <div className="ledger-row ledger-row-head">
            <span>#</span>
            <span>kind</span>
            <span>detail</span>
            <span>leaf</span>
            <span></span>
          </div>
          {(showAll ? entries : entries.slice(0, INITIAL_ROWS)).map((e) => (
            <div key={e.seq} className={`ledger-row ${e.accepted ? '' : 'ledger-row-bad'}`}>
              <span className="mono">{e.seq}</span>
              <span>
                <span className={`chip ${e.accepted ? 'chip-green' : 'chip-red'} chip-sm`}>{e.kind}</span>
              </span>
              <span className="ledger-detail" title={e.detail}>
                {e.detail}
              </span>
              <span className="mono dim">{e.leaf_hash.slice(0, 10)}…</span>
              <button className="link-btn" onClick={() => showProof(e.seq)}>
                proof
              </button>
            </div>
          ))}
        </div>
      )}

      {proof && (
        <div className="proof-box">
          <div>
            <b>inclusion proof seq #{proof.seq}</b> — {proof.siblings.length} sibling hashes
          </div>
          <code>
            {proof.leaf_hash.slice(0, 32)}… → root {proof.root.slice(0, 32)}…
          </code>
          <div className="dim">
            Replaying the sibling chain recomputes exactly this root: the event provably sits in the
            ledger.
          </div>
          <button className="link-btn" onClick={() => setProof(null)}>
            dismiss
          </button>
        </div>
      )}

      {!showAll && entries.length > INITIAL_ROWS && (
        <div className="ledger-more">
          <button className="btn btn-sm" onClick={() => setShowAll(true)}>
            show all {entries.length} entries
          </button>
          <span className="dim">showing the newest {INITIAL_ROWS} — rendering all of them on demand keeps the page fast</span>
        </div>
      )}

      {/* ---- developer-only ledger reset ---- */}
      <div className="ledger-dev">
        <input
          className="text-input"
          style={{ maxWidth: 220 }}
          type="password"
          placeholder="developer token (DEV only)"
          value={devToken}
          onChange={(e) => setDevToken(e.target.value)}
        />
        <button
          className="btn btn-sm"
          disabled={!devToken.trim() || busy}
          onClick={() => {
            setBusy(true)
            auditClearApi
              .clear(devToken.trim())
              .then((r) => {
                setCleared(true)
                setDevToken('')
                onLog(`ledger cleared by developer token — fresh chain begins at seq #${r.genesis_seq}`)
                refresh()
              })
              .catch((e) => onLog(`ledger clear refused: ${e instanceof Error ? e.message : String(e)}`))
              .finally(() => setBusy(false))
          }}
        >
          {busy ? 'Clearing…' : 'clear ledger (dev)'}
        </button>
        {cleared && <span className="dim">ledger reset — new genesis entry recorded</span>}
      </div>
    </section>
  )
}
