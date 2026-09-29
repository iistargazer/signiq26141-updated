import { useCallback, useEffect, useRef, useState } from 'react'
import {
  auditApi,
  type AuditEntry,
  type AuditExportResponse,
  type InclusionProof,
} from '../api'
import { OFFLINE_AUDIT_VERIFIER_HTML, verifyAuditBundle, type AuditVerificationReport } from '../auditEvidence'
import { Constellation } from './Constellation'

/** Row budget rendered on first paint; expansion renders the rest. Keeps
 * the panel light when the ledger grows into the hundreds of entries. */
const INITIAL_ROWS = 60

/**
 * The Merkle audit ledger as a first-class section: hash-chained events,
 * chain-integrity badge, per-entry inclusion proofs and portable evidence
 * exports. Previously this lived at the bottom of the Doc Vault; it now anchors
 * the `#ledger` nav section.
 */
export function LedgerPanel({ onLog }: { onLog: (line: string) => void }) {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  // First-load lifecycle: the panel must never claim "0 entries" while the
  // (possibly cold-starting) backend has not answered yet.
  const [loadState, setLoadState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [root, setRoot] = useState<string | null>(null)
  const [chainOk, setChainOk] = useState<boolean | null>(null)
  const [proof, setProof] = useState<InclusionProof | null>(null)
  const [showAll, setShowAll] = useState(false)
  // The ledger's true length (the feed endpoint caps what it returns) —
  // used for the "show all" affordance and the hint copy.
  const [total, setTotal] = useState(0)
  const [exportBusy, setExportBusy] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [exportReport, setExportReport] = useState<AuditVerificationReport | null>(null)
  const [portableBundle, setPortableBundle] = useState<AuditExportResponse | null>(null)

  const refresh = useCallback(() => {
    auditApi
      // Ask high; the server caps the feed. `total` carries the true count.
      .events(2000)
      .then((r) => {
        setEntries(r.entries)
        setRoot(r.root ?? null)
        setTotal(r.total ?? r.entries.length)
        setLoadState('ready')
      })
      .catch(() => {
        // A failed refresh after a successful load keeps the stale table;
        // only the very first load escalates to the error state.
        setLoadState((prev) => (prev === 'loading' ? 'error' : prev))
      })
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

  const downloadText = (filename: string, content: string, type: string) => {
    const url = URL.createObjectURL(new Blob([content], { type }))
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const buildPortableExport = async () => {
    setExportBusy(true)
    setExportError(null)
    setExportReport(null)
    try {
      const bundle = await auditApi.portableExport()
      const report = await verifyAuditBundle(bundle)
      setPortableBundle(bundle)
      setExportReport(report)
      downloadText(
        `signiq-audit-evidence-${new Date().toISOString().replace(/[:.]/g, '-')}.json`,
        `${JSON.stringify(bundle, null, 2)}\n`,
        'application/json;charset=utf-8',
      )
      onLog(`Portable audit evidence exported: ${bundle.total} entries · ${report.valid ? 'local chain/root/proof checks passed' : 'local verification found an issue'}`)
    } catch (e) {
      setExportError(e instanceof Error ? e.message : String(e))
    } finally {
      setExportBusy(false)
    }
  }

  const downloadOfflineVerifier = () => {
    downloadText('signiq-offline-audit-verifier.html', OFFLINE_AUDIT_VERIFIER_HTML, 'text/html;charset=utf-8')
    onLog('Downloaded the self-contained, no-network audit evidence verifier')
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
          <span className="chip chip-gray">{loadState === 'loading' ? 'loading…' : `${entries.length} entries`}</span>
        </div>
      </div>
      <p className="panel-hint">
        Append-only, hash-chained event log — {total} events so far, newest first. Click
        <b> proof</b> to recompute an entry's inclusion proof against the published root.
      </p>

      <div className="audit-export-actions">
        <button className="btn btn-primary btn-sm" onClick={() => { void buildPortableExport() }} disabled={exportBusy}>
          {exportBusy ? 'Verifying & exporting…' : 'Download portable evidence'}
        </button>
        <button className="btn btn-sm" onClick={downloadOfflineVerifier}>
          Download offline verifier
        </button>
        <span className="dim">Full snapshot · root · chain verdict · one inclusion proof per event</span>
      </div>
      {exportError && <div className="verdict-bad audit-export-status" role="alert">Export failed: {exportError}</div>}
      {exportReport && (
        <div className={`audit-export-report ${exportReport.valid ? 'audit-export-valid' : 'audit-export-invalid'}`} role="status" aria-live="polite">
          <div className="audit-export-report-head">
            <b>{exportReport.valid ? '✓ Bundle independently verified in this browser' : 'Bundle exported, but local verification found an issue'}</b>
            <span>{exportReport.entryCount.toLocaleString()} events · {exportReport.validProofs.toLocaleString()} valid proofs</span>
          </div>
          <code>{exportReport.root ?? '(empty ledger)'}</code>
          <ul>
            {exportReport.checks.map((check) => (
              <li key={check.label} className={check.valid ? 'audit-check-ok' : 'audit-check-bad'}>
                <b>{check.valid ? 'PASS' : 'FAIL'}</b> {check.label} — {check.detail}
              </li>
            ))}
          </ul>
          {portableBundle && (
            <p className="audit-export-note">
              The JSON bundle and separate offline verifier can travel together. The verifier checks
              internal consistency against this bundle's root; compare that root via a trusted
              independent channel to establish who published it.
            </p>
          )}
        </div>
      )}

      {loadState === 'loading' ? (
        <div className="ledger-skeleton" aria-hidden>
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="ledger-skeleton-row" />
          ))}
        </div>
      ) : loadState === 'error' && entries.length === 0 ? (
        <div className="empty-state" role="status">
          The audit ledger is unreachable right now — the API server may be starting up or asleep.
          It retries automatically every few seconds.
        </div>
      ) : entries.length === 0 ? (
        <div className="empty-state">No audit events yet — seal, verify, or transfer a document.</div>
      ) : (
        <>
          {/* the ledger as a night sky — same data as the table below */}
          <Constellation entries={entries} />
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
        </>
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
            show all {Math.max(total, entries.length)} entries
          </button>
          <span className="dim">showing the newest {INITIAL_ROWS} — rendering all of them on demand keeps the page fast</span>
        </div>
      )}


    </section>
  )
}
