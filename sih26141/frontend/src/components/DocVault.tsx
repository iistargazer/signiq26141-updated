import { useCallback, useEffect, useRef, useState } from 'react'
import {
  auditApi,
  authApi,
  b64ToBytes,
  bytesToB64,
  docApi,
  getAuthUsername,
  type AuditEntry,
  type InclusionProof,
  type SessionInfo,
  type SealResponse,
  type VerificationOutcome,
  type QuorumUnlockResponse,
  type DistributeResponse,
} from '../api'

/** Download helper for the .qsig container (base64 wire format). */
function downloadContainer(name: string, containerB64: string) {
  const blob = new Blob([b64ToBytes(containerB64)], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name.endsWith('.qsig') ? name : `${name}.qsig`
  a.click()
  URL.revokeObjectURL(url)
}

interface QuorumRow {
  x: number
  checked: boolean
}

export function DocVault({ onLog }: { onLog: (line: string) => void }) {
  const [session, setSession] = useState<SessionInfo | null>(null)
  const [file, setFile] = useState<{ name: string; bytes: Uint8Array } | null>(null)
  const [useQuorum, setUseQuorum] = useState(false)
  const [k, setK] = useState(3)
  const [m, setM] = useState(5)
  const [sealResp, setSealResp] = useState<SealResponse | null>(null)
  const [verify, setVerify] = useState<VerificationOutcome | null>(null)
  const [unlockResp, setUnlockResp] = useState<QuorumUnlockResponse | null>(null)
  const [quorumRows, setQuorumRows] = useState<QuorumRow[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Cross-account multiparty state (distribute / pledge / pledged unlock)
  const [registeredUsers, setRegisteredUsers] = useState<string[]>([])
  const [officerUsers, setOfficerUsers] = useState<string[]>([])
  const [distributeResp, setDistributeResp] = useState<DistributeResponse | null>(null)
  const [heldShare, setHeldShare] = useState<{ x: number; from: string } | null>(null)
  const [pledgesReceived, setPledgesReceived] = useState(0)

  // Audit log state
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [root, setRoot] = useState<string | null>(null)
  const [chainOk, setChainOk] = useState<boolean | null>(null)
  const [proof, setProof] = useState<InclusionProof | null>(null)
  const refreshAudit = useRef<() => void>(() => {})

  const refreshSession = useCallback(() => {
    docApi.session().then(setSession).catch(() => setSession(null))
    // Cross-account quorum state: what I hold, pledges I've received, who
    // exists to distribute to.
    docApi
      .quorumInfo()
      .then((q) => {
        setHeldShare(q.held_share ? { x: q.held_share.x, from: q.held_share.from } : null)
        setPledgesReceived(q.pledges_received ?? 0)
      })
      .catch(() => {})
    if (getAuthUsername()) {
      authApi.users().then((r) => setRegisteredUsers(r.users)).catch(() => {})
    }
  }, [])

  const refreshAuditNow = useCallback(() => {
    auditApi.events(200).then((r) => {
      setEntries(r.entries)
      setRoot(r.root ?? null)
    }).catch(() => {})
    auditApi.verifyChain().then((v) => setChainOk(v.ok)).catch(() => {})
  }, [])

  useEffect(() => {
    refreshSession()
    refreshAuditNow()
    refreshAudit.current = refreshAuditNow
    // Keep the audit log fresh when transfers happen elsewhere in the app.
    const t = setInterval(refreshAuditNow, 8000)
    return () => clearInterval(t)
  }, [refreshSession, refreshAuditNow])

  const onFile = (f: File | null) => {
    setError(null)
    setSealResp(null)
    setVerify(null)
    setUnlockResp(null)
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

  const guard = async (label: string, fn: () => Promise<void>) => {
    setBusy(label)
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const doSeal = () =>
    guard('seal', async () => {
      if (!file) return
      const resp = await docApi.seal({
        name: file.name,
        content_b64: bytesToB64(file.bytes),
        use_quorum: useQuorum,
        quorum_threshold: useQuorum ? k : undefined,
        quorum_shares: useQuorum ? m : undefined,
      })
      setSealResp(resp)
      setVerify(null)
      setUnlockResp(null)
      setDistributeResp(null)
      if (resp.quorum) {
        // Pre-fill the officer list with other registered accounts.
        const others = registeredUsers.filter((u) => u !== getAuthUsername())
        setOfficerUsers(
          Array.from({ length: resp.quorum[1] }, (_, i) => others[i] ?? ''),
        )
      }
      setQuorumRows(
        Array.from({ length: useQuorum ? m : 0 }, (_, i) => ({ x: i + 1, checked: i < (useQuorum ? k : 0) })),
      )
      downloadContainer(resp.name, resp.container_b64)
      onLog(
        `sealed '${file.name}' → ${resp.name}.qsig (${(resp.size / 1024).toFixed(1)} KB) · SHA-256 ${resp.sha256.slice(0, 12)}…` +
          (resp.quorum ? ` · quorum ${resp.quorum[0]}-of-${resp.quorum[1]}` : ''),
      )
      if (resp.audit_warning) onLog(`⚠ ledger: ${resp.audit_warning}`)
      refreshAuditNow()
      refreshSession()
    })

  const doVerify = () =>
    guard('verify', async () => {
      if (!sealResp) return
      const resp = await docApi.verify(sealResp.container_b64)
      setVerify(resp.outcome)
      onLog(`verify '${sealResp.name}': ${resp.outcome.note}`)
      refreshAuditNow()
    })

  const doUnlock = () =>
    guard('unlock', async () => {
      if (!sealResp) return
      // Officer stands-in: fetch the real share bytes from the quorum
      // registry for exactly the checked officers (the server validates
      // them against the stored commitments).
      const info = await docApi.quorumInfo()
      const byX = new Map(info.officers.map((o) => [o.x, o]))
      const shares = quorumRows
        .filter((r) => r.checked)
        .map((r) => ({ x: r.x, y: byX.get(r.x)?.y ?? [] }))
      const resp = await docApi.quorumUnlock({ container_b64: sealResp.container_b64, shares })
      setUnlockResp(resp)
      onLog(
        `quorum unlock ${resp.recognized_officers.length}/${resp.shares_presented} shares recognized — ${resp.outcome?.note ?? 'rejected'}`,
      )
      refreshAuditNow()
    })

  const showProof = (seq: number) =>
    guard('proof', async () => {
      const p = await auditApi.proof(seq)
      setProof(p)
    })

  // ---- cross-account multiparty threshold -------------------------------

  const doDistribute = () =>
    guard('distribute', async () => {
      if (!sealResp?.quorum) return
      if (officerUsers.some((u) => !u.trim())) {
        throw new Error('fill in every officer username (one per share)')
      }
      const resp = await docApi.quorumDistribute(officerUsers.map((u) => u.trim()))
      setDistributeResp(resp)
      onLog(
        `distributed ${resp.assignments.length} officer shares → ${resp.assignments
          .map(([u, x]) => `${u}(OFF-${String(x).padStart(2, '0')})`)
          .join(', ')}`,
      )
      refreshSession()
      refreshAuditNow()
    })

  const doPledge = () =>
    guard('pledge', async () => {
      const resp = await docApi.quorumPledge()
      onLog(
        `pledged officer ${String(resp.officer_x).padStart(2, '0')} → ${resp.pledges_received}/${resp.threshold} pledges${
          resp.quorum_met ? ' — QUORUM MET ✓' : ''
        }`,
      )
      refreshAuditNow()
    })

  const doPledgedUnlock = () =>
    guard('pledged-unlock', async () => {
      if (!sealResp) return
      // No shares in the request → the server unlocks with shares other
      // accounts pledged from their own logins.
      const resp = await docApi.quorumUnlock({ container_b64: sealResp.container_b64, shares: [] })
      setUnlockResp(resp)
      onLog(
        `cross-account unlock: ${resp.recognized_officers.length} pledged shares → ${
          resp.outcome ? `unlocked (${resp.outcome.unlocked_via})` : 'rejected'
        }`,
      )
      refreshAuditNow()
      refreshSession()
    })

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">⚛ Quantum Document Vault</div>
        <div className="vault-session">
          {session?.has_key ? (
            <span className="chip chip-green">
              session key {session.key_preview}… · {session.remembered_keys} remembered
            </span>
          ) : (
            <span className="chip chip-gray">no session key — run a QKD exchange first</span>
          )}
          {session?.quorum && (
            <span className="chip chip-blue">
              quorum {session.quorum[0]}-of-{session.quorum[1]}
            </span>
          )}
        </div>
      </div>

      {error && <div className="error-banner">⚠ {error}</div>}

      <div className="vault-grid">
        {/* ---- seal ---- */}
        <div className="vault-col">
          <div className="vault-col-title">1 · Seal</div>
          <label className="dropzone">
            <input type="file" hidden onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
            {file ? (
              <>
                <span className="dropzone-name">{file.name}</span>
                <span className="dropzone-size">{(file.bytes.length / 1024).toFixed(1)} KB</span>
              </>
            ) : (
              <>
                <span className="dropzone-icon">🗎</span>
                <span>Drop a PDF / image / text file here</span>
              </>
            )}
          </label>

          <label className="control control-toggle">
            <span>Shamir quorum seal (k-of-m officers)</span>
            <input type="checkbox" checked={useQuorum} onChange={(e) => setUseQuorum(e.target.checked)} />
          </label>
          {useQuorum && (
            <div className="quorum-km">
              <label className="control">
                <span>
                  threshold k = <b>{k}</b>
                </span>
                <input type="range" min={2} max={m} step={1} value={k} onChange={(e) => setK(Number(e.target.value))} />
              </label>
              <label className="control">
                <span>
                  officers m = <b>{m}</b>
                </span>
                <input
                  type="range"
                  min={k}
                  max={10}
                  step={1}
                  value={m}
                  onChange={(e) => {
                    const v = Number(e.target.value)
                    setM(v)
                    if (k > v) setK(v)
                  }}
                />
              </label>
            </div>
          )}

          <button className="btn btn-primary" onClick={doSeal} disabled={!file || busy === 'seal'}>
            {busy === 'seal' ? 'Sealing…' : 'Seal → .qsig'}
          </button>

          {sealResp && (
            <div className="vault-result">
              <div className="vault-result-row">
                <span className="k">key commitment</span>
                <code>{sealResp.key_commitment.slice(0, 24)}…</code>
              </div>
              {sealResp.quorum && (
                <div className="vault-result-row">
                  <span className="k">officer commitments</span>
                  <code>{sealResp.officer_commitments.length} shares × SHA-256</code>
                </div>
              )}

              {/* ---- cross-account distribution (multiparty threshold) ---- */}
              {sealResp.quorum && (
                <div className="quorum-panel" style={{ marginTop: 8 }}>
                  <div className="quorum-title">
                    Multiparty: distribute the {sealResp.quorum[1]} shares to user accounts
                  </div>
                  {officerUsers.map((u, i) => (
                    <label key={i} className="control" style={{ marginBottom: 4 }}>
                      <span>OFF-{String(i + 1).padStart(2, '0')} → account</span>
                      <input
                        className="text-input"
                        value={u}
                        list="vault-users"
                        spellCheck={false}
                        placeholder={i === 0 ? getAuthUsername() ?? 'yourself' : 'other user'}
                        onChange={(e) =>
                          setOfficerUsers((prev) => prev.map((p, j) => (j === i ? e.target.value : p)))
                        }
                      />
                    </label>
                  ))}
                  <datalist id="vault-users">
                    {registeredUsers.map((u) => (
                      <option key={u} value={u} />
                    ))}
                  </datalist>
                  <button
                    className="btn btn-sm"
                    onClick={doDistribute}
                    disabled={busy === 'distribute' || officerUsers.some((u) => !u.trim())}
                  >
                    {busy === 'distribute' ? 'Distributing…' : 'Distribute shares →'}
                  </button>
                  {distributeResp && (
                    <div className="dim">
                      ✓ {distributeResp.assignments.map(([u, x]) => `${u}←OFF-${x}`).join(', ')} — each
                      officer logs in and PLEDGES; once ≥ {distributeResp.threshold} pledges arrive,
                      unlock below.
                    </div>
                  )}
                  {pledgesReceived > 0 && (
                    <div className="dim">
                      pledges received: <b>{pledgesReceived}</b>
                      <button
                        className="btn btn-sm btn-primary"
                        style={{ marginLeft: 8 }}
                        onClick={doPledgedUnlock}
                        disabled={busy === 'pledged-unlock'}
                      >
                        Unlock with {pledgesReceived} pledged shares →
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* ---- verify / unlock ---- */}
        <div className="vault-col">
          <div className="vault-col-title">2 · Verify / Unlock</div>
          {!sealResp && <div className="vault-placeholder">Seal a document to enable verification.</div>}
          {sealResp && (
            <>
              <button className="btn" onClick={doVerify} disabled={busy === 'verify'}>
                {busy === 'verify' ? 'Verifying…' : 'Verify against session key'}
              </button>
              {verify && (
                <div className={`verdict ${verify.authentic && verify.integrity ? 'verdict-ok' : 'verdict-bad'}`}>
                  {verify.format_ok && verify.authentic && verify.integrity ? '✓' : '✗'} {verify.note}
                </div>
              )}

              {quorumRows.length > 0 && (
                <div className="quorum-panel">
                  <div className="quorum-title">
                    Officer shares — toggle {quorumRows.length > 0 ? 'which officers present their keys' : ''}
                  </div>
                  <div className="officer-row">
                    {quorumRows.map((r) => (
                      <label key={r.x} className={`officer ${r.checked ? 'officer-on' : ''}`}>
                        <input
                          type="checkbox"
                          checked={r.checked}
                          onChange={(e) => setQuorumRows((prev) => prev.map((p) => (p.x === r.x ? { ...p, checked: e.target.checked } : p)))}
                        />
                        OFF-{String(r.x).padStart(2, '0')}
                      </label>
                    ))}
                  </div>
                  <button className="btn" onClick={doUnlock} disabled={busy === 'unlock'}>
                    {busy === 'unlock' ? 'Reconstructing…' : 'Unlock with selected shares'}
                  </button>
                  {unlockResp && (
                    <div className={`verdict ${unlockResp.outcome ? 'verdict-ok' : 'verdict-bad'}`}>
                      {unlockResp.outcome
                        ? `✓ ${unlockResp.threshold}-of-${unlockResp.shares_total} quorum met — document unlocked via ${unlockResp.outcome.unlocked_via}`
                        : `✗ unlock rejected — only ${unlockResp.recognized_officers.length} valid shares (need ${unlockResp.threshold})`}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* ---- officer pledge card (for share holders) ---- */}
      {heldShare && (
        <div className="quorum-panel" style={{ marginTop: 12 }}>
          <div className="quorum-title">
            🔑 You hold officer OFF-{String(heldShare.x).padStart(2, '0')} (distributed by{' '}
            {heldShare.from})
          </div>
          <div className="dim" style={{ marginBottom: 6 }}>
            The share bytes live server-side — pledging just commits your approval. The sealant
            unlocks only once enough officers pledge (k-of-m).
          </div>
          <button className="btn btn-primary btn-sm" onClick={doPledge} disabled={busy === 'pledge'}>
            {busy === 'pledge' ? 'Pledging…' : 'Pledge my share →'}
          </button>
        </div>
      )}

      {/* ---- audit ledger ---- */}
      <div className="ledger">
        <div className="ledger-head">
          <div className="vault-col-title">3 · Merkle Audit Ledger</div>
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
        {entries.length === 0 ? (
          <div className="vault-placeholder">No audit events yet — seal, verify, or transfer a document.</div>
        ) : (
          <div className="ledger-table">
            <div className="ledger-row ledger-row-head">
              <span>#</span>
              <span>kind</span>
              <span>detail</span>
              <span>leaf</span>
              <span></span>
            </div>
            {entries.slice(0, 25).map((e) => (
              <div key={e.seq} className={`ledger-row ${e.accepted ? '' : 'ledger-row-bad'}`}>
                <span className="mono">{e.seq}</span>
                <span>
                  <span className={`chip ${e.accepted ? 'chip-green' : 'chip-red'} chip-sm`}>{e.kind}</span>
                </span>
                <span className="ledger-detail">{e.detail}</span>
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
            <code>{proof.leaf_hash.slice(0, 32)}… → root {proof.root.slice(0, 32)}…</code>
            <div className="dim">
              Replaying the sibling chain recomputes exactly this root: the event provably sits in the ledger.
            </div>
            <button className="link-btn" onClick={() => setProof(null)}>
              dismiss
            </button>
          </div>
        )}
      </div>
    </section>
  )
}
