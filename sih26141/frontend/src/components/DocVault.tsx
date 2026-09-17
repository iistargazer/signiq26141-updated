import { useCallback, useEffect, useRef, useState } from 'react'
import {
  authApi,
  b64ToBytes,
  bytesToB64,
  docApi,
  getAuthUsername,
  type OpenResponse,
  type QdsKeyResponse,
  type SessionInfo,
  type SealResponse,
  type VerificationOutcome,
  type QuorumUnlockResponse,
  type DistributeResponse,
} from '../api'

/** Minimal document glyph for the dropzone (stroke inherits currentColor). */
function DocIcon() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" aria-hidden>
      <path
        d="M7 3h7l4 4v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path d="M14 3v4h4M9.5 12h5M9.5 15.5h5" stroke="currentColor" strokeWidth="1.2" />
    </svg>
  )
}

/** Download helper for raw bytes (the opened document or a .qsig container). */
function downloadBytes(name: string, b64: string, mime = 'application/octet-stream') {
  const blob = new Blob([b64ToBytes(b64)], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

function downloadContainer(name: string, containerB64: string) {
  downloadBytes(name.endsWith('.qsig') ? name : `${name}.qsig`, containerB64)
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
  const [qdsKey, setQdsKey] = useState<QdsKeyResponse | null>(null)
  const [opened, setOpened] = useState<OpenResponse | null>(null)
  const [quorumRows, setQuorumRows] = useState<QuorumRow[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Cross-account multiparty state (distribute / pledge / pledged unlock)
  const [registeredUsers, setRegisteredUsers] = useState<string[]>([])
  const [officerUsers, setOfficerUsers] = useState<string[]>([])
  const [distributeResp, setDistributeResp] = useState<DistributeResponse | null>(null)
  const [heldShare, setHeldShare] = useState<{ x: number; from: string } | null>(null)
  const [pledgesReceived, setPledgesReceived] = useState(0)

  const refreshAudit = useRef<() => void>(() => {})

  const refreshAuditNow = useCallback(() => {
    refreshAudit.current()
  }, [])

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

  useEffect(() => {
    refreshSession()
  }, [refreshSession])

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
      setOpened(null)
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
          (resp.quorum ? ` · quorum ${resp.quorum[0]}-of-${resp.quorum[1]}` : '') +
          ` · key: ${resp.key_source}` +
          (resp.qds_signature ? ' · teleport-QDS signature attached' : ''),
      )
      if (resp.audit_warning) onLog(`ledger: ${resp.audit_warning}`)
      refreshAuditNow()
      refreshSession()
    })

  // Six-state QDS key generation: the document layer's own key path.
  const doQdsKey = () =>
    guard('qds-key', async () => {
      const resp = await docApi.qdsKey()
      setQdsKey(resp)
      onLog(`QDS key generated: ${resp.provenance}`)
      refreshAuditNow()
      refreshSession()
    })

  // Unlock: recover the ORIGINAL document (two-factor: seal key + QDS sig).
  const doOpen = () =>
    guard('open', async () => {
      if (!sealResp) return
      const resp = await docApi.open({ container_b64: sealResp.container_b64 })
      setOpened(resp)
      onLog(`unlocked '${resp.name}' — ${resp.unlocked_via}`)
      refreshAuditNow()
    })

  const saveOpened = () => {
    if (!opened) return
    downloadBytes(opened.name, opened.content_b64, opened.mime || 'application/octet-stream')
    onLog(`saved '${opened.name}' (${(opened.size / 1024).toFixed(1)} KB) — original bytes recovered`)
  }

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
        <div className="panel-title">Quantum Document Vault</div>
        <div className="vault-session">
          {session?.has_key ? (
            <span className="chip chip-green">
              session key {session.key_preview}… · {session.remembered_keys} remembered
            </span>
          ) : (
            <span className="chip chip-gray">no session key yet</span>
          )}
          {session?.quorum && (
            <span className="chip chip-blue">
              quorum {session.quorum[0]}-of-{session.quorum[1]}
            </span>
          )}
          <button className="btn btn-sm btn-primary" onClick={doQdsKey} disabled={busy === 'qds-key'}>
            {busy === 'qds-key' ? 'Deriving…' : 'Generate QDS key'}
          </button>
        </div>
      </div>

      {qdsKey && (
        <div className="dim" style={{ marginBottom: 8 }}>
          🔐 Sealing key derived from <b>six-state QDS session #{qdsKey.session_id}</b> —{' '}
          {qdsKey.conclusive_bits} conclusive bits / {qdsKey.n_pulses} qubits per message · mismatch{' '}
          {(qdsKey.mismatch_rate * 100).toFixed(1)}% · commitment {qdsKey.key_commitment.slice(0, 16)}…
        </div>
      )}

      {error && <div className="error-banner">{error}</div>}

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
                <span className="dropzone-icon"><DocIcon /></span>
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
              <button className="btn btn-primary" onClick={doOpen} disabled={busy === 'open'}>
                {busy === 'open' ? 'Unlocking…' : '🔓 Unlock & download original'}
              </button>
              {verify && (
                <div className={`verdict ${verify.authentic && verify.integrity ? 'verdict-ok' : 'verdict-bad'}`}>
                  {verify.format_ok && verify.authentic && verify.integrity ? '✓' : '✗'} {verify.note}
                </div>
              )}
              {opened && (
                <div className="vault-result">
                  <div className={`verdict verdict-ok`}>
                    ✓ document unlocked — {opened.unlocked_via}
                  </div>
                  {opened.qds_check && (
                    <div className="vault-result-row">
                      <span className="k">teleport-QDS</span>
                      <code>
                        {opened.qds_check.verdict.toUpperCase()} · {(opened.qds_check.match_ratio * 100).toFixed(0)}% match
                      </code>
                    </div>
                  )}
                  <div className="vault-result-row">
                    <span className="k">original file</span>
                    <code>
                      {opened.name} ({(opened.size / 1024).toFixed(1)} KB)
                    </code>
                  </div>
                  <button className="btn btn-sm btn-primary" onClick={saveOpened}>
                    ⬇ save '{opened.name}'
                  </button>
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
            You hold officer OFF-{String(heldShare.x).padStart(2, '0')} (distributed by{' '}
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

      <div className="ledger">
        <div className="ledger-head">
          <div className="vault-col-title">Merkle Audit Ledger</div>
          <div className="ledger-badges">
            <span className="chip chip-gray">
              live — full ledger + proofs in the <a className="link-btn" href="#ledger" onClick={(e) => { e.preventDefault(); document.getElementById('ledger')?.scrollIntoView({ behavior: 'smooth' }) }}>Ledger</a> section
            </span>
          </div>
        </div>
      </div>
    </section>
  )
}
