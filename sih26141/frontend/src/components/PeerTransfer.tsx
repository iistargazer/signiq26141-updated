import { useCallback, useEffect, useState } from 'react'
import {
  authApi,
  bytesToB64,
  docApi,
  getAuthUsername,
  type InboxItem,
  type OutboxItem,
  type PeerSendResponse,
  type WireProof,
  type RelayDepositResponse,
  type OpenResponse,
} from '../api'
import { sliderFillStyle } from '../sliderFill'

const MAX_BYTES = 5_000_000

/** Minimal signal-wave glyph for the dropzone (stroke inherits currentColor). */
function SignalIcon() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" aria-hidden>
      <path
        d="M2.5 12h3l2.5-6 4 12 3-8 1.8 2h4.7"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

/** Save raw document bytes (the opened original) as a file. */
function saveBytes(name: string, b64: string, mime = 'application/octet-stream') {
  const bin = atob(b64)
  const bytes = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const blob = new Blob([bytes as BlobPart], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

type Tab = 'inbox' | 'outbox'

/**
 * Real laptop-to-laptop transfer — three delivery modes:
 *   • Send to user        — into an account's inbox on THIS server.
 *   • Send to laptop      — POST over the network to another machine
 *                           (same LAN: HOST=0.0.0.0, no cloud needed).
 *   • Relay (cross-LAN)   — park the encrypted container on a public relay
 *                           under a claim code; the recipient redeems it
 *                           from ANY network (home ↔ friend's house).
 *
 * The sender's copies land in the OUTBOX (never the inbox). The wire report
 * shows transport metadata and ciphertext samples; it is not a cryptographic
 * proof that every byte was encrypted.
 */
export function PeerTransfer({
  onLog,
  authUser,
  authRevision,
}: {
  onLog: (line: string) => void
  authUser: string | null
  authRevision: number
}) {
  const [file, setFile] = useState<{ name: string; bytes: Uint8Array } | null>(null)
  const [peerUrl, setPeerUrl] = useState('')
  const [label, setLabel] = useState(getAuthUsername() ?? '')
  const [toUser, setToUser] = useState('')
  const [claimCode, setClaimCode] = useState('')
  const [registeredUsers, setRegisteredUsers] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<PeerSendResponse | null>(null)
  const [deposit, setDeposit] = useState<RelayDepositResponse | null>(null)
  const [tab, setTab] = useState<Tab>('inbox')
  const [items, setItems] = useState<InboxItem[]>([])
  const [sent, setSent] = useState<OutboxItem[]>([])
  const [wire, setWire] = useState<WireProof | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Consensus-ring delivery: members (comma-separated) + quorum k.
  const [ringMembers, setRingMembers] = useState('')
  const [ringK, setRingK] = useState(2)
  const [ringResult, setRingResult] = useState<{ accepted: string[]; missing: string[]; k: number; m: number; note: string } | null>(null)
  const [attesting, setAttesting] = useState<number | null>(null)

  const refreshBoxes = useCallback(() => {
    if (!authUser) {
      setItems([])
      setSent([])
      return
    }
    docApi.inbox(false).then((r) => setItems(r.items)).catch(() => {})
    docApi.outbox().then((r) => setSent(r.items)).catch(() => {})
  }, [authUser])

  useEffect(() => {
    setItems([])
    setSent([])
    setRegisteredUsers([])
    setResult(null)
    setDeposit(null)
    setRingResult(null)
    setError(null)
    setLabel(authUser ?? '')
    refreshBoxes()
    if (authUser) {
      // Address book: registered usernames for local user-to-user delivery.
      authApi.users().then((r) => setRegisteredUsers(r.users)).catch(() => {})
    }
    const t = setInterval(refreshBoxes, 5000)
    return () => clearInterval(t)
  }, [authRevision, authUser, refreshBoxes])

  const onFile = (f: File | null) => {
    setError(null)
    setResult(null)
    setDeposit(null)
    if (!f) {
      setFile(null)
      return
    }
    if (f.size > MAX_BYTES) {
      setError('file too large — demo scope is 5 MB')
      return
    }
    f.arrayBuffer().then((buf) => setFile({ name: f.name, bytes: new Uint8Array(buf) }))
  }

  const send = async (mode: 'user' | 'laptop') => {
    if (!file) return
    const targetUser = toUser.trim()
    const targetUrl = peerUrl.trim()
    if (mode === 'user' && !targetUser) return
    if (mode === 'laptop' && !targetUrl) return
    setBusy(true)
    setError(null)
    setResult(null)
    setDeposit(null)
    try {
      const resp = await docApi.peerSend({
        name: file.name,
        content_b64: bytesToB64(file.bytes),
        // The addressee is needed in BOTH modes: local delivery files the
        // container into that user's inbox here; laptop delivery tells the
        // remote server whose inbox to file it into.
        to_user: targetUser,
        peer_url: mode === 'laptop' ? targetUrl : undefined,
        from_label: label.trim() || 'peer',
      })
      setResult(resp)
      onLog(`p2p → ${resp.destination}: ${resp.summary}`)
      refreshBoxes()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  // Cross-LAN relay deposit: seal the file, then park the sealed container
  // on this server's relay mailbox under a claim code.
  const depositRelay = async () => {
    if (!file || !toUser.trim()) return
    setBusy(true)
    setError(null)
    setResult(null)
    setDeposit(null)
    try {
      const sealed = await docApi.seal({ name: file.name, content_b64: bytesToB64(file.bytes) })
      const resp = await docApi.relayDeposit({
        container_b64: sealed.container_b64,
        to_user: toUser.trim(),
        from_label: label.trim() || 'peer',
      })
      setDeposit(resp)
      onLog(`relay deposit → claim code ${resp.claim_code}: ${resp.relay_note}`)
      refreshBoxes()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const claimRelay = async () => {
    const code = claimCode.trim().toUpperCase()
    if (!code) return
    setBusy(true)
    setError(null)
    try {
      const resp = await docApi.relayClaim(code)
      onLog(`relay claim: ${resp.note}`)
      setClaimCode('')
      refreshBoxes()
      setTab('inbox')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const verifyItem = async (id: number, name: string) => {
    setError(null)
    try {
      const resp = await docApi.inboxVerify(id)
      onLog(`inbox verify '${name}': ${resp.outcome.note}`)
      refreshBoxes()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Download the ORIGINAL document from an inbox/outbox item (two-factor
  // unlock server-side: seal key + embedded QDS signature).
  const openItem = async (id: number, isOutbox: boolean, _name?: string) => {
    setError(null)
    try {
      const resp: OpenResponse = await docApi.open(
        isOutbox ? { outbox_id: id } : { inbox_id: id },
      )
      saveBytes(resp.name, resp.content_b64, resp.mime)
      onLog(`unlocked '${resp.name}' — ${resp.unlocked_via}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const showWireProof = async (id: number, isOutbox: boolean) => {
    setError(null)
    try {
      const w = await docApi.wireProof(isOutbox ? { outbox_id: id } : { inbox_id: id })
      setWire(w)
      onLog(`wire proof '${w.doc_name}': ${w.verdict}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const deleteItem = async (id: number, isOutbox: boolean) => {
    setError(null)
    try {
      if (isOutbox) await docApi.outboxDelete(id)
      else await docApi.inboxDelete(id)
      refreshBoxes()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const copyToClipboard = async (text: string, what: string) => {
    try {
      await navigator.clipboard.writeText(text)
      onLog(`${what} copied to clipboard`)
    } catch {
      /* clipboard unavailable — ignore */
    }
  }

  // ---- Consensus-ring delivery (Feature 4 fused with the P2P flow) ------
  // Seal the file, then deliver the SAME container to every ring member.
  // Each member must verify independently and attest; the recipient's open
  // stays locked until k attestations exist (enforced server-side).
  const sendRing = async () => {
    if (!file) return
    const members = ringMembers
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (members.length === 0) {
      setError('name the ring members (comma-separated usernames)')
      return
    }
    setBusy(true)
    setError(null)
    setRingResult(null)
    try {
      const sealed = await docApi.seal({ name: file.name, content_b64: bytesToB64(file.bytes) })
      const resp = await docApi.ringSend({
        container_b64: sealed.container_b64,
        members,
        k: Math.max(1, Math.min(members.length, ringK)),
      })
      setRingResult(resp)
      onLog(`consensus ring → ${resp.note}`)
      refreshBoxes()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  // This logged-in member's INDEPENDENT verification of a ring-delivered
  // copy — own session key, Trent's temporal trap, full statistics —
  // recorded as an attestation on the shared tally.
  const attestItem = async (id: number, name: string) => {
    const me = getAuthUsername()
    if (!me) return
    setAttesting(id)
    setError(null)
    try {
      const resp = await docApi.ringAttest(me, id)
      onLog(
        `ring attest '${name}': ${resp.verdict} — ${resp.note}`,
      )
      refreshBoxes()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setAttesting(null)
    }
  }

  const currentOutbox: OutboxItem[] = sent

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">Peer-to-Peer Transfer — inbox / outbox / relay</div>
        {busy && <span className="pulse-dot" aria-label="sending" />}
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="p2p-controls">
        <label className="dropzone dropzone-sm">
          <input type="file" hidden onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
          {file ? (
            <>
              <span className="dropzone-name">{file.name}</span>
              <span className="dropzone-size">{(file.bytes.length / 1024).toFixed(1)} KB</span>
            </>
          ) : (
            <>
              <span className="dropzone-icon"><SignalIcon /></span>
              <span>file to send (≤ 5 MB)</span>
            </>
          )}
        </label>

        <label className="control">
          <span>Recipient account</span>
          <input
            className="text-input"
            value={toUser}
            onChange={(e) => setToUser(e.target.value)}
            placeholder="bob"
            list="registered-users"
            spellCheck={false}
          />
          <datalist id="registered-users">
            {registeredUsers.map((u) => (
              <option key={u} value={u} />
            ))}
          </datalist>
        </label>
        <button className="btn btn-primary" onClick={() => send('user')} disabled={!file || busy || !toUser.trim()}>
          {busy ? 'Sending…' : 'Send to user →'}
        </button>
      </div>

      <div className="p2p-controls" style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
        <label className="control">
          <span>Consensus ring members (usernames, comma-separated)</span>
          <input
            className="text-input"
            value={ringMembers}
            onChange={(e) => setRingMembers(e.target.value)}
            placeholder="bob, charlie, dave"
            list="registered-users"
            spellCheck={false}
          />
        </label>
        <label className="control">
          <span>
            Quorum k <b>{ringK}</b>
          </span>
          <input
            type="range"
            min={1}
            max={Math.max(1, ringMembers.split(/[\s,;]+/).filter(Boolean).length)}
            step={1}
            value={Math.min(ringK, Math.max(1, ringMembers.split(/[\s,;]+/).filter(Boolean).length))}
            style={sliderFillStyle(1, Math.max(1, ringMembers.split(/[\s,;]+/).filter(Boolean).length), ringK)}
            onChange={(e) => setRingK(Number(e.target.value))}
          />
        </label>
        <button
          className="btn"
          onClick={sendRing}
          disabled={!file || busy || !ringMembers.trim()}
          title="Deliver to every member; each verifies independently; the copy unlocks only after k-of-m attestations"
        >
          Send to ring →
        </button>
      </div>

      <div className="p2p-controls" style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
        <label className="control">
          <span>Recipient server URL (same network)</span>
          <input
            className="text-input"
            value={peerUrl}
            onChange={(e) => setPeerUrl(e.target.value)}
            placeholder="http://<recipient-server-ip>:8080"
            spellCheck={false}
          />
        </label>
        <label className="control">
          <span>Sender name (optional)</span>
          <input className="text-input" value={label} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <button className="btn" onClick={() => send('laptop')} disabled={!file || busy || !peerUrl.trim() || !toUser.trim()}>
          Send to laptop →
        </button>
      </div>

      <div className="p2p-controls p2p-relay-controls">
        <div className="p2p-relay-copy">
          <b>Cross-network relay</b>
          <span>Use this server as the relay. The recipient claims the encrypted deposit here with your one-time code.</span>
        </div>
        <button
          className="btn"
          onClick={depositRelay}
          disabled={!file || busy || !toUser.trim()}
          title="Park the sealed file on this server's relay mailbox under a claim code"
        >
          Deposit on relay →
        </button>
        <label className="control">
          <span>…or claim a deposit</span>
          <input
            className="text-input"
            value={claimCode}
            onChange={(e) => setClaimCode(e.target.value)}
            placeholder="ABCD-EFGH"
            spellCheck={false}
            style={{ textTransform: 'uppercase' }}
          />
        </label>
        <button className="btn btn-primary" onClick={claimRelay} disabled={busy || !claimCode.trim()}>
          Claim →
        </button>
      </div>

      <div className="dim" style={{ margin: '4px 0 10px' }}>
        <b>Send to user</b> keeps delivery on this server. <b>Send to laptop</b> sends to a server
        you control on the same network. <b>Cross-network relay</b> parks the encrypted container
        here until the recipient claims it with a one-time code.{' '}
        <button className="link-btn" onClick={() => copyToClipboard(window.location.origin, "this server's base URL")}>
          copy this server's base URL
        </button>
        . The document container is encrypted before delivery; the wire report shows transport metadata, not a security attestation.
      </div>

      {result && (
        <div className={`verdict ${result.delivered ? 'verdict-ok' : 'verdict-bad'}`}>
          {result.delivered
            ? `✓ delivered — ${result.summary} (peer inbox id #${result.peer_item_id}, your copy in the outbox #${result.outbox_id})`
            : `✗ ${result.summary}`}
        </div>
      )}

      {ringResult && (
        <div className={`verdict ${ringResult.accepted.length > 0 ? 'verdict-ok' : 'verdict-bad'}`}>
          ⛨ consensus ring — {ringResult.note}
          {ringResult.missing.length > 0 && (
            <>
              {' '}unreachable: <b>{ringResult.missing.join(', ')}</b>
            </>
          )}
        </div>
      )}

      {deposit && (
        <div className="verdict verdict-ok">
          parked on the relay — claim code{' '}
          <b>
            <code
              style={{ cursor: 'pointer' }}
              onClick={() => copyToClipboard(deposit.claim_code, 'claim code')}
              title="click to copy"
            >
              {deposit.claim_code}
            </code>
          </b>{' '}
          — {deposit.relay_note}. {deposit.expires_note}
        </div>
      )}

      {wire && (
        <div className="proof-box">
          <div>
            <b>Transfer details — '{wire.doc_name}'</b> via {wire.transport}
          </div>
          <code style={{ display: 'block', margin: '4px 0' }}>
            wire bytes {wire.wire_bytes.toLocaleString()} · entropy{' '}
            <b>{wire.ciphertext_entropy.toFixed(2)} bits/byte</b> (≈8.0 = random) · scheme{' '}
            {wire.encryption_scheme}
            {wire.qds_signature_attached ? ' · QDS-signed' : ''}
          </code>
          <code style={{ display: 'block', wordBreak: 'break-all' }}>
            first wire bytes: {wire.ciphertext_sample_hex.slice(0, 64)}…
          </code>
          <div className="dim">
            {wire.verdict}            — the original file's SHA-256 is {wire.doc_sha256.slice(0, 16)}…. Ciphertext entropy and a byte sample are descriptive metadata, not proof that every wire byte was encrypted.
          </div>
          <button className="link-btn" onClick={() => setWire(null)}>
            dismiss
          </button>
        </div>
      )}

      <div className="p2p-inbox">
        <div className="p2p-inbox-head">
          <span>
            <button className={`btn btn-sm ${tab === 'inbox' ? 'btn-primary' : ''}`} onClick={() => setTab('inbox')}>
              Inbox ({items.length})
            </button>{' '}
            <button className={`btn btn-sm ${tab === 'outbox' ? 'btn-primary' : ''}`} onClick={() => setTab('outbox')}>
              Outbox ({currentOutbox.length})
            </button>
          </span>
          <span className="chip chip-gray">{tab === 'inbox' ? 'received from peers' : 'sent by you'}</span>
        </div>
        {tab === 'inbox' &&
          (items.length === 0 ? (
            <div className="vault-placeholder">Nothing received yet — send a document from another account or laptop.</div>
          ) : (
            <div className="p2p-inbox-list">
              {items.map((i) => (
                <div key={i.id} className="p2p-inbox-row">
                  <div className="p2p-inbox-main">
                    <b>{i.meta.name}</b>
                    <span className="dim">
                      {' '}· {(i.meta.size / 1024).toFixed(1)} KB · from {i.from_peer} ·{' '}
                      {i.received_at.slice(11, 19)}
                    </span>
                    {i.ring && (
                      <span
                        className={`chip chip-sm ${i.ring.attested_by.length >= i.ring.k ? 'chip-green' : 'chip-gray'}`}
                        style={{ marginLeft: 6 }}
                        title={`Consensus gate: ${i.ring.attested_by.length} of k = ${i.ring.k} independent verifications done (ring of ${i.ring.m}). Open stays locked until the quorum attests.${i.ring.attested_by.length > 0 ? ` Attested by: ${i.ring.attested_by.join(', ')}` : ''}`}
                      >
                        ⛨ ring {i.ring.attested_by.length}/{i.ring.k} of {i.ring.m}
                      </span>
                    )}
                  </div>
                  <div className="p2p-inbox-actions">
                    {i.ring && !i.ring.attested_by.includes(getAuthUsername() ?? '') && (
                      <button
                        className="btn btn-sm"
                        onClick={() => attestItem(i.id, i.meta.name)}
                        disabled={attesting === i.id}
                        title="Run YOUR independent verification (own key, Trent's temporal trap, full statistics) and record the attestation"
                      >
                        {attesting === i.id ? 'verifying…' : 'attest'}
                      </button>
                    )}
                    {i.verified === null && (
                      <button className="btn btn-sm" onClick={() => verifyItem(i.id, i.meta.name)}>
                        verify
                      </button>
                    )}
                    {i.verified !== null && (
                      <span className={`chip ${i.verified ? 'chip-green' : 'chip-red'} chip-sm`}>
                        {i.verified ? '✓ verified' : '✗ failed'}
                      </span>
                    )}
                    <button className="btn btn-sm" onClick={() => openItem(i.id, false, i.meta.name)} title="unlock (key + QDS signature) and download the original">
                      ⬇ open
                    </button>
                    <button className="btn btn-sm" onClick={() => showWireProof(i.id, false)} title="inspect available transfer metadata">
                      transfer details
                    </button>
                    <button className="link-btn" onClick={() => deleteItem(i.id, false)}>
                      delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ))}
        {tab === 'outbox' &&
          (currentOutbox.length === 0 ? (
            <div className="vault-placeholder">Nothing sent yet — your outgoing transfers appear here (never in the inbox).</div>
          ) : (
            <div className="p2p-inbox-list">
              {currentOutbox.map((o) => (
                <div key={o.id} className="p2p-inbox-row">
                  <div className="p2p-inbox-main">
                    <b>{o.meta.name}</b>
                    <span className="dim">
                      {' '}· {(o.meta.size / 1024).toFixed(1)} KB · to {o.to_peer} · via {o.via} ·{' '}
                      {o.sent_at.slice(11, 19)}
                    </span>
                    {o.claim_code && (
                      <span className="chip chip-blue chip-sm" style={{ marginLeft: 6 }}>
                        code {o.claim_code}
                      </span>
                    )}
                  </div>
                  <div className="p2p-inbox-actions">
                    <span className={`chip ${o.delivered ? 'chip-green' : 'chip-red'} chip-sm`}>
                      {o.delivered ? '✓ delivered' : '✗ failed'}
                    </span>
                    <button className="btn btn-sm" onClick={() => openItem(o.id, true, o.meta.name)} title="unlock your sent copy and download the original">
                      ⬇ open
                    </button>
                    <button className="btn btn-sm" onClick={() => showWireProof(o.id, true)} title="inspect available transfer metadata">
                      transfer details
                    </button>
                    <button className="link-btn" onClick={() => deleteItem(o.id, true)}>
                      delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ))}
      </div>
    </section>
  )
}
