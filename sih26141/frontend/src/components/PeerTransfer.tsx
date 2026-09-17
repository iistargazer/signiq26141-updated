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
 * The sender's copies land in the OUTBOX (never the inbox), and the wire
 * proof shows exactly what crossed the network: entropy, ciphertext sample,
 * hashes — the evidence that the file traveled encrypted.
 */
export function PeerTransfer({ onLog }: { onLog: (line: string) => void }) {
  const [file, setFile] = useState<{ name: string; bytes: Uint8Array } | null>(null)
  const [peerUrl, setPeerUrl] = useState('http://192.168.1.42:8080')
  const [relayUrl, setRelayUrl] = useState('')
  const [label, setLabel] = useState(getAuthUsername() ?? 'Alice')
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

  const refreshBoxes = useCallback(() => {
    if (!getAuthUsername()) return
    docApi.inbox(false).then((r) => setItems(r.items)).catch(() => {})
    docApi.outbox().then((r) => setSent(r.items)).catch(() => {})
  }, [])

  useEffect(() => {
    refreshBoxes()
    const t = setInterval(refreshBoxes, 5000)
    // Address book: registered usernames for local user-to-user delivery.
    authApi.users().then((r) => setRegisteredUsers(r.users)).catch(() => {})
    return () => clearInterval(t)
  }, [refreshBoxes])

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
          <span>Recipient username</span>
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

      <div className="p2p-controls" style={{ borderTop: '1px solid var(--line, #2a2a3a)', paddingTop: 10 }}>
        <label className="control">
          <span>Same-LAN laptop URL (other machine, HOST=0.0.0.0)</span>
          <input
            className="text-input"
            value={peerUrl}
            onChange={(e) => setPeerUrl(e.target.value)}
            placeholder="http://192.168.1.42:8080"
            spellCheck={false}
          />
        </label>
        <label className="control">
          <span>Sender label</span>
          <input className="text-input" value={label} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <button className="btn" onClick={() => send('laptop')} disabled={!file || busy || !peerUrl.trim() || !toUser.trim()}>
          Send to laptop →
        </button>
      </div>

      <div className="p2p-controls" style={{ borderTop: '1px solid var(--line, #2a2a3a)', paddingTop: 10 }}>
        <label className="control">
          <span>Cross-LAN relay URL (public deployment, e.g. onrender.com)</span>
          <input
            className="text-input"
            value={relayUrl}
            onChange={(e) => setRelayUrl(e.target.value)}
            placeholder="https://your-app.onrender.com (blank = this server is the relay)"
            spellCheck={false}
          />
        </label>
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
        <b>Send to user</b> = same server, different accounts. <b>Send to laptop</b> = another
        machine on the same network. <b>Relay</b> = different networks (home ↔ anywhere): the file
        is parked encrypted under a claim code and the recipient redeems it from any network.{' '}
        <button className="link-btn" onClick={() => copyToClipboard(window.location.origin, "this machine's base URL")}>
          copy this machine's base URL
        </button>
        . Only the AES-256-GCM ciphertext travels — and the <b>wire proof</b> proves it.
      </div>

      {result && (
        <div className={`verdict ${result.delivered ? 'verdict-ok' : 'verdict-bad'}`}>
          {result.delivered
            ? `✓ delivered — ${result.summary} (peer inbox id #${result.peer_item_id}, your copy in the outbox #${result.outbox_id})`
            : `✗ ${result.summary}`}
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
            <b>wire proof — '{wire.doc_name}'</b> via {wire.transport}
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
            {wire.verdict} — the original file's SHA-256 is {wire.doc_sha256.slice(0, 16)}… but every
            byte on the wire was ciphertext. A wiretap sees noise.
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
                  </div>
                  <div className="p2p-inbox-actions">
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
                    <button className="btn btn-sm" onClick={() => showWireProof(i.id, false)} title="prove what crossed the wire">
                      wire proof
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
                    <button className="btn btn-sm" onClick={() => showWireProof(o.id, true)} title="prove what crossed the wire">
                      wire proof
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
