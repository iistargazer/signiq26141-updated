import { useCallback, useEffect, useState } from 'react'
import {
  authApi,
  bytesToB64,
  docApi,
  getAuthUsername,
  type InboxItem,
  type PeerSendResponse,
} from '../api'

const MAX_BYTES = 5_000_000

/**
 * Real laptop-to-laptop transfer: POSTs the sealed .qsig container to a
 * peer server's /api/doc/receive over the network, and lists the local
 * inbox of documents received from other peers. Only the AES-GCM-encrypted
 * container crosses the wire — it is unreadable without the QKD session key.
 */
export function PeerTransfer({ onLog }: { onLog: (line: string) => void }) {
  const [file, setFile] = useState<{ name: string; bytes: Uint8Array } | null>(null)
  const [peerUrl, setPeerUrl] = useState('http://192.168.1.42:8080')
  const [label, setLabel] = useState(getAuthUsername() ?? 'Alice')
  const [toUser, setToUser] = useState('')
  const [registeredUsers, setRegisteredUsers] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<PeerSendResponse | null>(null)
  const [items, setItems] = useState<InboxItem[]>([])
  const [error, setError] = useState<string | null>(null)

  const refreshInbox = useCallback(() => {
    if (!getAuthUsername()) return
    docApi
      .inbox(false)
      .then((r) => setItems(r.items))
      .catch(() => {})
  }, [])

  useEffect(() => {
    refreshInbox()
    const t = setInterval(refreshInbox, 5000)
    // Address book: registered usernames for local user-to-user delivery.
    authApi.users().then((r) => setRegisteredUsers(r.users)).catch(() => {})
    return () => clearInterval(t)
  }, [refreshInbox])

  const onFile = (f: File | null) => {
    setError(null)
    setResult(null)
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
      refreshInbox()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const deleteItem = async (id: number) => {
    setError(null)
    try {
      await docApi.inboxDelete(id)
      refreshInbox()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      onLog('api base copied to clipboard')
    } catch {
      /* clipboard unavailable — ignore */
    }
  }

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">📡 Peer-to-Peer Transfer — laptop → laptop</div>
        {busy && <span className="pulse-dot" aria-label="sending" />}
      </div>

      {error && <div className="error-banner">⚠ {error}</div>}

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
              <span className="dropzone-icon">📡</span>
              <span>file to send (≤ 5 MB)</span>
            </>
          )}
        </label>

        <label className="control">
          <span>Recipient username (on this server)</span>
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
          <span>…or remote laptop API base URL (same recipient, other machine)</span>
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

      <div className="dim" style={{ margin: '4px 0 10px' }}>
        <b>Send to user</b> delivers into that account's inbox on THIS server (both accounts can
        share one laptop). <b>Send to laptop</b> POSTs the encrypted container over the network —
        the other laptop runs this server with <code>HOST=0.0.0.0</code> —{' '}
        <button className="link-btn" onClick={() => copyToClipboard(window.location.origin)}>
          copy this machine's base URL
        </button>{' '}
        and paste it into the peer box on the other machine. Only the AES-GCM-encrypted .qsig
        container travels; without the QKD session key the peer sees ciphertext.
      </div>

      {result && (
        <div className={`verdict ${result.delivered ? 'verdict-ok' : 'verdict-bad'}`}>
          {result.delivered
            ? `✓ delivered — ${result.summary} (peer inbox id #${result.peer_item_id})`
            : `✗ ${result.summary}`}
        </div>
      )}

      <div className="p2p-inbox">
        <div className="p2p-inbox-head">
          <span className="vault-col-title">Inbox — documents received from peers</span>
          <span className="chip chip-gray">{items.length} items</span>
        </div>
        {items.length === 0 ? (
          <div className="vault-placeholder">Nothing received yet — send a document from another laptop.</div>
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
                  <button className="link-btn" onClick={() => deleteItem(i.id)}>
                    dismiss
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
