import { useEffect, useState } from 'react'
import {
  authApi,
  clearAuthSession,
  getAuthToken,
  getAuthUsername,
  setAuthSession,
} from '../api'

/**
 * Account bar for the multi-user website: register / login / logout.
 *
 * The bearer token lives in localStorage; the server scopes session keys,
 * quorum splits, and the P2P inbox per user, so two laptops with two
 * accounts never see each other's documents. When the persisted token is
 * stale (server restart wipes the in-memory session table) the bar falls
 * back to anonymous mode automatically.
 */
export function AuthBar({
  onLog,
  onUserChange,
}: {
  onLog: (line: string) => void
  onUserChange: (user: string | null) => void
}) {
  const [user, setUser] = useState<string | null>(getAuthUsername())
  const [usernameInput, setUsernameInput] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Revalidate the persisted token on mount — expired sessions (server
  // restart) must not leave the UI claiming an identity it no longer has.
  useEffect(() => {
    const token = getAuthToken()
    if (!token) return
    authApi
      .me()
      .then((me) => {
        setUser(me.username)
        onUserChange(me.username)
      })
      .catch(() => {
        clearAuthSession()
        setUser(null)
        onUserChange(null)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const doAuth = async (mode: 'login' | 'register') => {
    const username = usernameInput.trim()
    if (!username || !password) {
      setError('username and password are required')
      return
    }
    setBusy(true)
    setError(null)
    try {
      if (mode === 'register') {
        const r = await authApi.register(username, password)
        if (!r.ok) throw new Error(r.error ?? 'registration failed')
        onLog(`account '${username}' registered`)
      }
      const r = await authApi.login(username, password)
      if (!r.ok || !r.token) throw new Error(r.error ?? 'login failed')
      setAuthSession(r.token, username)
      setUser(username)
      setUsernameInput('')
      setPassword('')
      onUserChange(username)
      onLog(`logged in as '${username}' — workspace, keys and inbox are now yours`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const logout = async () => {
    try {
      await authApi.logout()
    } catch {
      /* session may already be gone server-side */
    }
    clearAuthSession()
    setUser(null)
    onUserChange(null)
    onLog('logged out — back to the shared anonymous workspace')
  }

  if (user) {
    return (
      <div className="auth-bar">
        <span className="chip chip-green">{user}</span>
        <span className="dim">your keys, seals and inbox are private to this account</span>
        <button className="btn btn-sm" onClick={logout} disabled={busy}>
          log out
        </button>
      </div>
    )
  }

  return (
    <div className="auth-bar">
      <span className="dim">anonymous workspace —</span>
      <input
        className="text-input auth-input"
        placeholder="username"
        value={usernameInput}
        spellCheck={false}
        autoComplete="username"
        onChange={(e) => setUsernameInput(e.target.value)}
      />
      <input
        className="text-input auth-input"
        type="password"
        placeholder="password (≥ 6 chars)"
        value={password}
        autoComplete="current-password"
        onChange={(e) => setPassword(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') doAuth('login')
        }}
      />
      <button className="btn btn-sm btn-primary" onClick={() => doAuth('login')} disabled={busy}>
        log in
      </button>
      <button className="btn btn-sm" onClick={() => doAuth('register')} disabled={busy}>
        register
      </button>
      {error && <span className="auth-error">{error}</span>}
    </div>
  )
}
