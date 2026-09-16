export interface ScenarioResult {
  scenario: string
  intercept_ratio: number
  /** Environmental bit-flip probability (0 when the noise filter is off). */
  noise_rate?: number
  /** Relay hops between Alice and Bob (0 = direct link). */
  relay_hops?: number
  /** Per-link relay statistics when relays are in the route. */
  relay_stats?: HopStats[]
  raw_key_length: number
  matching_bases_count: number
  sifted_key_length: number
  qber: number
  dynamic_threshold: number
  is_authentic: boolean
  threat_flagged: boolean
  /** Three-way classification: secure / degraded / under_attack. */
  channel_class?: string
  first_divergence: number | null
  derived_secret?: string
  hmac_tag?: string
  hmac_valid?: boolean
  note: string
}

export interface HopStats {
  hop: number
  from: string
  to: string
  in_qubits: number
  out_qubits: number
  mismatches: number
  qber: number
  interceptions: number
  noise_rate: number
  intercept_ratio: number
}

export interface RunResponse {
  run_id: number
  /** Seed actually used server-side (blank UI seed = fresh random). */
  seed?: number
  results: ScenarioResult[]
  authenticated_message: string | null
}

export interface SweepResponse {
  run_id: number
  /** Seed actually used server-side. */
  seed?: number
  sweep: ScenarioResult[]
}

export interface ProgressEvent {
  type: 'progress'
  run_id: number
  scenario: string
  processed: number
  total: number
  sifted: number
  mismatches: number
  qber: number
  threshold: number
}

export interface ResultEvent {
  type: 'result'
  run_id: number
  result: ScenarioResult
}

export interface DoneEvent {
  type: 'done'
  run_id: number
}

export type RunEvent = ProgressEvent | ResultEvent | DoneEvent

// Same-origin by default; discoverApiBase() can retarget all calls to a
// fallback server port at runtime (see apiBase()).
let BASE_OVERRIDE = ''
export function setApiBase(newBase: string) {
  BASE_OVERRIDE = newBase
}

export function base(): string {
  if (BASE_OVERRIDE) return BASE_OVERRIDE
  return import.meta.env.DEV ? '' : window.location.origin
}

// ---------------- Auth session (bearer token in localStorage) ----------------

const TOKEN_KEY = 'qsig_token'
const USER_KEY = 'qsig_username'

export function getAuthToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function getAuthUsername(): string | null {
  return localStorage.getItem(USER_KEY)
}

export function setAuthSession(token: string, username: string) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, username)
}

export function clearAuthSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

/** Authorization header for the logged-in user (empty when anonymous). */
export function authHeaders(): Record<string, string> {
  const token = getAuthToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function jsonFetch<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(`${base()}${url}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const err = await res.json()
      if (err?.error) msg = err.error
    } catch {
      /* keep default */
    }
    throw new Error(msg)
  }
  return res.json() as Promise<T>
}

export function startRun(params: {
  key_length?: number
  base_threshold?: number
  intercept_ratio?: number
  noise_rate?: number
  relay_hops?: number
  message?: string
  seed?: number
  pace_ms?: number
}): Promise<RunResponse> {
  return jsonFetch<RunResponse>('/api/run', params)
}

export function runSweep(params: {
  intercept_ratios: number[]
  key_length?: number
  base_threshold?: number
  noise_rate?: number
  relay_hops?: number
  seed?: number
}): Promise<SweepResponse> {
  return jsonFetch<SweepResponse>('/api/simulate', params)
}

export function healthCheck(): Promise<string> {
  return fetch(`${base()}/api/health`).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    return r.text()
  })
}

/**
 * Locate the API when the same-origin health check fails.
 *
 * Discovery order:
 * 1. same-origin /api/health (server-served dashboard, or vite proxy in dev)
 * 2. /server-port.json static manifest — the server writes it into the
 *    frontend dist when a port fallback moved it off the requested port
 * 3. adjacent ports 8081..8090 — direct probe (works when the dashboard is
 *    opened via vite dev or a file copy where the manifest is stale)
 *
 * Resolves with the API base URL ("" for same-origin), rejects if none respond.
 */
export async function discoverApiBase(): Promise<string> {
  try {
    await healthCheck()
    return ''
  } catch {
    /* fall through to discovery */
  }

  // 2. static port manifest written by the server on fallback
  try {
    const res = await fetch('/server-port.json', { cache: 'no-store' })
    if (res.ok) {
      const manifest = (await res.json()) as { actual_port?: number }
      if (manifest.actual_port) {
        const base = `http://127.0.0.1:${manifest.actual_port}`
        const probe = await fetch(`${base}/api/health`)
        if (probe.ok) return base
      }
    }
  } catch {
    /* fall through */
  }

  // 3. adjacent-port probe
  for (let p = 8081; p <= 8090; p++) {
    try {
      const probe = await fetch(`http://127.0.0.1:${p}/api/health`)
      if (probe.ok) return `http://127.0.0.1:${p}`
    } catch {
      /* keep probing */
    }
  }
  throw new Error('API not found on same origin, port manifest, or ports 8081-8090')
}

// ---------------- QDS Signature Lab ----------------

export interface QdsSetupResponse {
  qubit_count: number
  lambda: number
  key_commitment: string
  theory_forgery_probability: number
}

export interface TeleportSample {
  position: number
  bell_outcome: number
  correction: string
  raw_bit: number
  corrected_bit: number
}

export interface QdsSignResponse {
  nonce: number
  signature_hex: string
  teleport_sample: TeleportSample[]
  qubit_count: number
  lambda: number
  theory_forgery_probability: number
  initial_verification_accepted: boolean
}

export interface VerificationReport {
  accepted: boolean
  verdict: 'acc1' | 'acc0' | 'rej'
  match_ratio: number
  mismatches: number
  total_positions: number
  /** False when rejection happened before statistics (replay/commitment
   * check) — mismatches/match_ratio are then not measured evidence. */
  evaluated?: boolean
  reason: string
}

export interface QdsOutcome {
  label: string
  kind: string
  report: VerificationReport
  description: string
  claimed_message: string
  charlie_agrees?: boolean
}

export interface QdsEventRow {
  ts: string
  kind: string
  label: string
  accepted: boolean
  detail: string
}

export interface ForgeryAnalysis {
  qubit_count: number
  lambda: number
  trials: number
  monte_carlo_probability: number
  theory_probability: number
  by_lambda: { lambda: number; theory: number }[]
}

export const qdsApi = {
  setup: (qubitCount: number, lambda: number): Promise<QdsSetupResponse> =>
    jsonFetch<QdsSetupResponse>('/api/qds/setup', {
      qubit_count: qubitCount,
      lambda,
    }),
  sign: (message: string, seed?: number): Promise<QdsSignResponse> =>
    jsonFetch<QdsSignResponse>('/api/qds/sign', { message, seed }),
  verify: (message: string, signatureHex: string, nonce: number): Promise<QdsOutcome> =>
    jsonFetch<QdsOutcome>('/api/qds/verify', {
      message,
      signature_hex: signatureHex,
      nonce,
    }),
  attacks: (tamperFraction?: number): Promise<QdsOutcome[]> => {
    const q = tamperFraction !== undefined ? `?tamper_fraction=${tamperFraction}` : ''
    return fetch(`${base()}/api/qds/attacks${q}`).then((r) => r.json())
  },
  forgeryAnalysis: (): Promise<ForgeryAnalysis> =>
    fetch(`${base()}/api/qds/forgery-analysis`).then((r) => r.json()),
  metrics: (trials?: number, seed?: number): Promise<MetricsReport> => {
    const params = new URLSearchParams()
    if (trials !== undefined) params.set('trials', String(trials))
    if (seed !== undefined) params.set('seed', String(seed))
    const q = params.toString() ? `?${params.toString()}` : ''
    return fetch(`${base()}/api/qds/metrics${q}`).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      return r.json()
    })
  },
  events: (): Promise<{ events: QdsEventRow[] }> =>
    fetch(`${base()}/api/qds/events`).then((r) => r.json()),
}

// ---------------- Performance evaluation (Lap 2 deliverable) ----------------

export interface ConfusionCounts {
  true_negatives: number
  false_positives: number
  true_positives: number
  false_negatives: number
}

export interface TimingStats {
  samples: number
  mean_sign_us: number
  mean_verify_us: number
  mean_attack_us: number
  mean_setup_us: number
}

export interface TeleportMetrics {
  trials: number
  qubit_count: number
  lambda: number
  confusion: ConfusionCounts
  empirical_forgery_probability: number
  theoretical_forgery_probability: number
  timing: TimingStats
}

export interface ClassDetection {
  detected: number
  missed: number
}

export interface SixStateMetrics {
  trials: number
  n_pulses: number
  confusion: ConfusionCounts
  detection_by_class: Record<string, ClassDetection>
  timing: TimingStats
}

export interface MetricsReport {
  teleport: TeleportMetrics
  six_state: SixStateMetrics
  notes: string[]
}

// ---------------- Accounts (multi-user website) ----------------

export interface AuthResponse {
  ok: boolean
  token: string | null
  username: string | null
  error: string | null
}

export const authApi = {
  register: (username: string, password: string): Promise<AuthResponse> =>
    jsonFetch<AuthResponse>('/api/auth/register', { username, password }),
  login: (username: string, password: string): Promise<AuthResponse> =>
    jsonFetch<AuthResponse>('/api/auth/login', { username, password }),
  logout: (): Promise<{ ok: boolean }> =>
    fetch(`${base()}/api/auth/logout`, { method: 'POST', headers: authHeaders() }).then((r) => r.json()),
  me: (): Promise<{ username: string }> =>
    fetch(`${base()}/api/auth/me`, { headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`not authenticated (HTTP ${r.status})`)
      return r.json()
    }),
  users: (): Promise<{ users: string[] }> =>
    fetch(`${base()}/api/auth/users`).then((r) => r.json()),
}

// ---------------- Document Vault (features 3 + 7) + Transfer Portal (4) + Audit (5) ----------------

export interface SessionInfo {
  has_key: boolean
  key_commitment?: string
  key_preview?: string
  remembered_keys: number
  quorum: [number, number] | null
}

export interface SealResponse {
  /** The .qsig container as base64 (wire format for P2P send/receive). */
  container_b64: string
  name: string
  size: number
  sha256: string
  key_commitment: string
  quorum: [number, number] | null
  officer_commitments: string[]
  audit_seq: number
  audit_root?: string
  audit_warning?: string
}

export interface VerificationOutcome {
  authentic: boolean
  integrity: boolean
  format_ok: boolean
  key_match: boolean
  unlocked_via: string
  note: string
  payloadScheme?: string
}

/** Mirrors the Rust `VerificationOutcome::passed()` (all four flags true). */
export function isPassed(o: VerificationOutcome): boolean {
  return o.format_ok && o.authentic && o.integrity && o.key_match
}

export interface VerifyResponse {
  outcome: VerificationOutcome
  verified_with_commitment?: string
  meta?: { name: string; size: number; mime: string; sha256: string; sealed_at: string }
  audit_seq: number
  audit_warning?: string
}

export interface QuorumUnlockResponse {
  shares_presented: number
  threshold: number
  shares_total: number
  enough_shares: boolean
  outcome: VerificationOutcome | null
  recognized_officers: number[]
  audit_seq: number
  audit_warning?: string
}

export interface OfficerShare {
  x: number
  y: number[]
  commitment: string
}

export interface QuorumInfo {
  threshold: number | null
  shares_total: number | null
  officers: OfficerShare[]
  /** Present when the CALLER holds a distributed officer share. */
  held_share?: { x: number; commitment: string; from: string } | null
  /** Cross-account pledges received by the caller (sealant side). */
  pledges_received?: number
  pledges?: string[]
}

export interface DistributeResponse {
  assignments: [string, number][]
  threshold: number
  shares_total: number
  audit_seq: number
  audit_warning?: string
}

export interface PledgeResponse {
  pledged: boolean
  officer_x: number
  pledges_received: number
  threshold: number
  quorum_met: boolean
  audit_seq: number
  audit_warning?: string
}

export interface InboxItem {
  id: number
  received_at: string
  from_peer: string
  meta: { name: string; size: number; mime: string; sha256: string; sealed_at: string }
  container_b64?: string
  verified: boolean | null
  note: string | null
}

export interface InboxListResponse {
  items: InboxItem[]
  total: number
}

export interface PeerSendResponse {
  delivered: boolean
  /** Where the container went: "bob (local)" or the peer API base URL. */
  destination: string
  peer_item_id: number | null
  peer_note: string | null
  sha256: string
  audit_seq: number
  audit_warning?: string
  summary: string
}

export interface PeerReceiveResponse {
  accepted: boolean
  item_id: number
  meta: { name: string; size: number; mime: string; sha256: string; sealed_at: string } | null
  can_verify_now: boolean
  note: string
  audit_seq: number
  audit_warning?: string
}

export interface TransferResponse {
  transfer_id: number
  hops: number
  key_derived: boolean
  seal_ok: boolean
  delivered: boolean
  verdict: VerificationOutcome | null
  relay_stats: HopStats[]
  qber?: number
  audit_seq: number
  summary: string
}

export interface TransferLogEvent {
  type: 'transfer_log'
  transfer_id: number
  stage: string
  node: string
  detail: string
  level: string
}

export interface TransferDoneEvent {
  type: 'transfer_done'
  transfer_id: number
  accepted: boolean
  summary: string
}

export type DocEvent = TransferLogEvent | TransferDoneEvent

export interface AuditEntry {
  seq: number
  ts: string
  kind: string
  label: string
  accepted: boolean
  detail: string
  payload_hash: string
  leaf_hash: string
}

export interface AuditEventsResponse {
  entries: AuditEntry[]
  root?: string
  total: number
}

export interface InclusionProof {
  seq: number
  leaf_hash: string
  siblings: string[]
  root: string
}

export interface ChainVerdict {
  ok: boolean
  broken_at: number | null
  root?: string
  detail: string
}

export interface AttackResponse {
  mode: string
  description: string
  /** The mangled container Mallory would forward to Bob. */
  container_b64: string
  target_sha256: string
  expected_outcome: string
  audit_seq: number
  audit_warning?: string
}

export type AttackMode = 'tamper_bytes' | 'swap_meta' | 'reseal' | 'truncate'

export const docApi = {
  session: (): Promise<SessionInfo> =>
    fetch(`${base()}/api/doc/session`, { headers: authHeaders() }).then((r) => r.json()),
  seal: (params: {
    name: string
    content_b64: string
    mime?: string
    use_quorum?: boolean
    quorum_threshold?: number
    quorum_shares?: number
  }): Promise<SealResponse> => jsonFetch<SealResponse>('/api/doc/seal', params),
  verify: (containerB64: string): Promise<VerifyResponse> =>
    jsonFetch<VerifyResponse>('/api/doc/verify', { container_b64: containerB64 }),
  quorumInfo: (): Promise<QuorumInfo> =>
    fetch(`${base()}/api/doc/quorum`, { headers: authHeaders() }).then((r) => r.json()),
  quorumDistribute: (users: string[]): Promise<DistributeResponse> =>
    jsonFetch<DistributeResponse>('/api/doc/quorum/distribute', { users }),
  quorumPledge: (): Promise<PledgeResponse> =>
    fetch(`${base()}/api/doc/quorum/pledge`, {
      method: 'POST',
      headers: authHeaders(),
    }).then((r) => {
      if (!r.ok) throw new Error(`pledge failed (HTTP ${r.status})`)
      return r.json()
    }),
  attack: (params: {
    container_b64: string
    mode: AttackMode
    from_label?: string
  }): Promise<AttackResponse> => jsonFetch<AttackResponse>('/api/doc/attack', params),
  quorumUnlock: (params: {
    container_b64?: string
    /** Omit (or pass []) for the cross-account pledged-unlock mode. */
    shares?: { x: number; y: number[] }[]
  }): Promise<QuorumUnlockResponse> =>
    jsonFetch<QuorumUnlockResponse>('/api/doc/quorum/unlock', {
      container_b64: params.container_b64,
      shares: params.shares ?? [],
    }),
  transfer: (params: {
    name: string
    content_b64: string
    mime?: string
    hops?: number
    noise_rate?: number
    intercept_ratio?: number
    eve_mode?: boolean
    seed?: number
  }): Promise<TransferResponse> => jsonFetch<TransferResponse>('/api/doc/transfer', params),
  peerSend: (params: {
    container_b64?: string
    name?: string
    content_b64?: string
    /** Remote laptop API base (cross-machine delivery). */
    peer_url?: string
    /** Recipient username on this server (local inbox delivery). */
    to_user?: string
    from_label?: string
  }): Promise<PeerSendResponse> => jsonFetch<PeerSendResponse>('/api/doc/send', params),
  inbox: (full = true): Promise<InboxListResponse> =>
    fetch(`${base()}/api/doc/inbox?full=${full}`, { headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`inbox requires login (HTTP ${r.status})`)
      return r.json()
    }),
  inboxVerify: (id: number): Promise<VerifyResponse> =>
    jsonFetch<VerifyResponse>('/api/doc/inbox/verify', { id }),
  inboxDelete: (id: number): Promise<{ deleted: number }> =>
    fetch(`${base()}/api/doc/inbox/${id}`, { method: 'DELETE' }).then((r) => {
      if (!r.ok) throw new Error(`delete failed (HTTP ${r.status})`)
      return r.json()
    }),
}

/** Base64 (standard alphabet, unpadded ok) ↔ Uint8Array helpers. */
export function bytesToB64(bytes: Uint8Array): string {
  let bin = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(bin)
}

export function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64)
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export const auditApi = {
  events: (limit = 100): Promise<AuditEventsResponse> =>
    fetch(`${base()}/api/audit/events?limit=${limit}`).then((r) => r.json()),
  root: (): Promise<{ root?: string; leaves: number }> =>
    fetch(`${base()}/api/audit/root`).then((r) => r.json()),
  proof: (seq: number): Promise<InclusionProof> =>
    fetch(`${base()}/api/audit/proof?seq=${seq}`).then((r) => {
      if (!r.ok) throw new Error(`no entry at seq ${seq}`)
      return r.json()
    }),
  verifyChain: (): Promise<ChainVerdict> =>
    fetch(`${base()}/api/audit/verify`).then((r) => r.json()),
}
