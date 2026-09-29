export interface SecurityAccounting {
  raw_bits: number
  eve_bits: number
  reconciliation_leakage: number
  min_entropy_bits: number
  output_bits: number
  epsilon: number | null
  finite_key_ok: boolean
}

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
  /** True only when the modeled entropy budget produced a key. */
  key_distilled: boolean
  threat_flagged: boolean
  /** Three-way classification: secure / degraded / under_attack. */
  channel_class?: string
  first_divergence: number | null
  derived_secret?: string
  hmac_tag?: string
  hmac_valid?: boolean
  /** Leftover-hash-lemma paperwork when the key was distilled. */
  security?: SecurityAccounting
  /** Classical software-model CHSH diagnostic, not physical certification. */
  bell_test?: BellTestReport
  /** Chernoff–Hoeffding dossier from THIS run's actual measurements. */
  statistical_bounds?: BoundsReport
  note: string
}

export interface BellTestReport {
  /** Sampled CHSH S from the classical software model (not a physical experiment). */
  s: number
  sigma: number
  rounds: number
  certified: boolean
  margin_sigma: number
  visibility: number
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

// Per-tab sessions: the token lives in sessionStorage so two tabs in one
// browser can hold two DIFFERENT accounts. LocalStorage would share one
// identity across tabs and silently switch the first tab on a second login.
export function getAuthToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY)
}

export function getAuthUsername(): string | null {
  return sessionStorage.getItem(USER_KEY)
}

export function setAuthSession(token: string, username: string) {
  sessionStorage.setItem(TOKEN_KEY, token)
  sessionStorage.setItem(USER_KEY, username)
}

export function clearAuthSession() {
  sessionStorage.removeItem(TOKEN_KEY)
  sessionStorage.removeItem(USER_KEY)
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

/** Locate the API by same origin, server port manifest, then local fallback ports. */
export async function discoverApiBase(): Promise<string> {
  try {
    await healthCheck()
    return ''
  } catch {
    /* continue discovery */
  }

  try {
    const res = await fetch('/server-port.json', { cache: 'no-store' })
    if (res.ok) {
      const manifest = (await res.json()) as { actual_port?: number }
      if (manifest.actual_port) {
        const apiBase = `http://127.0.0.1:${manifest.actual_port}`
        const probe = await fetch(`${apiBase}/api/health`)
        if (probe.ok) return apiBase
      }
    }
  } catch {
    /* continue discovery */
  }

  for (let port = 8081; port <= 8090; port++) {
    try {
      const probe = await fetch(`http://127.0.0.1:${port}/api/health`)
      if (probe.ok) return `http://127.0.0.1:${port}`
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
  temporal?: TemporalBindingView | null
}

export interface TemporalBindingView {
  window: number
  unix_ms: number
  entropy_prefix: string
  chain_prefix: string
  tag_prefix: string
  valid_until_window: number
}

export interface VerificationReport {
  accepted: boolean
  verdict: 'acc1' | 'acc0' | 'rej'
  match_ratio: number
  mismatches: number
  total_positions: number
  /** False when rejection occurred before statistical evaluation. */
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

export interface ConfidenceInterval {
  n: number
  k: number
  p_hat: number
  lo_hoeffding: number
  hi_hoeffding: number
  hi_chernoff: number
  confidence: number
}

export interface ThresholdPoint {
  n: number
  threshold: number
  slack: number
}

export interface VerdictConfidence {
  n: number
  k: number
  threshold: number
  p_value: number
  rejection_confidence: number
  band: 'airtight' | 'decisive' | 'significant' | 'undersized'
}

export interface BoundsReport {
  interval: ConfidenceInterval
  curve: ThresholdPoint[]
  verdict: VerdictConfidence
  chernoff_gain: number
}

export interface RingMember {
  name: string
  channel_noise: number
  report: VerificationReport
  accepted: boolean
  transferable: boolean
}

export interface RingVerdict {
  required: number
  members_queried: number
  accepted_count: number
  transferable_count: number
  quorum_ok: boolean
  transfer_grade: boolean
  members: RingMember[]
  note: string
}

export const qdsApi = {
  setup: (qubitCount: number, lambda: number): Promise<QdsSetupResponse> =>
    jsonFetch<QdsSetupResponse>('/api/qds/setup', { qubit_count: qubitCount, lambda }),
  sign: (message: string, seed?: number): Promise<QdsSignResponse> =>
    jsonFetch<QdsSignResponse>('/api/qds/sign', { message, seed }),
  verify: (message: string, signatureHex: string, nonce: number): Promise<QdsOutcome> =>
    jsonFetch<QdsOutcome>('/api/qds/verify', { message, signature_hex: signatureHex, nonce }),
  attacks: (tamperFraction?: number): Promise<QdsOutcome[]> => {
    const query = tamperFraction !== undefined ? `?tamper_fraction=${tamperFraction}` : ''
    return fetch(`${base()}/api/qds/attacks${query}`).then((r) => r.json())
  },
  forgeryAnalysis: (): Promise<ForgeryAnalysis> =>
    fetch(`${base()}/api/qds/forgery-analysis`).then((r) => r.json()),
  bounds: (k: number, n: number, threshold = 0.15, noise = 0.02, delta = 0.01): Promise<BoundsReport> => {
    const query = new URLSearchParams({ k: String(k), n: String(n), threshold: String(threshold), noise: String(noise), delta: String(delta) })
    return fetch(`${base()}/api/stats/bounds?${query}`).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      return r.json()
    })
  },
  consensusRing: (opts?: {
    k?: number
    m?: number
    members?: string[]
    attackedMember?: number | null
    attackNoise?: number
    tolerance?: number
    seed?: number
  }): Promise<RingVerdict> =>
    jsonFetch<RingVerdict & { verdict: RingVerdict }>('/api/qds/consensus-ring', {
      k: opts?.k,
      m: opts?.m,
      members: opts?.members,
      attacked_member: opts?.attackedMember ?? null,
      attack_noise: opts?.attackNoise,
      tolerance: opts?.tolerance,
      seed: opts?.seed,
    }).then((response) => response.verdict),
  metrics: (trials?: number, seed?: number): Promise<MetricsReport> => {
    const params = new URLSearchParams()
    if (trials !== undefined) params.set('trials', String(trials))
    if (seed !== undefined) params.set('seed', String(seed))
    const query = params.toString() ? `?${params.toString()}` : ''
    return fetch(`${base()}/api/qds/metrics${query}`).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      return r.json()
    })
  },
  events: (): Promise<{ events: QdsEventRow[] }> =>
    fetch(`${base()}/api/qds/events`).then((r) => r.json()),
}

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

export interface SessionInfo {
  has_key: boolean
  key_commitment?: string
  key_preview?: string
  remembered_keys: number
  quorum: [number, number] | null
}

export interface SealResponse {
  container_b64: string
  name: string
  size: number
  sha256: string
  key_commitment: string
  quorum: [number, number] | null
  officer_commitments: string[]
  key_source: string
  qds_signature: boolean
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

export function isPassed(outcome: VerificationOutcome): boolean {
  return outcome.format_ok && outcome.authentic && outcome.integrity && outcome.key_match
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
  held_share?: { x: number; commitment: string; from: string } | null
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
  ring?: RingSpec | null
}

export interface RingSpec {
  k: number
  m: number
  members: string[]
  attested_by: string[]
}

export interface InboxListResponse { items: InboxItem[]; total: number }

export interface PeerSendResponse {
  delivered: boolean
  destination: string
  peer_item_id: number | null
  peer_note: string | null
  sha256: string
  outbox_id: number
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
  hash_v?: number
}

export interface AuditEventsResponse { entries: AuditEntry[]; root?: string; total: number }
export interface InclusionProof { seq: number; leaf_hash: string; siblings: string[]; root: string }
export interface ChainVerdict { ok: boolean; broken_at: number | null; root?: string | null; detail: string }
export interface AuditExportResponse {
  format_version: number
  entries: AuditEntry[]
  proofs: InclusionProof[]
  root: string | null
  total: number
  chain: ChainVerdict
}

export interface AttackResponse {
  mode: string
  description: string
  container_b64: string
  target_sha256: string
  expected_outcome: string
  audit_seq: number
  audit_warning?: string
}

export type AttackMode = 'tamper_bytes' | 'swap_meta' | 'reseal' | 'truncate'
export interface OutboxItem {
  id: number
  sent_at: string
  to_peer: string
  via: string
  meta: { name: string; size: number; mime: string; sha256: string; sealed_at: string }
  container_b64: string
  delivered: boolean
  claim_code?: string | null
  summary: string
}
export interface OutboxListResponse { items: OutboxItem[]; total: number }

export interface QdsKeyResponse {
  key_commitment: string
  session_commitment: string
  session_id: number
  nonce: number
  n_pulses: number
  conclusive_bits: number
  mismatch_rate: number
  provenance: string
  audit_seq: number
  audit_warning?: string
}
export interface QdsCheckReport {
  accepted: boolean
  verdict: string
  match_ratio: number
  mismatches: number
  total_positions: number
  evaluated?: boolean
  reason: string
}
export interface OpenResponse {
  content_b64: string
  name: string
  mime: string
  size: number
  sha256: string
  outcome: VerificationOutcome
  qds_check: QdsCheckReport | null
  unlocked_via: string
  audit_seq: number
  audit_warning?: string
}
export interface WireProof {
  doc_name: string
  doc_sha256: string
  doc_size: number
  wire_bytes: number
  ciphertext_sample_hex: string
  ciphertext_entropy: number
  encryption_scheme: string
  key_commitment: string
  qds_signature_attached: boolean
  transport: string
  verdict: string
}
export interface TheaterStep {
  step: number
  title: string
  actor: string
  detail: string
  level: string
  evidence: Record<string, unknown>
}
export interface TheaterResponse {
  theater_id: number
  mode: string
  victim: string
  steps: TheaterStep[]
  victim_verdict: VerificationOutcome
  qds_verdict: QdsCheckReport | null
  rejected: boolean
  wire: WireProof
  audit_seq: number
  audit_warning?: string
}
export interface RelayDepositResponse {
  claim_code: string
  relay_note: string
  expires_note: string
  audit_seq: number
  audit_warning?: string
}
export interface RelayClaimResponse {
  accepted: boolean
  item_id: number | null
  meta: { name: string; size: number; mime: string; sha256: string; sealed_at: string } | null
  from_peer: string | null
  note: string
  audit_seq: number
  audit_warning?: string
}
export interface RelayDepositInfo {
  code: string
  from: string
  name: string
  size: number
  sha256: string
  deposited_at: string
}

export const docApi = {
  session: (): Promise<SessionInfo> =>
    fetch(`${base()}/api/doc/session`, { headers: authHeaders() }).then((r) => r.json()),
  qdsKey: (): Promise<QdsKeyResponse> => jsonFetch<QdsKeyResponse>('/api/doc/qds/key', {}),
  open: (params: { container_b64?: string; inbox_id?: number; outbox_id?: number }): Promise<OpenResponse> =>
    jsonFetch<OpenResponse>('/api/doc/open', params),
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
    fetch(`${base()}/api/doc/quorum/pledge`, { method: 'POST', headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`pledge failed (HTTP ${r.status})`)
      return r.json()
    }),
  attack: (params: { container_b64: string; mode: AttackMode; from_label?: string }): Promise<AttackResponse> =>
    jsonFetch<AttackResponse>('/api/doc/attack', params),
  quorumUnlock: (params: { container_b64?: string; shares?: { x: number; y: number[] }[] }): Promise<QuorumUnlockResponse> =>
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
    peer_url?: string
    to_user?: string
    from_label?: string
  }): Promise<PeerSendResponse> => jsonFetch<PeerSendResponse>('/api/doc/send', params),
  inbox: (full = true): Promise<InboxListResponse> =>
    fetch(`${base()}/api/doc/inbox?full=${full}`, { headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`inbox requires login (HTTP ${r.status})`)
      return r.json()
    }),
  inboxVerify: (id: number): Promise<VerifyResponse> => jsonFetch<VerifyResponse>('/api/doc/inbox/verify', { id }),
  inboxDelete: (id: number): Promise<{ deleted: number }> =>
    fetch(`${base()}/api/doc/inbox/${id}`, { method: 'DELETE', headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`delete failed (HTTP ${r.status})`)
      return r.json()
    }),
  outbox: (): Promise<OutboxListResponse> =>
    fetch(`${base()}/api/doc/outbox`, { headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`outbox requires login (HTTP ${r.status})`)
      return r.json()
    }),
  ringSend: (params: { container_b64: string; members: string[]; k?: number }): Promise<{ accepted: string[]; missing: string[]; k: number; m: number; note: string }> =>
    jsonFetch('/api/doc/ring/send', params),
  ringAttest: (member: string, inboxId: number): Promise<{ attested: boolean; verdict: string | null; reason: string | null; attested_count: number; k: number; m: number; quorum_ok: boolean; note: string }> =>
    jsonFetch('/api/doc/ring/attest', { member, inbox_id: inboxId }),
  outboxDelete: (id: number): Promise<{ deleted: number }> =>
    fetch(`${base()}/api/doc/outbox/${id}`, { method: 'DELETE', headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`delete failed (HTTP ${r.status})`)
      return r.json()
    }),
  wireProof: (ref: { inbox_id?: number; outbox_id?: number }): Promise<WireProof> => {
    const query = new URLSearchParams()
    if (ref.inbox_id !== undefined) query.set('inbox_id', String(ref.inbox_id))
    if (ref.outbox_id !== undefined) query.set('outbox_id', String(ref.outbox_id))
    return fetch(`${base()}/api/doc/wire-proof?${query.toString()}`, { headers: authHeaders() }).then((r) => {
      if (!r.ok) throw new Error(`wire proof failed (HTTP ${r.status})`)
      return r.json()
    })
  },
  attackTheater: (params: { container_b64: string; mode?: AttackMode; victim?: string; attacker?: string }): Promise<TheaterResponse> =>
    jsonFetch<TheaterResponse>('/api/doc/attack-theater', params),
  relayDeposit: (params: { container_b64: string; to_user: string; from_label?: string }): Promise<RelayDepositResponse> =>
    jsonFetch<RelayDepositResponse>('/api/doc/relay/deposit', params),
  relayClaim: (claim_code: string): Promise<RelayClaimResponse> =>
    jsonFetch<RelayClaimResponse>('/api/doc/relay/claim', { claim_code }),
  relayInbox: (): Promise<{ deposits: RelayDepositInfo[]; total: number }> =>
    fetch(`${base()}/api/doc/relay/inbox`, { headers: authHeaders() }).then((r) => r.json()),
}

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
  events: (limit = 100): Promise<AuditEventsResponse> => fetch(`${base()}/api/audit/events?limit=${limit}`).then((r) => r.json()),
  portableExport: async (): Promise<AuditExportResponse> => {
    const response = await fetch(`${base()}/api/audit/export`)
    if (!response.ok) {
      const body = await response.json().catch(() => null)
      throw new Error(body?.error ?? `audit export failed (HTTP ${response.status})`)
    }
    return response.json() as Promise<AuditExportResponse>
  },
  root: (): Promise<{ root?: string; leaves: number }> => fetch(`${base()}/api/audit/root`).then((r) => r.json()),
  proof: (seq: number): Promise<InclusionProof> => fetch(`${base()}/api/audit/proof?seq=${seq}`).then((r) => {
    if (!r.ok) throw new Error(`no entry at seq ${seq}`)
    return r.json()
  }),
  verifyChain: (): Promise<ChainVerdict> => fetch(`${base()}/api/audit/verify`).then((r) => r.json()),
}

export type BlindTreatment = 'clear' | 'environmental_noise' | 'interception'
export interface BlindChallengeMeasurement {
  run_id: number
  key_length: number
  qber: number
  dynamic_threshold: number
  matching_bases_count: number
  mismatches: number
  channel_class: string
  bell_test?: BellTestReport | null
}
export interface BlindChallengeStartResponse { challenge_id: string; commitment: string; measurement: BlindChallengeMeasurement }
export interface BlindChallengeRevealResponse {
  correct: boolean
  guess: BlindTreatment
  treatment: BlindTreatment
  explanation: string
  commitment: string
  commitment_payload: string
  noise_rate: number
  intercept_ratio: number
  seed: number
  channel_class: string
  measurement: BlindChallengeMeasurement
}
export const blindChallengeApi = {
  start: async (): Promise<BlindChallengeStartResponse> => {
    const response = await fetch(`${base()}/api/blind-challenge/start`, { method: 'POST' })
    if (!response.ok) {
      const body = await response.json().catch(() => null)
      throw new Error(body?.error ?? `challenge failed (HTTP ${response.status})`)
    }
    return response.json() as Promise<BlindChallengeStartResponse>
  },
  reveal: (challenge_id: string, guess: BlindTreatment): Promise<BlindChallengeRevealResponse> =>
    jsonFetch<BlindChallengeRevealResponse>('/api/blind-challenge/reveal', { challenge_id, guess }),
}
