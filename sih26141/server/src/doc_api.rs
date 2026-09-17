//! Document-sealing, peer-to-peer transfer, threat-attack, and audit-log
//! API handlers, scoped to per-user workspaces.
//!
//! **Accounts.** Register/login issues a bearer token (`auth.rs`). Every
//! handler accepts `OptionalAuth`: the workspace name is the username for
//! logged-in users and `shared` for anonymous use, so the classic
//! single-workspace demo keeps working while multiple users get isolated
//! session keys, quorum splits, inboxes, and last-sealed documents. P2P
//! delivery is addressed by username: `POST /api/doc/send` with
//! `to_user: "bob"` drops the container into Bob's inbox on this server.
//!
//! **Three-laptop demo.** Laptop A (alice) sends a sealed document to Bob;
//! laptop B (bob) receives it; laptop C (mallory) runs `POST /api/doc/attack`
//! against a captured container — every attack mode is rejected by Bob's
//! side with a precise failure reason, and the attempt lands in the Merkle
//! audit ledger as an `attack` event.
//!
//! Endpoints:
//!   POST /api/auth/register      — create an account
//!   POST /api/auth/login         — get a bearer token
//!   POST /api/auth/logout        — drop the token
//!   GET  /api/auth/me            — who am I
//!   GET  /api/auth/users         — registered usernames (for address books)
//!   GET  /api/doc/session        — this user's key state
//!   POST /api/doc/seal           — seal a file (base64 in, container out)
//!   POST /api/doc/verify         — verify a container against the session key
//!   GET  /api/doc/quorum         — officer share view (for the unlock demo)
//!   POST /api/doc/quorum/unlock  — combine k officer shares and verify
//!   POST /api/doc/transfer       — sealed in-transit transfer over the simulated route
//!   POST /api/doc/send           — REAL transfer: seal + POST to a peer URL
//!                                  (addressee on this server: `to_user`)
//!   POST /api/doc/receive        — accept an inbound container into the inbox
//!   GET  /api/doc/inbox          — list the inbox (?full=false for metadata)
//!   POST /api/doc/inbox/verify   — verify one inbox container
//!   DELETE /api/doc/inbox/{id}   — remove one inbox item
//!   POST /api/doc/attack         — Mallory's tamper/substitute/resend modes
//!                                  (used to DEMONSTRATE rejection)
//!   GET  /api/doc/events         — SSE: live transfer-log events
//!   GET  /api/audit/*            — shared Merkle audit ledger (events/root/proof/verify)
//!
//! **Key commitment (single definition):** SHA-256 of the *canonical* key
//! (final byte reduced into GF(251)), via `sealing::key_commitment_for`.

use crate::auth::{AuthState, AuthUser, OptionalAuth};
use crate::qds_state::chrono_now;
use crate::{bad_request, internal_error, random_seed};
use audit::{AuditEntry, AuditLog, ChainVerdict, InclusionProof};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use quantum::relay::{simulate_relay_transmission, RelayRoute};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sealing::{parse_container, seal_document, verify_document, AuditRef, KeyShare, QuorumSpec};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

/// Upload cap for seal/send/receive/transfer (the "5 MB" demo scope).
pub const MAX_FILE_BYTES: usize = 5 * 1024 * 1024;
/// Body cap: base64 files are 1.33× raw size plus container overhead.
const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;

/// Workspace for anonymous calls without a token.
const SHARED_WORKSPACE: &str = "shared";

// ---------------------------------------------------------------------------
// Per-user workspace
// ---------------------------------------------------------------------------

/// Mutable per-user state: session key, quorum, inbox, outbox, last seal.
#[derive(Default)]
pub struct Workspace {
    pub session: SealSession,
    /// Last sealed container (so /verify and quorum unlock can be demoed
    /// without re-uploading).
    pub last_sealed: Option<sealing::QsigDocument>,
    /// Documents RECEIVED from peers, oldest first.
    pub inbox: Vec<InboxItem>,
    pub inbox_counter: u64,
    /// Documents SENT by this user (the sender's record of outgoing
    /// transfers — kept out of the inbox so receiver and sender never
    /// confuse their copies).
    pub outbox: Vec<OutboxItem>,
    pub outbox_counter: u64,
    /// An officer share placed in THIS user's custody by a sealant
    /// (`POST /api/doc/quorum/distribute`). The y-bytes never leave the
    /// server: the holder pledges by name, the server moves the pointer.
    pub custody: Option<Custody>,
    /// Shares pledged toward THIS user's quorum unlock (the sealant side).
    pub pending_pledges: Vec<sealing::KeyShare>,
}

/// One officer share held in a user's custody.
#[derive(Debug, Clone, Serialize)]
pub struct Custody {
    pub x: u8,
    /// Not serialized to the holder's UI — only the commitment is public.
    #[serde(skip_serializing)]
    pub y: Vec<u8>,
    pub commitment: String,
    /// Username of the sealant who distributed it (pledges go back there).
    pub from: String,
}

#[derive(Default)]
pub struct SealSession {
    pub secret_hex: Option<String>,
    pub secret_history: Vec<String>,
    /// Where the current key came from: "six-state-qds" | "qkd-legacy".
    pub secret_source: Option<String>,
    pub quorum_threshold: Option<u8>,
    pub quorum_shares: Option<u8>,
    pub officer_shares: Vec<sealing::KeyShare>,
}

impl SealSession {
    pub fn set_secret(&mut self, hex_key: String) {
        if self.secret_hex.as_deref() != Some(hex_key.as_str()) {
            if let Some(old) = self.secret_hex.take() {
                self.secret_history.push(old);
                if self.secret_history.len() > 8 {
                    self.secret_history.remove(0);
                }
            }
            self.secret_hex = Some(hex_key);
        }
    }

    pub fn known_secrets(&self) -> Vec<String> {
        let mut all = self.secret_hex.clone().map(|s| vec![s]).unwrap_or_default();
        all.extend(self.secret_history.iter().cloned());
        all
    }
}

/// One document waiting in a user's inbox.
#[derive(Debug, Clone, Serialize)]
pub struct InboxItem {
    pub id: u64,
    pub received_at: String,
    pub from_peer: String,
    pub meta: sealing::DocumentMeta,
    pub container_b64: String,
    pub verified: Option<bool>,
    pub note: Option<String>,
}

/// One document this user SENT (outbox record). `container_b64` is kept so
/// the sender can re-download or re-send their own sealed copy.
#[derive(Debug, Clone, Serialize)]
pub struct OutboxItem {
    pub id: u64,
    pub sent_at: String,
    pub to_peer: String,
    /// "local" (same-server account) | "laptop" (remote URL) | "relay"
    /// (cross-LAN claim-code pickup).
    pub via: String,
    pub meta: sealing::DocumentMeta,
    pub container_b64: String,
    /// Whether delivery was accepted by the destination.
    pub delivered: bool,
    /// Claim code for relay-mode deliveries (peers redeem it to pick up).
    pub claim_code: Option<String>,
    pub summary: String,
}

type AppError = (StatusCode, Json<serde_json::Value>);
type MainState = crate::AppState;

// ---------------------------------------------------------------------------
// Live transfer event stream (SSE)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DocEvent {
    TransferLog {
        transfer_id: u64,
        stage: String, // "qkd" | "sift" | "amplify" | "hmac" | "transmit" | "verify" | "attack"
        node: String,  // "Alice" | "Relay 1" | "Bob" | "peer" | "mallory"
        detail: String,
        level: String, // "info" | "warn" | "error" | "ok"
    },
    TransferDone {
        transfer_id: u64,
        accepted: bool,
        summary: String,
    },
}

/// A container parked on the public relay waiting for its recipient to
/// claim it (cross-LAN transfer: different networks, no port forwarding).
#[derive(Debug, Clone, Serialize)]
pub struct RelayDeposit {
    pub code: String,
    pub deposited_at: String,
    pub from_peer: String,
    pub meta: sealing::DocumentMeta,
    pub container_b64: String,
    /// Set when a peer redeemed the code; the deposit is dropped after.
    pub claimed_by: Option<String>,
}

/// Shared document-layer state: one audit ledger, per-user workspaces.
pub struct DocStateHolder {
    /// Workspace name -> state. Created on demand (login, run, receive…).
    /// Workspaces live for the whole process, so each mutex is `Box::leak`ed
    /// into a `&'static` — that lets `workspace()` hand out a MutexGuard
    /// without borrowing the map lock or juggling Arc clones.
    pub workspaces: Mutex<HashMap<String, &'static Mutex<Workspace>>>,
    pub auth: Arc<AuthState>,
    /// Shared Merkle audit ledger (every user's events chain together).
    pub audit: Mutex<AuditLog>,
    pub audit_path: PathBuf,
    pub doc_events_tx: tokio::sync::broadcast::Sender<Arc<DocEvent>>,
    pub transfer_counter: AtomicU64,
    /// Cross-LAN claim-code mailbox (relay deposits, see RelayDeposit).
    pub relay: Mutex<HashMap<String, RelayDeposit>>,
    /// Monotonic counter seeding fresh six-state QDS key-derivation sessions.
    pub qds_key_counter: AtomicU64,
    /// The developer token enabling `/api/audit/clear` (DEVELOPER_TOKEN env;
    /// None = clearing is permanently disabled for this process).
    pub dev_token: Option<String>,
}

impl DocStateHolder {
    /// Startup path: adopt a log reloaded from disk (`AuditLog::load_jsonl`).
    pub fn from_log(log: AuditLog, audit_path: PathBuf, auth: Arc<AuthState>, dev_token: Option<String>) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1024);
        Self {
            workspaces: Mutex::new(HashMap::new()),
            auth,
            audit: Mutex::new(log),
            audit_path,
            doc_events_tx: tx,
            transfer_counter: AtomicU64::new(1),
            relay: Mutex::new(HashMap::new()),
            qds_key_counter: AtomicU64::new(1),
            dev_token,
        }
    }

    /// Lock (creating on demand) the named user's workspace.
    pub fn workspace(&self, name: &str) -> MutexGuard<'_, Workspace> {
        let mutex: &'static Mutex<Workspace> = {
            let mut map = self.workspaces.lock().expect("workspaces lock poisoned");
            *map
                .entry(name.to_string())
                .or_insert_with(|| Box::leak(Box::new(Mutex::new(Workspace::default()))))
        };
        mutex.lock().expect("workspace lock poisoned")
    }

    /// Lock an EXISTING workspace without creating one (peer delivery — a
    /// recipient must have logged in at least once to be addressable).
    pub fn try_workspace(&self, name: &str) -> Option<MutexGuard<'_, Workspace>> {
        let mutex: &'static Mutex<Workspace> = {
            let map = self.workspaces.lock().expect("workspaces lock poisoned");
            *map.get(name)?
        };
        Some(mutex.lock().expect("workspace lock poisoned"))
    }

    /// Append to the shared Merkle audit log and persist as JSONL. Returns
    /// a warning string when persistence failed (the in-memory chain stays
    /// contiguous for this process run).
    pub fn audit_append(
        &self,
        user: &str,
        kind: &str,
        label: &str,
        accepted: bool,
        detail: &str,
        payload_hash: &str,
    ) -> (AuditEntry, Option<String>) {
        let entry = {
            let mut log = self.audit.lock().expect("audit lock poisoned");
            log.append(
                kind,
                &format!("{label}:{user}"),
                accepted,
                detail,
                payload_hash,
                &chrono_now(),
            )
        };
        let warn = match AuditLog::append_persist(&self.audit_path, &entry) {
            Ok(_) => None,
            Err(e) => Some(format!("audit persistence failed: {e}")),
        };
        if let Some(w) = &warn {
            let _ = self.doc_events_tx.send(Arc::new(DocEvent::TransferLog {
                transfer_id: 0,
                stage: "audit".into(),
                node: "ledger".into(),
                detail: w.clone(),
                level: "warn".into(),
            }));
        }
        (entry, warn)
    }
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub ok: bool,
    pub token: Option<String>,
    pub username: Option<String>,
    pub error: Option<String>,
}

async fn auth_register(
    State(state): State<Arc<MainState>>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    match state.doc.auth.register(&req.username, &req.password, &chrono_now()) {
        Ok(()) => {
            state.doc.audit_append(
                req.username.trim(),
                "auth",
                "register",
                true,
                "account created",
                "",
            );
            Ok(Json(AuthResponse {
                ok: true,
                token: None,
                username: Some(req.username.trim().to_string()),
                error: None,
            }))
        }
        Err(e) => Err(bad_request(e)),
    }
}

async fn auth_login(
    State(state): State<Arc<MainState>>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    match state.doc.auth.login(&req.username, &req.password) {
        Ok(token) => {
            let username = req.username.trim().to_string();
            // Logging in creates the user's workspace so peers can
            // address them immediately.
            drop(state.doc.workspace(&username));
            state
                .doc
                .audit_append(&username, "auth", "login", true, "session opened", "");
            Ok(Json(AuthResponse { ok: true, token: Some(token), username: Some(username), error: None }))
        }
        Err(e) => Err(bad_request(e)),
    }
}

async fn auth_logout(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    // The extractor validated the caller; drop the presented token itself.
    if let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        state.doc.auth.logout(token);
    }
    state.doc.audit_append(&user.0, "auth", "logout", true, "session closed", "");
    Json(serde_json::json!({ "ok": true }))
}

async fn auth_me(user: AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "username": user.0 }))
}

async fn auth_users(State(state): State<Arc<MainState>>) -> Json<serde_json::Value> {
    let names = state
        .doc
        .auth
        .registered_users();
    Json(serde_json::json!({ "users": names }))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn mime_for(name: &str, explicit: Option<String>) -> String {
    if let Some(m) = explicit {
        return m;
    }
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" | "md" | "log" => "text/plain",
        "json" => "application/json",
        "csv" => "text/csv",
        "zip" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Record a distilled secret as a user's session key.
///
/// `source` records where the key came from:
///   * "qds" — a six-state QDS key-generation session (`/api/doc/qds/key`,
///     the document layer's primary path);
///   * "qkd-legacy" — the raw QKD demo run (`/api/run`) distilled a secret.
pub(crate) fn capture_session_secret(state: &MainState, user: &str, secret_hex: &str, source: &str) {
    {
        let mut ws = state.doc.workspace(user);
        ws.session.set_secret(secret_hex.to_string());
        ws.session.secret_source = Some(source.to_string());
    }
    if source == "qds" {
        return; // the QDS key endpoint writes its own richer audit entry
    }
    state.doc.audit_append(
        user,
        "keygen",
        "qkd-legacy",
        true,
        "session key distilled from the QKD demo run (legacy path — prefer the six-state QDS key endpoint)",
        "",
    );
}

/// Commitment for a session key under the single canonical definition.
fn commitment_for(secret_hex: &str) -> Option<String> {
    let bytes = hex::decode(secret_hex).ok()?;
    Some(sealing::key_commitment_for(&sealing::canonicalize_key(&bytes)))
}

/// Session-key info for the UI.
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub has_key: bool,
    pub key_commitment: Option<String>,
    pub key_preview: Option<String>,
    pub remembered_keys: usize,
    pub quorum: Option<(u8, u8)>,
}

async fn session_info(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
) -> Json<SessionInfo> {
    let ws = state.doc.workspace(&user.0.unwrap_or_else(|| SHARED_WORKSPACE.into()));
    let commitment = ws.session.secret_hex.as_ref().and_then(|k| commitment_for(k));
    let preview = ws
        .session
        .secret_hex
        .as_ref()
        .map(|k| format!("{}…", &k[..k.len().min(12)]));
    Json(SessionInfo {
        has_key: ws.session.secret_hex.is_some(),
        key_commitment: commitment,
        key_preview: preview,
        remembered_keys: ws.session.known_secrets().len(),
        quorum: ws.session.quorum_threshold.zip(ws.session.quorum_shares).map(|(t, m)| (t, m)),
    })
}

// ---------------------------------------------------------------------------
// Seal + verify
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SealRequest {
    /// File name (with extension) for metadata.
    name: String,
    /// File bytes, base64-encoded (preferred).
    #[serde(default)]
    content_b64: Option<String>,
    /// Legacy wire format: raw bytes as a JSON number array.
    #[serde(default)]
    content: Option<Vec<u8>>,
    mime: Option<String>,
    /// Use the quorum split (feature 7) when sealing.
    use_quorum: Option<bool>,
    /// Quorum parameters (default 3 of 5).
    quorum_threshold: Option<u8>,
    quorum_shares: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct SealResponse {
    /// The .qsig container as base64 (wire format used by P2P send/receive).
    container_b64: String,
    name: String,
    size: usize,
    sha256: String,
    key_commitment: String,
    quorum: Option<(u8, u8)>,
    officer_commitments: Vec<String>,
    /// Provenance of the sealing key ("six-state-qds" | "qkd-legacy").
    key_source: String,
    /// Whether the teleport-QDS signature was attached and verified.
    qds_signature: bool,
    audit_seq: u64,
    audit_root: Option<String>,
    audit_warning: Option<String>,
}

async fn doc_seal(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<SealRequest>,
) -> Result<Json<SealResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| SHARED_WORKSPACE.into());
    let content = if let Some(b64) = req.content_b64.as_ref().filter(|s| !s.is_empty()) {
        b64_decode(b64).ok_or_else(|| bad_request("content_b64 is not valid base64".into()))?
    } else {
        req.content.clone().unwrap_or_default()
    };
    if req.name.is_empty() || req.name.len() > 256 {
        return Err(bad_request("name must be 1..256 chars".into()));
    }
    if content.is_empty() {
        return Err(bad_request("content must not be empty".into()));
    }
    if content.len() > MAX_FILE_BYTES {
        return Err(bad_request(format!(
            "content must be at most {} bytes (demo scope)",
            MAX_FILE_BYTES
        )));
    }

    let use_quorum = req.use_quorum.unwrap_or(false);
    let threshold = req.quorum_threshold.unwrap_or(3);
    let shares_total = req.quorum_shares.unwrap_or(5);

    let mut ws = state.doc.workspace(&username);
    let (secret_hex, key_source) = {
        let s = &ws.session;
        (
            s.secret_hex.clone(),
            s.secret_source.clone().unwrap_or_else(|| "qkd-legacy".into()),
        )
    };
    let secret_hex = secret_hex.ok_or_else(|| {
        bad_request(
            "no session key yet — click “Generate QDS key” (POST /api/doc/qds/key) to derive the sealing key from a six-state QDS session"
                .into(),
        )
    })?;

    // Optional quorum split of the session key.
    let mut officer_commitments = Vec::new();
    let quorum_spec = if use_quorum {
        let mut rng = StdRng::from_entropy();
        let shares = sealing::split_secret(&secret_hex, threshold, shares_total, &mut rng)
            .map_err(bad_request)?;
        officer_commitments = shares.iter().map(|s| s.commitment.clone()).collect();
        ws.session.quorum_threshold = Some(threshold);
        ws.session.quorum_shares = Some(shares_total);
        ws.session.officer_shares = shares;
        ws.pending_pledges.clear(); // a fresh split invalidates old pledges
        QuorumSpec {
            threshold: Some(threshold),
            shares: Some(shares_total),
            officer_commitments: officer_commitments.clone(),
        }
    } else {
        QuorumSpec::default()
    };

    // Pin current audit coverage into the container.
    let (first_seq, last_seq, root) = {
        let log = state.doc.audit.lock().expect("audit lock poisoned");
        (
            log.entries().first().map(|e| e.seq),
            log.entries().last().map(|e| e.seq),
            log.root(),
        )
    };

    let mut rng = StdRng::from_entropy();
    let mut sealed = seal_document(
        &req.name,
        &mime_for(&req.name, req.mime),
        &content,
        &secret_hex,
        &chrono_now(),
        AuditRef { first_seq, last_seq, root },
        quorum_spec,
        &mut rng,
    )
    .map_err(bad_request)?;

    // Attach a genuine teleportation-QDS signature over the document hash
    // (the quantum-digital-signature half of the seal — see qds_keys.rs).
    // Opening the document later re-verifies this signature via Trent.
    let qds_sig_attached = {
        let holder = state.qds.lock().expect("qds lock poisoned");
        let mut trent = holder.inner.trent.lock().expect("trent lock poisoned");
        let signed = crate::qds_keys::sign_document_qds(&mut trent, &sealed.meta.sha256);
        let accepted = signed.accepted_at_signing;
        sealed.qds_sig = Some(sealing::QdsSigAttachment {
            correction_bits: signed.signature.correction_bits,
            nonce: signed.signature.nonce,
            key_commitment: signed.signature.key_commitment,
            scheme: "teleport-qds-v1".into(),
        });
        accepted
    };

    let sha256 = sealed.meta.sha256.clone();
    let container = sealing::container_bytes(&sealed);
    let container_b64 = b64_encode(&container);
    let key_commitment = sealed.key_commitment.clone();

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "seal",
        "doc-vault",
        true,
        &format!(
            "sealed '{}' ({} bytes, quorum: {}) — teleport-QDS signature {}",
            req.name,
            content.len(),
            if use_quorum { format!("{threshold}-of-{shares_total}") } else { "none".into() },
            if qds_sig_attached { "attached ✓" } else { "FAILED — document will not open" }
        ),
        &sha256,
    );

    ws.last_sealed = Some(sealed);
    drop(ws);

    Ok(Json(SealResponse {
        container_b64,
        name: req.name,
        size: content.len(),
        sha256,
        key_commitment,
        quorum: if use_quorum { Some((threshold, shares_total)) } else { None },
        officer_commitments,
        key_source: key_source.clone(),
        qds_signature: qds_sig_attached,
        audit_seq: entry.seq,
        audit_root: state.doc.audit.lock().expect("audit lock poisoned").root(),
        audit_warning,
    }))
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The .qsig container, base64-encoded (preferred).
    #[serde(default)]
    container_b64: Option<String>,
    /// Legacy wire format: raw bytes as a JSON number array.
    #[serde(default)]
    container: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    /// Full verification outcome for the current (or remembered) session key.
    pub outcome: sealing::VerificationOutcome,
    /// Which recorded key verified the container (None = none matched).
    pub verified_with_commitment: Option<String>,
    pub meta: Option<sealing::DocumentMeta>,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// Shared verification core: try every remembered key of the workspace.
fn verify_against_workspace(
    container: &[u8],
    secrets: &[String],
) -> Option<(sealing::VerificationOutcome, String)> {
    // Parse preserving the envelope distinction. v3 envelopes carry v=2 in
    // their placeholder doc — only `sealed_envelope` tells them apart.
    let parsed = sealing::parse_container_full(container).ok()?;
    if parsed.sealed_envelope {
        // Meta is sealed: unseal with each candidate key, then verify the
        // revealed document.
        let mut best: Option<(sealing::VerificationOutcome, String)> = None;
        for key in secrets {
            if let Ok(doc) = sealing::unseal_envelope(&parsed.doc, key) {
                if let Ok(outcome) = verify_document(&doc, key) {
                    let commit = commitment_for(key).unwrap_or_default();
                    if outcome.passed() {
                        return Some((outcome, commit));
                    }
                    if best.is_none() {
                        best = Some((outcome, commit));
                    }
                }
            }
        }
        return best;
    }
    let mut best: Option<(sealing::VerificationOutcome, String)> = None;
    for key in secrets {
        if let Ok(outcome) = verify_document(&parsed.doc, key) {
            if outcome.passed() {
                return Some((outcome, commitment_for(key).unwrap_or_default()));
            }
            if best.is_none() {
                best = Some((outcome, commitment_for(key).unwrap_or_default()));
            }
        }
    }
    best
}

/// Unseal a (possibly v3-envelope) container against a workspace's known
/// keys, returning the first success. For clear-JSON containers this is the
/// identity; for envelopes the metadata is recovered with the right key.
fn unseal_against_workspace(
    container: &[u8],
    secrets: &[String],
) -> Result<sealing::QsigDocument, String> {
    // Parse preserving the envelope distinction: a v3 envelope arrives as a
    // placeholder (v=2, empty meta) that MUST be unsealed before any
    // verification — branching on `doc.v` alone would misroute every
    // envelope to the legacy path.
    let parsed = sealing::parse_container_full(container).map_err(|e| e.to_string())?;
    if !parsed.sealed_envelope {
        let mut doc = parsed.doc;
        doc.key = sealing::canonicalize_key(
            &hex::decode(secrets.first().ok_or_else(|| "no session key on record".to_string())?)
                .unwrap_or_default(),
        );
        return Ok(doc);
    }
    let mut last = "no session key matches this container's key commitment".to_string();
    for key in secrets {
        match sealing::unseal_envelope(&parsed.doc, key) {
            Ok(doc) => return Ok(doc),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn doc_verify(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| SHARED_WORKSPACE.into());
    let container = if let Some(b64) = req.container_b64.as_ref().filter(|s| !s.is_empty()) {
        b64_decode(b64).ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?
    } else {
        req.container.clone().unwrap_or_default()
    };
    if container.is_empty() {
        return Err(bad_request("container must not be empty".into()));
    }
    let parsed = parse_container(&container).map_err(bad_request)?;

    let secrets = {
        let ws = state.doc.workspace(&username);
        ws.session.known_secrets()
    };
    if secrets.is_empty() {
        return Err(bad_request("no session key on record — cannot verify".into()));
    }

    let (outcome, commitment) = verify_against_workspace(&container, &secrets)
        .ok_or_else(|| internal_error("verification failed against all known keys".into()))?;
    // Recover real metadata for v3 envelopes (empty placeholder until now).
    let real_meta = unseal_against_workspace(&container, &secrets)
        .map(|d| d.meta)
        .unwrap_or_else(|_| parsed.meta.clone());
    let passed = outcome.passed();
    let note = outcome.note.clone();

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "verify",
        "doc-vault",
        passed,
        &format!("verified '{}' — {}", real_meta.name, note),
        &real_meta.sha256,
    );

    Ok(Json(VerifyResponse {
        outcome,
        verified_with_commitment: Some(commitment),
        meta: Some(real_meta),
        audit_seq: entry.seq,
        audit_warning,
    }))
}

// ---------------------------------------------------------------------------
// Quorum unlock (feature 7)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct QuorumUnlockRequest {
    /// The .qsig container: base64 (preferred) or legacy byte array.
    container: Option<Vec<u8>>,
    #[serde(default)]
    container_b64: Option<String>,
    /// Officer shares presented for unlock (k of m required).
    shares: Vec<ShareInput>,
}

#[derive(Debug, Deserialize)]
pub struct ShareInput {
    pub x: u8,
    pub y: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct QuorumUnlockResponse {
    pub shares_presented: usize,
    pub threshold: u8,
    pub shares_total: u8,
    pub enough_shares: bool,
    pub outcome: Option<sealing::VerificationOutcome>,
    pub recognized_officers: Vec<u8>,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

async fn quorum_unlock(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<QuorumUnlockRequest>,
) -> Result<Json<QuorumUnlockResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| SHARED_WORKSPACE.into());
    let (threshold, total, stored_shares, pledged_shares) = {
        let ws = state.doc.workspace(&username);
        let pledged = ws.pending_pledges.clone();
        match (ws.session.quorum_threshold, ws.session.quorum_shares.clone(), &ws.session.officer_shares) {
            (Some(t), Some(m), s) if !s.is_empty() => (t, m, s.clone(), pledged),
            _ => {
                return Err(bad_request(
                    "no quorum split on record — seal a document with use_quorum first".into(),
                ))
            }
        }
    };

    // Cross-account mode: no shares in the request — unlock with the shares
    // PLEDGED by other user accounts (officers pledged from their logins).
    if req.shares.is_empty() {
        if pledged_shares.len() < threshold as usize {
            let (entry, audit_warning) = state.doc.audit_append(
                &username,
                "quorum",
                "unlock",
                false,
                &format!(
                    "pledged unlock REJECTED: {} of {} pledges received (threshold {threshold})",
                    pledged_shares.len(),
                    total
                ),
                "",
            );
            return Ok(Json(QuorumUnlockResponse {
                shares_presented: pledged_shares.len(),
                threshold,
                shares_total: total,
                enough_shares: false,
                outcome: None,
                recognized_officers: pledged_shares.iter().map(|s| s.x).collect(),
                audit_seq: entry.seq,
                audit_warning,
            }));
        }
        // Validate pledged shares against the sealant's officer commitments.
        let mut valid = Vec::new();
        for p in &pledged_shares {
            if let Some(st) = stored_shares.iter().find(|st| st.x == p.x) {
                if sealing::share_commitment(p.x, &p.y) == st.commitment {
                    valid.push(p.clone());
                }
            }
        }
        if valid.len() < threshold as usize {
            let (entry, audit_warning) = state.doc.audit_append(
                &username,
                "quorum",
                "unlock",
                false,
                &format!(
                    "pledged unlock REJECTED: only {} pledged shares validate against officer commitments",
                    valid.len()
                ),
                "",
            );
            return Ok(Json(QuorumUnlockResponse {
                shares_presented: pledged_shares.len(),
                threshold,
                shares_total: total,
                enough_shares: false,
                outcome: None,
                recognized_officers: valid.iter().map(|s| s.x).collect(),
                audit_seq: entry.seq,
                audit_warning,
            }));
        }
        let reconstructed = sealing::combine_shares(&valid).map_err(bad_request)?;
        // Resolve the container first — v3 envelopes must be unsealed with
        // the reconstructed key BEFORE verification (the placeholder doc has
        // empty meta, so its GCM AAD can never match).
        let (container_bytes, in_memory_doc): (Option<Vec<u8>>, Option<sealing::QsigDocument>) = {
            let ws = state.doc.workspace(&username);
            match (&req.container_b64, &req.container) {
                (Some(b64), _) if !b64.is_empty() => (
                    Some(b64_decode(b64).ok_or_else(|| {
                        bad_request("container_b64 is not valid base64".into())
                    })?),
                    None,
                ),
                (_, Some(c)) if !c.is_empty() => (Some(c.clone()), None),
                _ => match ws.last_sealed.clone() {
                    Some(doc) => (None, Some(doc)),
                    None => {
                        return Err(bad_request(
                            "no container supplied and none sealed yet".into(),
                        ))
                    }
                },
            }
        };
        let parsed: sealing::QsigDocument = match in_memory_doc {
            // In-memory last-sealed doc is already unsealed.
            Some(doc) => doc,
            None => {
                let p = sealing::parse_container_full(
                    container_bytes.as_deref().unwrap_or(&[]),
                )
                .map_err(bad_request)?;
                if p.sealed_envelope {
                    sealing::unseal_envelope(&p.doc, &reconstructed).map_err(bad_request)?
                } else {
                    p.doc
                }
            }
        };
        let outcome = verify_document(&parsed, &reconstructed).map_err(bad_request)?;
        let passed = outcome.passed();
        let via = outcome.unlocked_via.clone();
        let (entry, audit_warning) = state.doc.audit_append(
            &username,
            "quorum",
            "unlock",
            passed,
            &format!(
                "CROSS-ACCOUNT unlock {}-of-{} via pledged officers {:?} — {}",
                threshold, total,
                valid.iter().map(|s| s.x).collect::<Vec<_>>(),
                via
            ),
            &parsed.meta.sha256,
        );
        // Pledges are consumed by a successful unlock.
        if passed {
            state.doc.workspace(&username).pending_pledges.clear();
        }
        return Ok(Json(QuorumUnlockResponse {
            shares_presented: valid.len(),
            threshold,
            shares_total: total,
            enough_shares: true,
            outcome: Some(outcome),
            recognized_officers: valid.iter().map(|s| s.x).collect(),
            audit_seq: entry.seq,
            audit_warning,
        }));
    }

    if req.shares.len() < threshold as usize {
        let (entry, audit_warning) = state.doc.audit_append(
            &username,
            "quorum",
            "unlock",
            false,
            &format!(
                "unlock REJECTED: {} of {} shares presented (threshold {threshold})",
                req.shares.len(),
                total
            ),
            "",
        );
        return Ok(Json(QuorumUnlockResponse {
            shares_presented: req.shares.len(),
            threshold,
            shares_total: total,
            enough_shares: false,
            outcome: None,
            recognized_officers: vec![],
            audit_seq: entry.seq,
            audit_warning,
        }));
    }

    // Validate presented shares against the stored officer shares via the
    // public commitment SHA-256(x ‖ y).
    let mut recognized = Vec::new();
    let mut valid = Vec::new();
    for s in &req.shares {
        let stored = stored_shares.iter().find(|st| st.x == s.x);
        if let Some(st) = stored {
            if sealing::share_commitment(s.x, &s.y) == st.commitment {
                recognized.push(s.x);
                valid.push(KeyShare { x: s.x, y: s.y.clone(), commitment: st.commitment.clone() });
            }
        }
    }

    if valid.len() < threshold as usize {
        let (entry, audit_warning) = state.doc.audit_append(
            &username,
            "quorum",
            "unlock",
            false,
            &format!(
                "unlock REJECTED: only {} recognized shares (need {threshold}) — forged or stale shares",
                valid.len()
            ),
            "",
        );
        return Ok(Json(QuorumUnlockResponse {
            shares_presented: req.shares.len(),
            threshold,
            shares_total: total,
            enough_shares: false,
            outcome: None,
            recognized_officers: recognized,
            audit_seq: entry.seq,
            audit_warning,
        }));
    }

    // Reconstruct the canonical key and verify.
    let reconstructed = sealing::combine_shares(&valid).map_err(bad_request)?;
    let container = if let Some(b64) = req.container_b64.as_ref().filter(|s| !s.is_empty()) {
        b64_decode(b64).ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?
    } else {
        req.container.clone().unwrap_or_default()
    };
    let parsed = if !container.is_empty() {
        parse_container(&container).map_err(bad_request)?
    } else {
        state
            .doc
            .workspace(&username)
            .last_sealed
            .clone()
            .ok_or_else(|| bad_request("no container supplied and none sealed yet".into()))?
    };
    let outcome = verify_document(&parsed, &reconstructed).map_err(bad_request)?;
    let passed = outcome.passed();
    let via = outcome.unlocked_via.clone();

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "quorum",
        "unlock",
        passed,
        &format!(
            "quorum unlock {}-of-{} with officers {recognized:?} — {}",
            threshold, total, via
        ),
        &parsed.meta.sha256,
    );

    Ok(Json(QuorumUnlockResponse {
        shares_presented: req.shares.len(),
        threshold,
        shares_total: total,
        enough_shares: true,
        outcome: Some(outcome),
        recognized_officers: recognized,
        audit_seq: entry.seq,
        audit_warning,
    }))
}

/// GET /api/doc/quorum — officer view: which share each officer holds
/// (the dashboard's officer toggles present exactly these share bytes).
#[derive(Debug, Serialize)]
pub struct OfficerShareView {
    pub x: u8,
    pub y: Vec<u8>,
    pub commitment: String,
}

/// GET /api/doc/quorum — quorum view for the CALLER:
/// * sealant: their officers + how many pledges have arrived;
/// * officer: which share they hold in custody (from whom);
/// * both: the k-of-m parameters.
async fn quorum_info(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
) -> Json<serde_json::Value> {
    let username = user.0.unwrap_or_else(|| SHARED_WORKSPACE.into());
    let ws = state.doc.workspace(&username);
    let officers: Vec<OfficerShareView> = ws
        .session
        .officer_shares
        .iter()
        .map(|s| OfficerShareView { x: s.x, y: s.y.clone(), commitment: s.commitment.clone() })
        .collect();
    let held = ws.custody.as_ref().map(|c| {
        serde_json::json!({
            "x": c.x,
            "commitment": c.commitment,
            "from": c.from,
        })
    });
    let pledges: Vec<String> = ws
        .pending_pledges
        .iter()
        .map(|_| "pledged".to_string())
        .collect();
    Json(serde_json::json!({
        "threshold": ws.session.quorum_threshold,
        "shares_total": ws.session.quorum_shares,
        "officers": officers,
        "held_share": held,
        "pledges_received": ws.pending_pledges.len(),
        "pledges": pledges,
    }))
}

// ---------------------------------------------------------------------------
// Cross-account multiparty threshold: distribute / pledge / unlock
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DistributeRequest {
    /// Exactly m usernames (officer i gets share i+1). Every user must have
    /// logged in at least once (workspace exists). The sealant may include
    /// themselves for one of the shares.
    users: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DistributeResponse {
    pub assignments: Vec<(String, u8)>, // username -> officer x
    pub threshold: u8,
    pub shares_total: u8,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// POST /api/doc/quorum/distribute — after a quorum seal, hand each officer
/// share to a NAMED USER ACCOUNT (cross-account multiparty authorization).
/// Each recipient's workspace stores its share in custody; the bytes stay
/// server-side, recipients pledge by name from their own login.
async fn quorum_distribute(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    Json(req): Json<DistributeRequest>,
) -> Result<Json<DistributeResponse>, AppError> {
    let username = &user.0;
    let (threshold, total, shares) = {
        let ws = state.doc.workspace(username);
        match (ws.session.quorum_threshold, ws.session.quorum_shares.clone(), &ws.session.officer_shares) {
            (Some(t), Some(m), s) if !s.is_empty() => (t, m, s.clone()),
            _ => {
                return Err(bad_request(
                    "no quorum split on record — seal a document with use_quorum first".into(),
                ))
            }
        }
    };
    let users: Vec<String> = req.users.iter().map(|u| u.trim().to_string()).collect();
    if users.len() != total as usize {
        return Err(bad_request(format!(
            "expected exactly {total} usernames (one per officer share), got {}",
            users.len()
        )));
    }
    if users.iter().any(|u| u.is_empty()) {
        return Err(bad_request("usernames must not be empty".into()));
    }
    // Recipients must exist as workspaces (logged in once) — otherwise the
    // share would silently vanish.
    for u in &users {
        if state.doc.try_workspace(u).is_none() {
            return Err(bad_request(format!(
                "user '{u}' has no workspace on this server — they must log in once first"
            )));
        }
    }
    let mut assignments = Vec::with_capacity(users.len());
    for (share, target) in shares.iter().zip(users.iter()) {
        let mut ws = state.doc.workspace(target);
        ws.custody = Some(Custody {
            x: share.x,
            y: share.y.clone(),
            commitment: share.commitment.clone(),
            from: username.clone(),
        });
        drop(ws);
        assignments.push((target.clone(), share.x));
    }
    // A fresh distribution invalidates pledges gathered for older splits.
    state.doc.workspace(username).pending_pledges.clear();

    let (entry, audit_warning) = state.doc.audit_append(
        username,
        "quorum",
        "distribute",
        true,
        &format!(
            "distributed {} officer shares to accounts {:?} ({}-of-{})",
            total,
            users,
            threshold, total
        ),
        "",
    );
    Ok(Json(DistributeResponse {
        assignments,
        threshold,
        shares_total: total,
        audit_seq: entry.seq,
        audit_warning,
    }))
}

#[derive(Debug, Serialize)]
pub struct PledgeResponse {
    pub pledged: bool,
    pub officer_x: u8,
    pub pledges_received: usize,
    pub threshold: u8,
    pub quorum_met: bool,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// POST /api/doc/quorum/pledge — the logged-in share holder commits their
/// officer share toward the sealant's unlock. The share bytes were placed
/// in their custody server-side; nothing secret crosses the wire here.
async fn quorum_pledge(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
) -> Result<Json<PledgeResponse>, AppError> {
    let holder = &user.0;
    let (share, sealant) = {
        let ws = state.doc.workspace(holder);
        match &ws.custody {
            Some(c) => (
                sealing::KeyShare { x: c.x, y: c.y.clone(), commitment: c.commitment.clone() },
                c.from.clone(),
            ),
            None => {
                return Err(bad_request(
                    "you hold no officer share — ask the sealant to distribute one to your account"
                        .into(),
                ))
            }
        }
    };
    let (received, threshold) = {
        let mut ws = state.doc.workspace(&sealant);
        if !ws.pending_pledges.iter().any(|p| p.x == share.x) {
            ws.pending_pledges.push(share.clone());
        }
        let t = ws.session.quorum_threshold.unwrap_or(0);
        (ws.pending_pledges.len(), t)
    };
    let met = threshold > 0 && received >= threshold as usize;
    let (entry, audit_warning) = state.doc.audit_append(
        holder,
        "quorum",
        "pledge",
        true,
        &format!(
            "officer {} pledged their share to '{sealant}' — {received}/{threshold} pledges{}",
            share.x,
            if met { " — QUORUM MET" } else { "" }
        ),
        "",
    );
    Ok(Json(PledgeResponse {
        pledged: true,
        officer_x: share.x,
        pledges_received: received,
        threshold,
        quorum_met: met,
        audit_seq: entry.seq,
        audit_warning,
    }))
}

// ---------------------------------------------------------------------------
// Real P2P transfer: laptop-to-laptop over HTTP, addressed by username
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PeerSendRequest {
    /// Either raw file bytes to seal now...
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    content_b64: Option<String>,
    /// ...or an already-sealed container (bytes or base64).
    #[serde(default)]
    container: Option<Vec<u8>>,
    #[serde(default)]
    container_b64: Option<String>,
    /// Destination peer server (another laptop), e.g. "http://192.168.1.42:8080".
    #[serde(default)]
    peer_url: Option<String>,
    /// Recipient USERNAME on the destination server (local delivery when
    /// peer_url is absent).
    #[serde(default)]
    to_user: Option<String>,
    /// Optional sender label (defaults to the authenticated username).
    #[serde(default)]
    from_label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PeerSendResponse {
    pub delivered: bool,
    pub destination: String,
    pub peer_item_id: Option<u64>,
    pub peer_note: Option<String>,
    pub sha256: String,
    /// The sender's outbox record id (their copy of the sent container).
    pub outbox_id: u64,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
    pub summary: String,
}

/// POST /api/doc/send — seal (if needed) and deliver the .qsig container.
/// Local delivery (`to_user`, no `peer_url`) drops it straight into the
/// recipient's inbox on THIS server. Remote delivery POSTs to
/// `{peer_url}/api/doc/receive` over the network.
async fn peer_send(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<PeerSendRequest>,
) -> Result<Json<PeerSendResponse>, AppError> {
    let username = user.0.clone().unwrap_or_else(|| "anonymous".into());
    let from_label = req.from_label.clone().unwrap_or_else(|| username.clone());

    // Resolve the container: existing bytes/base64, or seal fresh content.
    let (container, sha256, name) = if let Some(c) = req.container.as_ref().filter(|c| !c.is_empty()) {
        let parsed = parse_container(c).map_err(bad_request)?;
        (c.clone(), parsed.meta.sha256.clone(), parsed.meta.name.clone())
    } else if let Some(b64) = req.container_b64.as_ref().filter(|s| !s.is_empty()) {
        let bytes = b64_decode(b64).ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?;
        let parsed = parse_container(&bytes).map_err(bad_request)?;
        (bytes, parsed.meta.sha256.clone(), parsed.meta.name.clone())
    } else {
        let name = req.name.clone().unwrap_or_default();
        let content = if let Some(b64) = req.content_b64.as_ref().filter(|s| !s.is_empty()) {
            b64_decode(b64).ok_or_else(|| bad_request("content_b64 is not valid base64".into()))?
        } else {
            Vec::new()
        };
        if name.is_empty() || content.is_empty() {
            return Err(bad_request(
                "provide container/container_b64 or name+content_b64 to seal".into(),
            ));
        }
        if content.len() > MAX_FILE_BYTES {
            return Err(bad_request(format!(
                "content must be at most {} bytes (demo scope)",
                MAX_FILE_BYTES
            )));
        }
        let workspace_name = user.0.clone().unwrap_or_else(|| SHARED_WORKSPACE.into());
        let secret_hex = {
            let ws = state.doc.workspace(&workspace_name);
            ws.session.secret_hex.clone()
        }
        .ok_or_else(|| {
            bad_request("no session key yet — run a QKD exchange first (POST /api/run)".into())
        })?;
        let (first_seq, last_seq, root) = {
            let log = state.doc.audit.lock().expect("audit lock poisoned");
            (
                log.entries().first().map(|e| e.seq),
                log.entries().last().map(|e| e.seq),
                log.root(),
            )
        };
        let mut rng = StdRng::from_entropy();
        let mut sealed = seal_document(
            &name,
            &mime_for(&name, None),
            &content,
            &secret_hex,
            &chrono_now(),
            AuditRef { first_seq, last_seq, root },
            QuorumSpec::default(),
            &mut rng,
        )
        .map_err(bad_request)?;
        // Attach the teleport-QDS signature here too (same rule as the
        // vault seal — every sealed container is quantum-signed).
        {
            let holder = state.qds.lock().expect("qds lock poisoned");
            let mut trent = holder.inner.trent.lock().expect("trent lock poisoned");
            let signed = crate::qds_keys::sign_document_qds(&mut trent, &sealed.meta.sha256);
            sealed.qds_sig = Some(sealing::QdsSigAttachment {
                correction_bits: signed.signature.correction_bits,
                nonce: signed.signature.nonce,
                key_commitment: signed.signature.key_commitment,
                scheme: "teleport-qds-v1".into(),
            });
        }
        let sha = sealed.meta.sha256.clone();
        (sealing::container_bytes(&sealed), sha, name)
    };

    // ---- delivery ---------------------------------------------------------
    let (delivered, destination, peer_item_id, peer_note) = if let Some(peer_url) = req
        .peer_url
        .as_ref()
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
    {
        // Remote laptop: POST the container to the peer's receive endpoint.
        let url = format!("{peer_url}/api/doc/receive");
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "container_b64": b64_encode(&container),
            "from_label": from_label,
            // Addressed handoff: the recipient's /api/doc/receive resolves
            // its user from the bearer token OR this to_user field.
            "to_user": req.to_user,
        });
        let resp = client
            .post(&url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await;
        let reply = match resp {
            Ok(r) => r.json::<serde_json::Value>().await.unwrap_or_else(|_| {
                serde_json::json!({ "accepted": false, "error": "peer returned a non-JSON reply" })
            }),
            Err(e) => {
                serde_json::json!({ "accepted": false, "error": format!("peer unreachable: {e}") })
            }
        };
        let delivered = reply.get("accepted").and_then(|v| v.as_bool()).unwrap_or(false);
        let item_id = reply.get("item_id").and_then(|v| v.as_u64());
        let note = reply
            .get("note")
            .or_else(|| reply.get("error"))
            .and_then(|v| v.as_str().map(String::from));
        (delivered, peer_url.to_string(), item_id, note)
    } else if let Some(to_user) = req.to_user.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        // Local delivery to a named user's workspace on this server.
        let to_user = to_user.to_string();
        let item_id = deliver_local(&state, &to_user, &from_label, &container, None);
        match item_id {
            Some(id) => (
                true,
                format!("{to_user} (local)"),
                Some(id),
                Some(format!("accepted into {to_user}'s inbox")),
            ),
            None => (
                false,
                to_user.clone(),
                None,
                Some(format!(
                    "user '{to_user}' has no workspace on this server yet — they must log in once first"
                )),
            ),
        }
    } else {
        return Err(bad_request("provide to_user (local) or peer_url (remote)".into()));
    };

    // Sender's outbox record (the sender's copy lives in the OUTBOX,
    // never the inbox — receiver and sender copies are now distinct).
    let outbox_id = {
        let mut ws = state.doc.workspace(&username);
        let id = ws.outbox_counter;
        ws.outbox_counter += 1;
        ws.outbox.push(OutboxItem {
            id,
            sent_at: chrono_now(),
            to_peer: destination.clone(),
            via: if req.peer_url.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false) {
                "laptop".into()
            } else {
                "local".into()
            },
            meta: parse_container(&container)
                .map(|p| p.meta)
                .ok()
                .filter(|m| !m.name.is_empty())
                .unwrap_or_else(|| sealing::DocumentMeta {
                    name: name.clone(),
                    size: container.len(),
                    mime: "application/octet-stream".into(),
                    sha256: sha256.clone(),
                    sealed_at: chrono_now(),
                }),
            container_b64: b64_encode(&container),
            delivered,
            claim_code: None,
            summary: if delivered {
                format!("accepted by {destination}")
            } else {
                peer_note.clone().unwrap_or_else(|| "not accepted".into())
            },
        });
        id
    };

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "transfer",
        "p2p-send",
        delivered,
        &format!(
            "sent '{}' ({}) to {destination} — {}",
            name,
            format_bytes_short(container.len()),
            if delivered { "accepted" } else { "NOT accepted" }
        ),
        &sha256,
    );

    Ok(Json(PeerSendResponse {
        outbox_id,
        delivered,
        destination: destination.clone(),
        peer_item_id,
        peer_note: peer_note.clone(),
        sha256,
        audit_seq: entry.seq,
        audit_warning,
        summary: if delivered {
            format!("delivered to {destination} — container accepted into the inbox")
        } else {
            format!("NOT delivered — {}", peer_note.unwrap_or_else(|| "unknown error".into()))
        },
    }))
}

/// Insert a container into a local user's inbox. Fails (None) when the user
/// has no workspace yet.
fn deliver_local(
    state: &MainState,
    to_user: &str,
    from_label: &str,
    container: &[u8],
    known_bad: Option<&str>,
) -> Option<u64> {
    let parsed = parse_container(container).ok()?;
    let can_verify_now = {
        let mut can = false;
        if let Some(ws) = state.doc.try_workspace(to_user) {
            let secrets = ws.session.known_secrets();
            if verify_against_workspace(container, &secrets)
                .map(|(o, _)| o.passed())
                .unwrap_or(false)
            {
                can = true;
            }
        }
        can
    };
    // Real metadata when the recipient's key unseals the envelope; otherwise
    // a neutral placeholder that says so (meta stays hidden until verify).
    let meta = {
        let secrets = state
            .doc
            .try_workspace(to_user)
            .map(|ws| ws.session.known_secrets())
            .unwrap_or_default();
        unseal_against_workspace(&container, &secrets)
            .map(|d| d.meta)
            .unwrap_or_else(|_| sealing::DocumentMeta {
                name: "(sealed — verify to reveal)".into(),
                size: parsed.meta.size,
                mime: "application/octet-stream".into(),
                sha256: String::new(),
                sealed_at: chrono_now(),
            })
    };
    let mut ws = state.doc.try_workspace(to_user)?;
    let id = ws.inbox_counter;
    ws.inbox_counter += 1;
    // A pre-computed rejection (attack theater) is flagged IMMEDIATELY — the
    // victim sees "✗ FORGED" the moment the item lands, no verify click needed.
    let note = match known_bad {
        Some(reason) => format!("FORGED — {reason}"),
        None if can_verify_now => {
            "container accepted — session key present, ready to verify".to_string()
        }
        None => "container accepted — no matching session key yet".to_string(),
    };
    ws.inbox.push(InboxItem {
        id,
        received_at: chrono_now(),
        from_peer: from_label.to_string(),
        meta: meta.clone(),
        container_b64: b64_encode(container),
        verified: match known_bad {
            Some(_) => Some(false),
            None if can_verify_now => Some(true),
            None => None,
        },
        note: Some(note.clone()),
    });
    drop(ws);
    state.doc.audit_append(
        to_user,
        "transfer",
        "p2p-receive",
        true,
        &format!(
            "received '{}' ({} bytes) from {from_label} — {note}",
            meta.name,
            format_bytes_short(meta.size)
        ),
        &meta.sha256,
    );
    let _ = state.doc.doc_events_tx.send(Arc::new(DocEvent::TransferLog {
        transfer_id: 0,
        stage: "verify".into(),
        node: "peer".into(),
        detail: format!("inbound '{}' from {from_label}", meta.name),
        level: "info".into(),
    }));
    Some(id)
}

#[derive(Debug, Deserialize)]
pub struct PeerReceiveRequest {
    /// Sealed .qsig container bytes (base64).
    container_b64: String,
    /// Sender label for provenance.
    #[serde(default)]
    from_label: Option<String>,
    /// Recipient username for server-to-server handoff when the sender
    /// holds no token on the receiving laptop.
    #[serde(default)]
    to_user: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PeerReceiveResponse {
    pub accepted: bool,
    pub item_id: u64,
    pub meta: Option<sealing::DocumentMeta>,
    pub can_verify_now: bool,
    pub note: String,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// POST /api/doc/receive — the peer-side endpoint. Files the container into
/// the AUTHENTICATED user's inbox (the laptop owner). Verification happens
/// later via /api/doc/inbox/verify once this laptop holds the same key.
async fn peer_receive(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<PeerReceiveRequest>,
) -> Result<Json<PeerReceiveResponse>, AppError> {
    // The recipient is the authenticated laptop owner; server-to-server
    // handoff names the recipient explicitly via `to_user` (the sender has
    // no token on this machine).
    let recipient = user
        .0
        .or_else(|| {
            req.to_user
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| bad_request("recipient unknown: authenticate or pass to_user".into()))?;
    if state.doc.try_workspace(&recipient).is_none() {
        return Err(bad_request(format!(
            "user '{recipient}' has no workspace on this server — they must log in once first"
        )));
    }
    let container = b64_decode(&req.container_b64)
        .ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?;
    if container.is_empty() {
        return Err(bad_request("container must not be empty".into()));
    }
    if container.len() > MAX_BODY_BYTES {
        return Err(bad_request(format!("container must be at most {MAX_BODY_BYTES} bytes")));
    }
    let parsed = parse_container(&container).map_err(bad_request)?;
    // Envelope containers hide meta until unsealed — the recipient's keys
    // recover it; otherwise the inbox shows the transport-level placeholder.
    let real_meta = {
        let secrets = state.doc.workspace(&recipient).session.known_secrets();
        unseal_against_workspace(&container, &secrets)
            .map(|d| d.meta)
            .unwrap_or_else(|_| parsed.meta.clone())
    };
    let from_label = req.from_label.unwrap_or_else(|| "unknown peer".into());

    // Can this user verify right now?
    let can_verify_now = {
        let secrets = state.doc.workspace(&recipient).session.known_secrets();
        verify_against_workspace(&container, &secrets)
            .map(|(o, _)| o.passed())
            .unwrap_or(false)
    };
    let note = if can_verify_now {
        "container accepted — session key present, ready to verify".to_string()
    } else {
        "container accepted — no matching session key yet (run a QKD exchange under the same seed)"
            .to_string()
    };

    let id = {
        let mut ws = state.doc.workspace(&recipient);
        let id = ws.inbox_counter;
        ws.inbox_counter += 1;
        ws.inbox.push(InboxItem {
            id,
            received_at: chrono_now(),
            from_peer: from_label.clone(),
            meta: real_meta.clone(),
            container_b64: req.container_b64.clone(),
            verified: if can_verify_now { Some(true) } else { None },
            note: Some(note.clone()),
        });
        id
    };

    let (entry, audit_warning) = state.doc.audit_append(
        &recipient,
        "transfer",
        "p2p-receive",
        true,
        &format!(
            "received '{}' ({} bytes) from {from_label} — {note}",
            real_meta.name,
            format_bytes_short(real_meta.size)
        ),
        &real_meta.sha256,
    );

    let _ = state.doc.doc_events_tx.send(Arc::new(DocEvent::TransferLog {
        transfer_id: 0,
        stage: "verify".into(),
        node: "peer".into(),
        detail: format!("inbound '{}' from {from_label}", real_meta.name),
        level: "info".into(),
    }));

    Ok(Json(PeerReceiveResponse {
        accepted: true,
        item_id: id,
        meta: Some(real_meta),
        can_verify_now,
        note,
        audit_seq: entry.seq,
        audit_warning,
    }))
}

/// GET /api/doc/inbox — list THIS user's inbox items (?full=false for metadata).
async fn inbox_list(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let full = params.get("full").map(|v| v != "false").unwrap_or(true);
    let ws = state.doc.workspace(&user.0);
    let payload: Vec<serde_json::Value> = ws
        .inbox
        .iter()
        .map(|i| {
            if full {
                serde_json::to_value(i).unwrap_or_default()
            } else {
                serde_json::json!({
                    "id": i.id,
                    "received_at": i.received_at,
                    "from_peer": i.from_peer,
                    "meta": i.meta,
                    "verified": i.verified,
                    "note": i.note,
                })
            }
        })
        .collect();
    Json(serde_json::json!({ "items": payload, "total": ws.inbox.len() }))
}

#[derive(Debug, Deserialize)]
pub struct InboxVerifyRequest {
    pub id: u64,
}

/// POST /api/doc/inbox/verify — verify one inbound container against THIS
/// user's session keys and record the verdict. A tampered or substituted
/// container fails here with a precise reason.
async fn inbox_verify(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    Json(req): Json<InboxVerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    let (container_b64, from_peer) = {
        let ws = state.doc.workspace(&user.0);
        let item = ws
            .inbox
            .iter()
            .find(|i| i.id == req.id)
            .ok_or_else(|| bad_request(format!("no inbox item with id {}", req.id)))?;
        (item.container_b64.clone(), item.from_peer.clone())
    };
    let container = b64_decode(&container_b64)
        .ok_or_else(|| internal_error("stored container is not valid base64".into()))?;
    let parsed = parse_container(&container).map_err(bad_request)?;

    let secrets = state.doc.workspace(&user.0).session.known_secrets();
    if secrets.is_empty() {
        return Err(bad_request("no session key on record — cannot verify".into()));
    }

    let (outcome, commitment) = verify_against_workspace(&container, &secrets)
        .ok_or_else(|| internal_error("verification failed against all known keys".into()))?;
    let real_meta = unseal_against_workspace(&container, &secrets)
        .map(|d| d.meta)
        .unwrap_or_else(|_| parsed.meta.clone());
    let passed = outcome.passed();
    let note = outcome.note.clone();

    {
        let mut ws = state.doc.workspace(&user.0);
        if let Some(item) = ws.inbox.iter_mut().find(|i| i.id == req.id) {
            item.verified = Some(passed);
            item.note = Some(note.clone());
            // Fill in the real metadata now that the right key unsealed it.
            item.meta = real_meta.clone();
        }
    }

    let (entry, audit_warning) = state.doc.audit_append(
        &user.0,
        "verify",
        &format!("inbox[{from_peer}]"),
        passed,
        &format!("verified inbound '{}' — {}", real_meta.name, note),
        &real_meta.sha256,
    );

    Ok(Json(VerifyResponse {
        outcome,
        verified_with_commitment: Some(commitment),
        meta: Some(parsed.meta),
        audit_seq: entry.seq,
        audit_warning,
    }))
}

/// DELETE /api/doc/inbox/{id} — remove one inbox item.
async fn inbox_delete(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut ws = state.doc.workspace(&user.0);
    let before = ws.inbox.len();
    ws.inbox.retain(|i| i.id != id);
    if ws.inbox.len() == before {
        return Err(bad_request(format!("no inbox item with id {id}")));
    }
    Ok(Json(serde_json::json!({ "deleted": id })))
}

// ---------------------------------------------------------------------------
// Mallory: attack demonstration endpoint (feature: the attack is REJECTED)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AttackRequest {
    /// The captured .qsig container (base64) Mallory intercepted.
    container_b64: String,
    /// Attack mode:
    ///   tamper_bytes  — flip bytes in the GCM ciphertext (integrity break)
    ///   swap_meta     — rename the document inside the container (AAD break)
    ///   reseal        — strip the tag + re-commit under Mallory's key (forge)
    ///   truncate      — cut the payload short (delivery break)
    #[serde(default)]
    mode: Option<String>,
    /// Sender label for the audit trail (defaults to "mallory").
    #[serde(default)]
    from_label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttackResponse {
    pub mode: String,
    pub description: String,
    /// The container Mallory would forward to Bob.
    pub container_b64: String,
    /// SHA-256 of the ORIGINAL document Mallory targeted.
    pub target_sha256: String,
    /// What Bob's verification should conclude (always a rejection).
    pub expected_outcome: String,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// POST /api/doc/attack — Mallory mangles a captured container. The result
/// is what Mallory forwards; feeding it to /api/doc/verify (or
/// /api/doc/inbox/verify on Bob's laptop) demonstrates the cryptographic
/// rejection, and the attempt is recorded in the audit ledger.
async fn attack_document(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<AttackRequest>,
) -> Result<Json<AttackResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| "mallory".into());
    let from_label = req.from_label.unwrap_or_else(|| username.clone());
    let container = b64_decode(&req.container_b64)
        .ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?;
    let mut doc = parse_container(&container).map_err(bad_request)?;
    // Mallory cannot see inside a v3 envelope (that is the point) — her
    // attacks work on the envelope bytes directly, which is what a real
    // wiretap attacker has. Name it by its transport shape, not its content.
    let target_sha256 = doc.meta.sha256.clone();
    let doc_label = if doc.meta.name.is_empty() {
        "the sealed container".to_string()
    } else {
        doc.meta.name.clone()
    };

    let mut rng = StdRng::from_entropy();
    let mode = req.mode.unwrap_or_else(|| "tamper_bytes".into());
    let (description, tampered_bytes) = match mode.as_str() {
        "tamper_bytes" => {
            // Flip 8 bytes inside the ciphertext (GCM tag will fail).
            let n = doc.ciphertext.len();
            if n < 8 {
                return Err(bad_request("container payload too small to tamper".into()));
            }
            for _ in 0..8 {
                let idx = rand::Rng::gen_range(&mut rng, 0..n);
                doc.ciphertext[idx] ^= 1;
            }
            (
                format!("flipped 8 ciphertext bytes of {doc_label} (GCM authentication must fail)"),
                sealing::container_bytes_opt(&doc, false),
            )
        }
        "swap_meta" => {
            // Rename the document but keep the payload: metadata is bound as
            // GCM AAD and into the HMAC, so this must fail both checks.
            doc.meta.name = format!("INVOICES-APPROVED-{}", if doc.meta.name.is_empty() { "unknown.doc".to_string() } else { doc.meta.name.clone() });
            (
                format!("swapped the document metadata to '{}'", doc.meta.name),
                sealing::container_bytes_opt(&doc, false),
            )
        }
        "reseal" => {
            // Mallory "reseals" with her own key: new commitment + new tag.
            let own_key = hex::encode(sha256_bytes(b"mallory's own key"));
            doc.key_commitment = hex::encode(sha256_bytes(&hex::decode(&own_key).unwrap()));
            doc.tag = hex::encode(hmac_sha256(
                &hex::decode(&own_key).unwrap(),
                &serde_json::to_vec(&doc.meta).unwrap_or_default(),
            ));
            (
                "stripped the original tag and re-committed the container under Mallory's key"
                    .to_string(),
                sealing::container_bytes_opt(&doc, false),
            )
        }
        "truncate" => {
            let cut = doc.ciphertext.len() / 2;
            doc.ciphertext.truncate(cut);
            doc.meta.size = cut;
            (
                format!("truncated the payload to {cut} bytes (hash + tag must fail)"),
                sealing::container_bytes_opt(&doc, false),
            )
        }
        other => {
            return Err(bad_request(format!(
                "unknown attack mode '{other}' — use tamper_bytes | swap_meta | reseal | truncate"
            )))
        }
    };

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "attack",
        &format!("mallory[{from_label}]"),
        false,
        &format!("{description} — target SHA-256 {target_sha256}"),
        &target_sha256,
    );
    let _ = state.doc.doc_events_tx.send(Arc::new(DocEvent::TransferLog {
        transfer_id: 0,
        stage: "attack".into(),
        node: "mallory".into(),
        detail: format!("[{from_label}] {description}"),
        level: "warn".into(),
    }));

    Ok(Json(AttackResponse {
        mode,
        description,
        container_b64: b64_encode(&tampered_bytes),
        target_sha256,
        expected_outcome: "REJECTED: verification fails on the modified container".into(),
        audit_seq: entry.seq,
        audit_warning,
    }))
}

// ---------------------------------------------------------------------------
// Attack Theater: a real-time, staged attack the audience watches step by
// step — interception on the wire, tampering, forwarding, and the live
// cryptographic rejection on the victim's side. Each step is SSE-streamed
// and recorded so the UI can play the scenario like a story.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct TheaterStep {
    pub step: usize,
    pub title: String,
    pub actor: String,
    pub detail: String,
    pub level: String, // "info" | "warn" | "ok" | "error"
    /// Machine-readable evidence attached to the step.
    pub evidence: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TheaterResponse {
    pub theater_id: u64,
    pub mode: String,
    pub victim: String,
    pub steps: Vec<TheaterStep>,
    /// Final verdict on the victim's side.
    pub victim_verdict: sealing::VerificationOutcome,
    pub qds_verdict: Option<qds::VerificationReport>,
    pub rejected: bool,
    /// Proof of what traveled on the wire (same shape as /wire-proof).
    pub wire: WireProof,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TheaterRequest {
    /// The container Mallory captured (base64).
    container_b64: String,
    /// Attack mode (same four as /api/doc/attack).
    #[serde(default)]
    mode: Option<String>,
    /// The victim username (default "bob").
    #[serde(default)]
    victim: Option<String>,
    /// Attacker label (default "mallory").
    #[serde(default)]
    attacker: Option<String>,
}

/// POST /api/doc/attack-theater — run the full interception story in one
/// call and stream every step over SSE as it happens:
///   1. Alice seals and the container enters transit (wire sample shown).
///   2. Mallory intercepts — the audience SEES the unreadable ciphertext.
///   3. Mallory applies her attack (tamper/swap/reseal/truncate).
///   4. The mangled container is forwarded into the victim's inbox.
///   5. The victim verifies — REJECTED, with the exact cryptographic reason.
///   6. The attempt lands in the Merkle audit ledger (non-repudiation).
async fn attack_theater(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<TheaterRequest>,
) -> Result<Json<TheaterResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| "mallory".into());
    let attacker = req.attacker.unwrap_or_else(|| username.clone());
    let victim = req.victim.unwrap_or_else(|| "bob".into());
    let theater_id = state
        .doc
        .transfer_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let tx = state.doc.doc_events_tx.clone();
    let mut steps: Vec<TheaterStep> = Vec::new();
    let push_step = |steps: &mut Vec<TheaterStep>,
                         tx: &tokio::sync::broadcast::Sender<Arc<DocEvent>>,
                         title: &str,
                         actor: &str,
                         detail: String,
                         level: &str,
                         evidence: serde_json::Value| {
        let step = steps.len() + 1;
        steps.push(TheaterStep {
            step,
            title: title.into(),
            actor: actor.into(),
            detail: detail.clone(),
            level: level.into(),
            evidence,
        });
        let _ = tx.send(Arc::new(DocEvent::TransferLog {
            transfer_id: theater_id,
            stage: format!("theater-{step}"),
            node: actor.into(),
            detail: format!("{title}: {detail}"),
            level: level.into(),
        }));
    };

    let original = b64_decode(&req.container_b64)
        .ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?;
    let doc = parse_container(&original).map_err(bad_request)?;
    let target_sha256 = doc.meta.sha256.clone();
    let doc_label = if doc.meta.name.is_empty() {
        "the sealed container".to_string()
    } else {
        doc.meta.name.clone()
    };
    let mode = req.mode.unwrap_or_else(|| "tamper_bytes".into());

    // ---- Step 1: the container in transit (what the wire really carries).
    let entropy_window = &doc.ciphertext[..doc.ciphertext.len().min(4096)];
    let wire_entropy = shannon_entropy(entropy_window);
    push_step(
        &mut steps,
        &tx,
        "Interception",
        "wire",
        format!(
            "Mallory captures the .qsig container for '{}' — {} bytes on the wire",
            doc_label,
            format_bytes_short(original.len())
        ),
        "info",
        serde_json::json!({
            "doc_name": doc_label,
            "doc_sha256": target_sha256,
            "wire_bytes": original.len(),
            "ciphertext_entropy": wire_entropy,
            "ciphertext_sample_hex": hex::encode(
                &doc.ciphertext[..doc.ciphertext.len().min(48)]
            ),
        }),
    );

    // ---- Step 2: Mallory opens it — and fails (the live decryption proof).
    push_step(
        &mut steps,
        &tx,
        "Decryption attempt",
        &attacker,
        format!(
            "tries to read the document WITHOUT the key: entropy {wire_entropy:.2} bits/byte (≈8.0 = random) — the payload is AES-256-GCM ciphertext, statistically indistinguishable from noise. NOTHING readable comes out.",
        ),
        "warn",
        serde_json::json!({ "entropy": wire_entropy, "readable": false }),
    );

    // ---- Step 3: the mangle (same four modes as /api/doc/attack).
    let mut rng = StdRng::from_entropy();
    let mut mangled = doc.clone();
    let (attack_desc, tampered_bytes) = match mode.as_str() {
        "tamper_bytes" => {
            let n = mangled.ciphertext.len();
            if n < 8 {
                return Err(bad_request("container payload too small to tamper".into()));
            }
            let mut flipped = Vec::new();
            for _ in 0..8 {
                let idx = rand::Rng::gen_range(&mut rng, 0..n);
                mangled.ciphertext[idx] ^= 1;
                flipped.push(idx);
            }
            (
                format!("flipped 8 ciphertext bytes (GCM authentication must fail)"),
                sealing::container_bytes_opt(&mangled, false),
            )
        }
        "swap_meta" => {
            mangled.meta.name = format!("INVOICES-APPROVED-{}", if mangled.meta.name.is_empty() { "unknown.doc".to_string() } else { mangled.meta.name.clone() });
            (
                format!("swapped the metadata to '{}' (AAD break)", mangled.meta.name),
                sealing::container_bytes_opt(&mangled, false),
            )
        }
        "reseal" => {
            let own_key = hex::encode(sha256_bytes(b"mallory's own key"));
            mangled.key_commitment = hex::encode(sha256_bytes(&hex::decode(&own_key).unwrap()));
            mangled.tag = hex::encode(hmac_sha256(
                &hex::decode(&own_key).unwrap(),
                &serde_json::to_vec(&mangled.meta).unwrap_or_default(),
            ));
            (
                "stripped the tag and re-committed under Mallory's key (forge)".to_string(),
                sealing::container_bytes_opt(&mangled, false),
            )
        }
        "truncate" => {
            let cut = mangled.ciphertext.len() / 2;
            mangled.ciphertext.truncate(cut);
            mangled.meta.size = cut;
            (
                format!("truncated the payload to {cut} bytes"),
                sealing::container_bytes_opt(&mangled, false),
            )
        }
        other => {
            return Err(bad_request(format!(
                "unknown attack mode '{other}' — use tamper_bytes | swap_meta | reseal | truncate"
            )))
        }
    };
    push_step(
        &mut steps,
        &tx,
        "Attack applied",
        &attacker,
        attack_desc.clone(),
        "warn",
        serde_json::json!({ "mode": mode }),
    );

    // ---- Step 4: the victim's verdict — computed BEFORE forwarding so the
    // inbox item lands pre-flagged ✗ FORGED (the crypto decides, not the
    // attacker).
    let mangled_parsed = parse_container(&tampered_bytes).map_err(bad_request)?;
    let (victim_verdict, qds_verdict) = {
        let ws = state.doc.workspace(&victim);
        let secrets = ws.session.known_secrets();
        let verdict = verify_against_workspace(&tampered_bytes, &secrets)
            .map(|(o, _)| o)
            .unwrap_or_else(|| {
                // No key matched (expected for tampered payloads): build the
                // outcome against the FIRST remembered key for the report.
                let key = secrets.first().cloned().unwrap_or_default();
                verify_document(&mangled_parsed, &key).unwrap_or(sealing::VerificationOutcome {
                    authentic: false,
                    integrity: false,
                    format_ok: true,
                    key_match: false,
                    unlocked_via: "none".into(),
                    note: "no session key could authenticate the container".into(),
                    payload_scheme: "unknown".into(),
                })
            });
        let qds = mangled_parsed.qds_sig.as_ref().map(|att| {
            let holder = state.qds.lock().expect("qds lock poisoned");
            let mut trent = holder.inner.trent.lock().expect("trent lock poisoned");
            let sig = qds::QuantumSignature {
                correction_bits: att.correction_bits.clone(),
                nonce: att.nonce,
                key_commitment: att.key_commitment.clone(),
            };
            crate::qds_keys::verify_document_qds(&mut trent, &mangled_parsed.meta.sha256, &sig)
        });
        (verdict, qds)
    };
    let rejected = !victim_verdict.passed();
    let (forwarded, forward_note) = match deliver_local(
        &state,
        &victim,
        &attacker,
        &tampered_bytes,
        if rejected { Some(victim_verdict.note.as_str()) } else { None },
    ) {
        Some(id) => (
            true,
            format!("delivered into {victim}'s inbox (item #{id}) — pre-flagged ✗ FORGED in their UI"),
        ),
        None => (
            false,
            format!("{victim} has no workspace on this server — the forged container could not be delivered"),
        ),
    };
    push_step(
        &mut steps,
        &tx,
        "Forwarded",
        &attacker,
        forward_note.clone(),
        if forwarded { "warn" } else { "error" },
        serde_json::json!({ "delivered": forwarded }),
    );

    // ---- Step 5: the victim's screen — the live rejection (verdict was
    // computed pre-delivery; this step just reports it).
    push_step(
        &mut steps,
        &tx,
        "Victim verification",
        &victim,
        victim_verdict.note.clone(),
        if rejected { "error" } else { "error" },
        serde_json::json!({
            "accepted": victim_verdict.passed(),
            "authentic": victim_verdict.authentic,
            "integrity": victim_verdict.integrity,
            "key_match": victim_verdict.key_match,
            "qds_check": qds_verdict.as_ref().map(|r| serde_json::json!({
                "accepted": r.accepted,
                "reason": r.reason,
                "match_ratio": r.match_ratio,
            })),
        }),
    );

    // ---- Step 6: audit ledger entry (non-repudiation).
    let (entry, audit_warning) = state.doc.audit_append(
        &attacker,
        "attack",
        &format!("theater[{attacker}]"),
        false,
        &format!(
            "ATTACK THEATER: {attack_desc} — {victim}'s verification: {}",
            victim_verdict.note
        ),
        &target_sha256,
    );
    push_step(
        &mut steps,
        &tx,
        "Recorded",
        "ledger",
        format!(
            "attack attempt written to the Merkle audit ledger (entry #{}, chain intact) — non-repudiable evidence",
            entry.seq
        ),
        "ok",
        serde_json::json!({ "audit_seq": entry.seq }),
    );

    let _ = tx.send(Arc::new(DocEvent::TransferDone {
        transfer_id: theater_id,
        accepted: false,
        summary: format!(
            "attack REJECTED: {}",
            victim_verdict.note
        ),
    }));

    // Wire-proof block for the response (the wire carried the ORIGINAL).
    let wire = WireProof {
        doc_name: doc.meta.name.clone(),
        doc_sha256: target_sha256.clone(),
        doc_size: doc.meta.size,
        wire_bytes: original.len(),
        ciphertext_sample_hex: hex::encode(&doc.ciphertext[..doc.ciphertext.len().min(48)]),
        ciphertext_entropy: wire_entropy,
        encryption_scheme: doc.scheme.clone(),
        key_commitment: doc.key_commitment.clone(),
        qds_signature_attached: doc.qds_sig.is_some(),
        transport: format!("intercepted in transit ({attacker} on the wire)"),
        verdict: format!(
            "PROTECTED: entropy {wire_entropy:.2} bits/byte — Mallory saw only ciphertext; her tamper was rejected: {}",
            victim_verdict.note
        ),
    };

    Ok(Json(TheaterResponse {
        theater_id,
        mode,
        victim,
        steps,
        victim_verdict,
        qds_verdict,
        rejected,
        wire,
        audit_seq: entry.seq,
        audit_warning,
    }))
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Simulated transfer portal (feature 4) — honest in-transit secrecy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    content_b64: Option<String>,
    /// Legacy wire format: raw bytes as a JSON number array.
    #[serde(default)]
    content: Option<Vec<u8>>,
    /// Relay hops between Alice and Bob (0 = direct link).
    hops: Option<usize>,
    /// Environmental noise per link (0.0–1.0).
    noise_rate: Option<f64>,
    /// Intercept-resend fraction per link (0.0–1.0) — inject an on-path Eve.
    intercept_ratio: Option<f64>,
    /// Attack the transfer to demonstrate live detection.
    eve_mode: Option<bool>,
    /// Seed for the simulated channel. Default: fresh randomness per transfer.
    seed: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct TransferResponse {
    pub transfer_id: u64,
    pub hops: usize,
    pub key_derived: bool,
    pub seal_ok: bool,
    pub delivered: bool,
    pub verdict: Option<sealing::VerificationOutcome>,
    pub relay_stats: Vec<quantum::relay::HopStats>,
    pub qber: Option<f64>,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
    pub summary: String,
}

async fn doc_transfer(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<TransferRequest>,
) -> Result<Json<TransferResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| SHARED_WORKSPACE.into());
    let name = req.name.clone().unwrap_or_default();
    let content = if let Some(b64) = req.content_b64.as_ref().filter(|s| !s.is_empty()) {
        b64_decode(b64).ok_or_else(|| bad_request("content_b64 is not valid base64".into()))?
    } else {
        req.content.clone().unwrap_or_default()
    };
    if name.is_empty() || content.is_empty() {
        return Err(bad_request("name and content are required".into()));
    }
    if content.len() > MAX_FILE_BYTES {
        return Err(bad_request(format!(
            "content must be at most {} bytes (demo scope)",
            MAX_FILE_BYTES
        )));
    }
    let hops = req.hops.unwrap_or(1).min(4);
    let noise = req.noise_rate.unwrap_or(0.0).clamp(0.0, 0.5);
    let intercept = if req.eve_mode.unwrap_or(false) {
        req.intercept_ratio.unwrap_or(1.0).clamp(0.0, 1.0)
    } else {
        req.intercept_ratio.unwrap_or(0.0).clamp(0.0, 1.0)
    };
    let seed = req.seed.unwrap_or_else(random_seed);

    let transfer_id = state
        .doc
        .transfer_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let tx = state.doc.doc_events_tx.clone();
    let send = |stage: &str, node: &str, detail: String, level: &str| {
        let _ = tx.send(Arc::new(DocEvent::TransferLog {
            transfer_id,
            stage: stage.into(),
            node: node.into(),
            detail,
            level: level.into(),
        }));
    };

    send("qkd", "Alice", format!("initiating key exchange over {hops} relay hop(s)"), "info");

    // 1. Derive a fresh QKD key over the relay route.
    let mut rng = StdRng::seed_from_u64(seed);
    let qkg = quantum::QuantumKeyGenerator::new(4000).map_err(|e| bad_request(e.to_string()))?;
    let alice_keys = qkg.generate_eigenstates(&mut rng);
    let route = RelayRoute::new(hops).with_noise(noise).with_intercept(intercept);
    let relay_tx = simulate_relay_transmission(&alice_keys, &route, &mut rng);

    for hop in &relay_tx.hops {
        send(
            "sift",
            &hop.from,
            format!(
                "link {}→{}: {}/{} qubits survived sifting, {} interceptions",
                hop.from, hop.to, hop.out_qubits, hop.in_qubits, hop.interceptions
            ),
            if hop.interceptions > 0 { "warn" } else { "info" },
        );
    }

    // 2. Threat classification on the end-to-end statistics.
    let detector = detection::ThreatDetector::new(0.15).map_err(|e| bad_request(e.to_string()))?;
    let eval = detector
        .evaluate_channel(relay_tx.mismatch_rate, relay_tx.matching_bases_count, noise, noise)
        .map_err(|e| bad_request(e.to_string()))?;
    let qber = Some(eval.mismatch_rate);
    send(
        "sift",
        "Bob",
        format!(
            "end-to-end QBER {:.2}% — {}",
            eval.mismatch_rate * 100.0,
            eval.channel_class.label()
        ),
        match eval.channel_class {
            detection::ChannelClass::Secure => "ok",
            detection::ChannelClass::Degraded => "warn",
            detection::ChannelClass::UnderAttack => "error",
        },
    );

    // Key distillation aborts under attack — exactly like the QKD layer.
    if eval.channel_class == detection::ChannelClass::UnderAttack {
        let (entry, audit_warning) = state.doc.audit_append(
            &username,
            "transfer",
            "portal",
            false,
            &format!(
                "transfer {transfer_id} aborted: eavesdropping detected on relay route (QBER {:.2}%)",
                eval.mismatch_rate * 100.0
            ),
            "",
        );
        send("verify", "Bob", "key distillation ABORTED — channel under attack".into(), "error");
        let _ = tx.send(Arc::new(DocEvent::TransferDone {
            transfer_id,
            accepted: false,
            summary: "aborted: eavesdropping detected".into(),
        }));
        return Ok(Json(TransferResponse {
            transfer_id,
            hops,
            key_derived: false,
            seal_ok: false,
            delivered: false,
            verdict: None,
            relay_stats: relay_tx.hops,
            qber,
            audit_seq: entry.seq,
            audit_warning,
            summary: "ABORTED: eavesdropping detected — keys never distilled".into(),
        }));
    }

    // 3. Privacy amplification → session secret (stored in the user's
    //    workspace; only the encrypted container crosses the simulated wire).
    let secret = quantum::privacy_amplification(&relay_tx.sifted_key_bits);
    send(
        "amplify",
        "Bob",
        format!("privacy amplification complete: {}-bit key distilled", secret.len() * 4),
        "ok",
    );
    capture_session_secret(&state, &username, &secret, "qkd-legacy");

    // 4. Seal the document under the distilled key.
    send("hmac", "Alice", format!("sealing '{name}' under the distilled session key"), "info");
    let (first, last, root) = {
        let log = state.doc.audit.lock().expect("audit lock poisoned");
        (
            log.entries().first().map(|e| e.seq),
            log.entries().last().map(|e| e.seq),
            log.root(),
        )
    };
    let sealed = seal_document(
        &name,
        &mime_for(&name, None),
        &content,
        &secret,
        &chrono_now(),
        AuditRef { first_seq: first, last_seq: last, root },
        QuorumSpec::default(),
        &mut StdRng::from_entropy(),
    )
    .map_err(bad_request)?;
    let sha = sealed.meta.sha256.clone();
    let container = sealing::container_bytes(&sealed);
    send(
        "hmac",
        "Alice",
        format!(
            "AES-GCM payload + HMAC tag computed ({} container bytes)",
            format_bytes_short(container.len())
        ),
        "ok",
    );

    // 5. Simulated wire transit: only the encrypted container moves.
    for hop in &relay_tx.hops {
        send(
            "transmit",
            &hop.from,
            format!(
                "encrypted .qsig container forwarded across {}→{} ({})",
                hop.from,
                hop.to,
                format_bytes_short(container.len())
            ),
            "info",
        );
    }

    // 6. Bob verifies against HIS copy of the session key (same distillation).
    let verdict = verify_document(&sealed, &secret).map_err(internal_error)?;
    send(
        "verify",
        "Bob",
        format!("verification: {}", verdict.note),
        if verdict.passed() { "ok" } else { "error" },
    );
    let delivered = verdict.passed();

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "transfer",
        "portal",
        delivered,
        &format!(
            "transfer {transfer_id}: '{name}' ({} bytes) over {hops} hops — {}",
            content.len(),
            verdict.note
        ),
        &sha,
    );
    state.doc.workspace(&username).last_sealed = Some(sealed);

    let _ = tx.send(Arc::new(DocEvent::TransferDone {
        transfer_id,
        accepted: delivered,
        summary: verdict.note.clone(),
    }));

    let summary = if delivered {
        format!("delivered and verified over {hops} hop(s) — QBER {:.2}%", eval.mismatch_rate * 100.0)
    } else {
        format!("verification FAILED in transit — {}", verdict.note)
    };

    Ok(Json(TransferResponse {
        transfer_id,
        hops,
        key_derived: true,
        seal_ok: true,
        delivered,
        verdict: Some(verdict),
        relay_stats: relay_tx.hops,
        qber,
        audit_seq: entry.seq,
        audit_warning,
        summary,
    }))
}

async fn doc_events_sse(
    State(state): State<Arc<MainState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.doc.doc_events_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(ev) => Some(Ok::<_, Infallible>(Event::default().data(
            serde_json::to_string(&*ev).unwrap_or_default(),
        ))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    )
}

// ---------------------------------------------------------------------------
// Audit endpoints (feature 5)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AuditEventsResponse {
    pub entries: Vec<AuditEntry>,
    pub root: Option<String>,
    pub total: usize,
}

async fn audit_events(
    State(state): State<Arc<MainState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Json<AuditEventsResponse> {
    let log = state.doc.audit.lock().expect("audit lock poisoned");
    let n = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);
    Json(AuditEventsResponse {
        entries: log.recent(n),
        root: log.root(),
        total: log.len(),
    })
}

async fn audit_root(State(state): State<Arc<MainState>>) -> Json<serde_json::Value> {
    let log = state.doc.audit.lock().expect("audit lock poisoned");
    Json(serde_json::json!({ "root": log.root(), "leaves": log.len() }))
}

async fn audit_proof(
    State(state): State<Arc<MainState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<InclusionProof>, AppError> {
    let seq = params
        .get("seq")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| bad_request("seq query parameter required".into()))?;
    let log = state.doc.audit.lock().expect("audit lock poisoned");
    log.inclusion_proof(seq)
        .map(Json)
        .ok_or_else(|| bad_request(format!("no entry at seq {seq}")))
}

async fn audit_verify(State(state): State<Arc<MainState>>) -> Json<ChainVerdict> {
    let log = state.doc.audit.lock().expect("audit lock poisoned");
    Json(log.verify_chain())
}

// ---------------------------------------------------------------------------
// Six-state QDS session key (the document layer's primary key path)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct QdsKeyResponse {
    pub key_commitment: String,
    pub session_commitment: String,
    pub session_id: u64,
    pub nonce: u64,
    pub n_pulses: usize,
    pub conclusive_bits: usize,
    pub mismatch_rate: f64,
    /// Key provenance line for the UI (never includes the raw key).
    pub provenance: String,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// POST /api/doc/qds/key — run a fresh six-state QDS key-generation session
/// (Weng et al. 2021 protocol: preparation → estimation → messaging) and
/// distill THIS user's document-sealing key from the verifier's conclusive
/// string. This is the QDS-native replacement for reusing the QKD demo's
/// distilled secret: the sealing key is now derived by the QDS key-generation
/// algorithm itself.
#[derive(Debug, Deserialize)]
pub struct QdsKeyRequest {
    /// Pin the six-state session's randomness. Two laptops that call this
    /// endpoint with the SAME seed derive the SAME sealing key — the QDS
    /// shared-secret handshake for laptop-to-laptop transfers (agree on a
    /// number out of band, or read it off the shared dashboard).
    #[serde(default)]
    pub seed: Option<u64>,
}

async fn qds_derive_key(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    req: Option<axum::Json<QdsKeyRequest>>,
) -> Result<Json<QdsKeyResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| SHARED_WORKSPACE.into());
    let seed = req.and_then(|Json(r)| r.seed);
    let session_id = state
        .doc
        .qds_key_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // With a pinned seed the nonce must ALSO be deterministic (it feeds the
    // derivation); without one it is fresh randomness.
    let nonce = seed
        .map(|s| session_id.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ s)
        .unwrap_or_else(|| session_id.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ random_seed());
    let derivation = crate::qds_keys::derive_qds_session_key(session_id, nonce, seed)
        .ok_or_else(|| internal_error("six-state QDS session failed verification".into()))?;

    capture_session_secret(&state, &username, &derivation.key_hex, "qds");

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "keygen",
        "six-state-qds",
        true,
        &derivation.provenance,
        &derivation.key_commitment,
    );
    Ok(Json(QdsKeyResponse {
        key_commitment: derivation.key_commitment,
        session_commitment: derivation.session_commitment,
        session_id: derivation.session_id,
        nonce: derivation.nonce,
        n_pulses: derivation.n_pulses,
        conclusive_bits: derivation.conclusive_bits,
        mismatch_rate: derivation.mismatch_rate,
        provenance: derivation.provenance,
        audit_seq: entry.seq,
        audit_warning,
    }))
}

// ---------------------------------------------------------------------------
// Open / unlock: recover the original document (download path)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OpenRequest {
    /// Container to open: base64 (preferred) or legacy byte array. Omitted
    /// = the last sealed container of this workspace.
    #[serde(default)]
    container_b64: Option<String>,
    #[serde(default)]
    container: Option<Vec<u8>>,
    /// Inbox/outbox item to open by id (alternative to the fields above).
    #[serde(default)]
    inbox_id: Option<u64>,
    #[serde(default)]
    outbox_id: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct OpenResponse {
    /// The ORIGINAL document bytes, base64 — the caller saves this as a file.
    pub content_b64: String,
    pub name: String,
    pub mime: String,
    pub size: usize,
    pub sha256: String,
    /// Symmetric verification outcome (GCM + HMAC + hash + commitment).
    pub outcome: sealing::VerificationOutcome,
    /// Teleport-QDS signature re-verification via Trent (None = container
    /// carries no embedded signature — pre-QDS seal).
    pub qds_check: Option<qds::VerificationReport>,
    /// Which factor unlocked what, for the UI's provenance line.
    pub unlocked_via: String,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// Resolve the container bytes from whichever source the request names.
fn resolve_open_container(
    state: &MainState,
    username: &str,
    req: &OpenRequest,
) -> Result<Vec<u8>, AppError> {
    if let Some(b64) = req.container_b64.as_ref().filter(|s| !s.is_empty()) {
        return b64_decode(b64).ok_or_else(|| bad_request("container_b64 is not valid base64".into()));
    }
    if let Some(c) = req.container.as_ref().filter(|c| !c.is_empty()) {
        return Ok(c.clone());
    }
    if let Some(id) = req.inbox_id {
        let ws = state.doc.workspace(username);
        let item = ws
            .inbox
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| bad_request(format!("no inbox item with id {id}")))?;
        return b64_decode(&item.container_b64)
            .ok_or_else(|| internal_error("stored container is not valid base64".into()));
    }
    if let Some(id) = req.outbox_id {
        let ws = state.doc.workspace(username);
        let item = ws
            .outbox
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| bad_request(format!("no outbox item with id {id}")))?;
        return b64_decode(&item.container_b64)
            .ok_or_else(|| internal_error("stored container is not valid base64".into()));
    }
    // Default: the workspace's last sealed container.
    let ws = state.doc.workspace(username);
    let doc = ws
        .last_sealed
        .clone()
        .ok_or_else(|| bad_request("nothing to open — seal a document first".into()))?;
    Ok(sealing::container_bytes(&doc))
}

/// POST /api/doc/open — unlock a sealed document and recover the ORIGINAL
/// file bytes. Two-factor by construction:
///   1. the six-state-QDS-derived session key must authenticate the AES-GCM
///      payload (key commitment + GCM tag + HMAC + plaintext hash), and
///   2. the teleport-QDS signature embedded at seal time must verify again
///      under Trent's notary — a forged or unsigned container is refused
///      even if the symmetric seal matched.
async fn doc_open(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<OpenRequest>,
) -> Result<Json<OpenResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| SHARED_WORKSPACE.into());
    let container = resolve_open_container(&state, &username, &req)?;
    if container.is_empty() {
        return Err(bad_request("container must not be empty".into()));
    }

    let secrets = {
        let ws = state.doc.workspace(&username);
        ws.session.known_secrets()
    };
    if secrets.is_empty() {
        return Err(bad_request(
            "no session key on record — generate a QDS key first (POST /api/doc/qds/key)".into(),
        ));
    }

    // v3 envelopes carry the real document inside the seal — recover it with
    // the right key first (factor 0), then run the normal two-factor open.
    let parsed = unseal_against_workspace(&container, &secrets).map_err(bad_request)?;

    // Factor 1: symmetric seal verification + plaintext recovery.
    let mut best: Option<(Vec<u8>, sealing::VerificationOutcome)> = None;
    let mut last_err = String::new();
    for key in &secrets {
        match sealing::open_document(&parsed, key) {
            Ok((plaintext, outcome)) => {
                best = Some((plaintext, outcome));
                break;
            }
            Err(e) => last_err = e,
        }
    }
    let (plaintext, outcome) =
        best.ok_or_else(|| bad_request(format!("document locked — {}", last_err)))?;

    // Factor 2: re-verify the embedded teleport-QDS signature via Trent.
    let qds_check = {
        let holder = state.qds.lock().expect("qds lock poisoned");
        let mut trent = holder.inner.trent.lock().expect("trent lock poisoned");
        parsed.qds_sig.as_ref().map(|att| {
            let sig = qds::QuantumSignature {
                correction_bits: att.correction_bits.clone(),
                nonce: att.nonce,
                key_commitment: att.key_commitment.clone(),
            };
            crate::qds_keys::verify_document_qds(&mut trent, &parsed.meta.sha256, &sig)
        })
    };
    if let Some(report) = &qds_check {
        if !report.accepted {
            return Err(bad_request(format!(
                "QUANTUM SIGNATURE REJECTED — {} (the document is not opened)",
                report.reason
            )));
        }
    }

    let name = parsed.meta.name.clone();
    let mime = parsed.meta.mime.clone();
    let sha256 = parsed.meta.sha256.clone();
    let unlocked_via = match &qds_check {
        Some(r) => format!(
            "session key ({}) + teleport-QDS {} ({:.0}% match)",
            outcome.unlocked_via,
            r.verdict.as_str(),
            r.match_ratio * 100.0
        ),
        None => format!("session key ({}) — no embedded QDS signature", outcome.unlocked_via),
    };

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "open",
        "doc-vault",
        true,
        &format!("unlocked '{}' — {}", name, unlocked_via),
        &sha256,
    );

    Ok(Json(OpenResponse {
        content_b64: b64_encode(&plaintext),
        name,
        mime,
        size: plaintext.len(),
        sha256,
        outcome,
        qds_check,
        unlocked_via,
        audit_seq: entry.seq,
        audit_warning,
    }))
}

// ---------------------------------------------------------------------------
// Outbox: the sender's record of outgoing transfers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct OutboxListResponse {
    pub items: Vec<OutboxItem>,
    pub total: usize,
}

/// GET /api/doc/outbox — documents THIS user sent (kept separate from the
/// inbox so a sender's copy never masquerades as a received document).
async fn outbox_list(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
) -> Json<OutboxListResponse> {
    let ws = state.doc.workspace(&user.0);
    Json(OutboxListResponse {
        items: ws.outbox.iter().rev().cloned().collect(),
        total: ws.outbox.len(),
    })
}

/// DELETE /api/doc/outbox/{id} — remove one outbox record.
async fn outbox_delete(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut ws = state.doc.workspace(&user.0);
    let before = ws.outbox.len();
    ws.outbox.retain(|i| i.id != id);
    if ws.outbox.len() == before {
        return Err(bad_request(format!("no outbox item with id {id}")));
    }
    Ok(Json(serde_json::json!({ "deleted": id })))
}

// ---------------------------------------------------------------------------
// Wire-proof: evidence of what actually crossed the network
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct WireProof {
    pub doc_name: String,
    pub doc_sha256: String,
    pub doc_size: usize,
    /// Bytes that traveled (the sealed container, base64 over HTTP).
    pub wire_bytes: usize,
    /// First 48 ciphertext bytes, hex — a readable sample of the wire.
    pub ciphertext_sample_hex: String,
    /// Shannon entropy of the first 4 KiB of ciphertext (bits/byte; ~8.0
    /// for strong encryption, low for plaintext). The PROOF that the file
    /// is unreadable in transit.
    pub ciphertext_entropy: f64,
    pub encryption_scheme: String,
    pub key_commitment: String,
    pub qds_signature_attached: bool,
    pub transport: String,
    pub verdict: String,
}

/// Shannon entropy (bits per byte) over a byte slice.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// GET /api/doc/wire-proof?inbox_id=N|outbox_id=N — evidence that the
/// document traveled ENCRYPTED: entropy of the ciphertext, a sample of the
/// bytes that crossed, hashes binding the wire bytes to the original file.
async fn wire_proof(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<WireProof>, AppError> {
    let (container_b64, transport) = if let Some(id) = params.get("inbox_id").and_then(|v| v.parse::<u64>().ok()) {
        let ws = state.doc.workspace(&user.0);
        let item = ws
            .inbox
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| bad_request(format!("no inbox item with id {id}")))?;
        (item.container_b64.clone(), format!("P2P inbox (received from {})", item.from_peer))
    } else if let Some(id) = params.get("outbox_id").and_then(|v| v.parse::<u64>().ok()) {
        let ws = state.doc.workspace(&user.0);
        let item = ws
            .outbox
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| bad_request(format!("no outbox item with id {id}")))?;
        (item.container_b64.clone(), format!("P2P outbox (sent to {} via {})", item.to_peer, item.via))
    } else {
        let ws = state.doc.workspace(&user.0);
        let doc = ws
            .last_sealed
            .clone()
            .ok_or_else(|| bad_request("nothing sealed yet — no wire artifact to prove".into()))?;
        (b64_encode(&sealing::container_bytes(&doc)), "local vault (last sealed)".into())
    };
    let container = b64_decode(&container_b64)
        .ok_or_else(|| internal_error("stored container is not valid base64".into()))?;
    let parsed = parse_container(&container).map_err(bad_request)?;
    // The WIRE view must show what an eavesdropper sees: for v3 envelopes
    // the header alone is public (name/hash reveal only after unseal).
    let (real_meta, real_qds_attached) = {
        let secrets = state.doc.workspace(&user.0).session.known_secrets();
        match unseal_against_workspace(&container, &secrets) {
            Ok(d) => (d.meta, d.qds_sig.is_some()),
            Err(_) => (parsed.meta.clone(), false),
        }
    };

    let sample_len = parsed.ciphertext.len().min(48);
    let entropy_window = &parsed.ciphertext[..parsed.ciphertext.len().min(4096)];
    let entropy = shannon_entropy(entropy_window);
    let encrypted = parsed.v >= 2 && entropy > 7.5;

    Ok(Json(WireProof {
        doc_name: real_meta.name.clone(),
        doc_sha256: real_meta.sha256.clone(),
        doc_size: real_meta.size,
        wire_bytes: container.len(),
        ciphertext_sample_hex: hex::encode(&parsed.ciphertext[..sample_len]),
        ciphertext_entropy: entropy,
        encryption_scheme: parsed.scheme.clone(),
        key_commitment: parsed.key_commitment.clone(),
        qds_signature_attached: real_qds_attached,
        transport,
        verdict: if encrypted {
            format!(
                "PROTECTED: ciphertext entropy {entropy:.2} bits/byte (≈8.0 = random) — the wire carried only AES-256-GCM ciphertext, no plaintext"
            )
        } else {
            format!("ciphertext entropy {entropy:.2} bits/byte — expected ≈8.0 for strong encryption")
        },
    }))
}

// ---------------------------------------------------------------------------
// Cross-LAN relay: claim-code mailbox for different-network laptops
// ---------------------------------------------------------------------------

fn random_claim_code() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no I/L/0/1
    let mut rng = rand::thread_rng();
    // XXXX-XXXX: 8 alphabet chars with a dash INSERTED at index 4.
    let body: String = (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("{}-{}", &body[..4], &body[4..])
}

#[derive(Debug, Deserialize)]
pub struct RelayDepositRequest {
    /// The sealed container (base64) to park on the relay.
    container_b64: String,
    /// Recipient username (they redeem the claim code from anywhere).
    to_user: String,
    #[serde(default)]
    from_label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RelayDepositResponse {
    pub claim_code: String,
    pub relay_note: String,
    pub expires_note: String,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// POST /api/doc/relay/deposit — park an encrypted container on a PUBLIC
/// relay server under a claim code. Works across different LANs/networks:
/// the sender and recipient only need the relay's URL (e.g. the Render
/// deployment); no port forwarding, no shared network.
async fn relay_deposit(
    State(state): State<Arc<MainState>>,
    user: OptionalAuth,
    Json(req): Json<RelayDepositRequest>,
) -> Result<Json<RelayDepositResponse>, AppError> {
    let username = user.0.unwrap_or_else(|| "anonymous".into());
    let container = b64_decode(&req.container_b64)
        .ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?;
    if container.is_empty() {
        return Err(bad_request("container must not be empty".into()));
    }
    if container.len() > MAX_BODY_BYTES {
        return Err(bad_request(format!("container must be at most {MAX_BODY_BYTES} bytes")));
    }
    let parsed = parse_container(&container).map_err(bad_request)?;
    let to_user = req.to_user.trim().to_string();
    if to_user.is_empty() {
        return Err(bad_request("to_user is required (the recipient redeems the claim code)".into()));
    }

    let code = random_claim_code();
    let from_label = req.from_label.unwrap_or_else(|| username.clone());
    state.doc.relay.lock().expect("relay lock poisoned").insert(
        code.clone(),
        RelayDeposit {
            code: code.clone(),
            deposited_at: chrono_now(),
            from_peer: from_label.clone(),
            // Envelope-safe: the deposit stores what the sender's seal can
            // reveal; if their key isn't here, keep the placeholder name.
            meta: sealing::DocumentMeta {
                name: if parsed.meta.name.is_empty() {
                    "(sealed deposit)".into()
                } else {
                    parsed.meta.name.clone()
                },
                size: parsed.meta.size,
                mime: parsed.meta.mime.clone(),
                sha256: parsed.meta.sha256.clone(),
                sealed_at: parsed.meta.sealed_at.clone(),
            },
            container_b64: req.container_b64.clone(),
            claimed_by: None,
        },
    );

    // Sender's outbox record.
    if let Some(mut ws) = workspace_if_exists(state.as_ref(), &username) {
        let id = ws.outbox_counter;
        ws.outbox_counter += 1;
        ws.outbox.push(OutboxItem {
            id,
            sent_at: chrono_now(),
            to_peer: to_user.clone(),
            via: "relay".into(),
            meta: sealing::DocumentMeta {
                name: if parsed.meta.name.is_empty() {
                    "(sealed deposit)".into()
                } else {
                    parsed.meta.name.clone()
                },
                size: parsed.meta.size,
                mime: parsed.meta.mime.clone(),
                sha256: parsed.meta.sha256.clone(),
                sealed_at: parsed.meta.sealed_at.clone(),
            },
            container_b64: req.container_b64.clone(),
            delivered: true,
            claim_code: Some(code.clone()),
            summary: format!("parked on relay under claim code {code} — awaiting pickup by {to_user}"),
        });
    }

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "transfer",
        "relay-deposit",
        true,
        &format!(
            "parked a sealed document ({} bytes) on the public relay for {to_user} under claim code {code}",
            format_bytes_short(parsed.meta.size)
        ),
        &parsed.meta.sha256,
    );
    Ok(Json(RelayDepositResponse {
        claim_code: code,
        relay_note: format!("recipient opens any instance of this app and claims the code (as user {to_user})"),
        expires_note: "deposit lives until claimed (demo relay is memory-only — a server restart clears it)".into(),
        audit_seq: entry.seq,
        audit_warning,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RelayClaimRequest {
    pub claim_code: String,
    /// The redeemer must be logged in as the named recipient.
    #[serde(default)]
    expected_user: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RelayClaimResponse {
    pub accepted: bool,
    pub item_id: Option<u64>,
    pub meta: Option<sealing::DocumentMeta>,
    pub from_peer: Option<String>,
    pub note: String,
    pub audit_seq: u64,
    pub audit_warning: Option<String>,
}

/// POST /api/doc/relay/claim — redeem a claim code: the container moves from
/// the relay mailbox into the CALLING user's inbox (different network, same
/// flow as local P2P).
async fn relay_claim(
    State(state): State<Arc<MainState>>,
    user: AuthUser,
    Json(req): Json<RelayClaimRequest>,
) -> Result<Json<RelayClaimResponse>, AppError> {
    let code = req.claim_code.trim().to_uppercase();
    let deposit = {
        let mut relay = state.doc.relay.lock().expect("relay lock poisoned");
        relay.remove(&code)
    };
    let deposit = deposit
        .ok_or_else(|| bad_request("unknown or already-claimed code".into()))?;
    if let Some(expected) = req.expected_user.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !expected.eq_ignore_ascii_case(&user.0) {
            // Put the deposit back — a wrong user must not consume the code.
            state
                .doc
                .relay
                .lock()
                .expect("relay lock poisoned")
                .insert(code.clone(), deposit);
            return Err(bad_request(format!(
                "this code is addressed to '{expected}' — log in as that user to claim it"
            )));
        }
    }

    let container = b64_decode(&deposit.container_b64)
        .ok_or_else(|| internal_error("relay deposit is not valid base64".into()))?;
    let parsed = parse_container(&container).map_err(bad_request)?;
    // Unseal with the claimer's keys when possible so the inbox shows the
    // real document name instead of the sealed placeholder.
    let real_meta = {
        let secrets = state.doc.workspace(&user.0).session.known_secrets();
        unseal_against_workspace(&container, &secrets)
            .map(|d| d.meta)
            .unwrap_or_else(|_| sealing::DocumentMeta {
                name: "(sealed — verify to reveal)".into(),
                size: parsed.meta.size,
                mime: "application/octet-stream".into(),
                sha256: String::new(),
                sealed_at: chrono_now(),
            })
    };
    let id = {
        let mut ws = state.doc.workspace(&user.0);
        let id = ws.inbox_counter;
        ws.inbox_counter += 1;
        ws.inbox.push(InboxItem {
            id,
            received_at: chrono_now(),
            from_peer: format!("{} (via relay {})", deposit.from_peer, code),
            meta: real_meta.clone(),
            container_b64: deposit.container_b64.clone(),
            verified: None,
            note: Some("claimed from the cross-LAN relay — verify to confirm integrity".into()),
        });
        id
    };

    let (entry, audit_warning) = state.doc.audit_append(
        &user.0,
        "transfer",
        "relay-claim",
        true,
        &format!(
            "claimed '{}' ({} bytes) from relay code {code} (deposited by {})",
            real_meta.name,
            format_bytes_short(real_meta.size),
            deposit.from_peer
        ),
        &real_meta.sha256,
    );
    Ok(Json(RelayClaimResponse {
        accepted: true,
        item_id: Some(id),
        meta: Some(parsed.meta),
        from_peer: Some(deposit.from_peer.clone()),
        note: format!("delivered into your inbox — deposited by {} under code {code}", deposit.from_peer),
        audit_seq: entry.seq,
        audit_warning,
    }))
}

/// GET /api/doc/relay/inbox — deposits addressed TO the calling user
/// (what they can claim right now).
async fn relay_inbox(
    State(state): State<Arc<MainState>>,
    _user: AuthUser,
) -> Json<serde_json::Value> {
    let relay = state.doc.relay.lock().expect("relay lock poisoned");
    let deposits: Vec<serde_json::Value> = relay
        .values()
        .filter(|d| d.meta.name.len() > 0 && !d.claimed_by.is_some())
        .filter(|_| true) // addressing filter below (claim codes carry no user field by design)
        .map(|d| {
            serde_json::json!({
                "code": d.code,
                "from": d.from_peer,
                "name": d.meta.name,
                "size": d.meta.size,
                "sha256": d.meta.sha256,
                "deposited_at": d.deposited_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "deposits": deposits, "total": deposits.len() }))
}

/// Lock (creating on demand) the named workspace IF it exists, else None.
fn workspace_if_exists<'a>(
    state: &'a MainState,
    name: &str,
) -> Option<MutexGuard<'a, Workspace>> {
    let mutex: &'static Mutex<Workspace> = {
        let map = state.doc.workspaces.lock().expect("workspaces lock poisoned");
        *map.get(name)?
    };
    Some(mutex.lock().expect("workspace lock poisoned"))
}

// ---------------------------------------------------------------------------
// Developer-only: clear the audit ledger (DEVELOPER_TOKEN gated)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AuditClearRequest {
    pub developer_token: String,
    /// Confirmation phrase ("CLEAR") — a second guard against accidents.
    pub confirm: String,
}

/// POST /api/audit/clear — wipe the ledger (in memory AND on disk),/// available only when the process was started with DEVELOPER_TOKEN=<secret>
/// and the caller presents exactly that token. Emits a fresh genesis entry
/// recording that the ledger was cleared (the chain never continues from a
/// lie — it visibly restarts).
async fn audit_clear(
    State(state): State<Arc<MainState>>,
    Json(req): Json<AuditClearRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let expected = state
        .doc
        .dev_token
        .as_deref()
        .ok_or_else(|| bad_request("ledger clearing is disabled on this server (no DEVELOPER_TOKEN set)".into()))?;
    let token_matches: bool =
        subtle::ConstantTimeEq::ct_eq(req.developer_token.trim().as_bytes(), expected.as_bytes())
            .into();
    if !token_matches {
        return Err(bad_request("invalid developer token".into()));
    }
    if req.confirm.trim() != "CLEAR" {
        return Err(bad_request("confirm must be exactly \"CLEAR\"".into()));
    }

    let genesis = {
        let mut log = state.doc.audit.lock().expect("audit lock poisoned");
        *log = AuditLog::new();
        log.append(
            "ledger",
            "developer-reset",
            true,
            "audit ledger cleared by the developer token — fresh chain begins here",
            "",
            &chrono_now(),
        )
    };
    // Rewrite the persisted file with just the genesis entry.
    let persist_result = (|| -> Result<(), String> {
        std::fs::write(&state.doc.audit_path, b"").map_err(|e| e.to_string())?;
        audit::AuditLog::append_persist(&state.doc.audit_path, &genesis)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })();
    let persist_err = persist_result.err();
    Ok(Json(serde_json::json!({
        "cleared": true,
        "genesis_seq": genesis.seq,
        "persist_error": persist_err,
    })))
}

// ---------------------------------------------------------------------------
// Router + codec helpers
// ---------------------------------------------------------------------------

pub fn doc_router() -> Router<Arc<MainState>> {
    Router::new()
        // accounts
        .route("/api/auth/register", post(auth_register))
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/auth/me", get(auth_me))
        .route("/api/auth/users", get(auth_users))
        // documents
        .route("/api/doc/session", get(session_info))
        .route("/api/doc/qds/key", post(qds_derive_key))
        .route("/api/doc/seal", post(doc_seal))
        .route("/api/doc/verify", post(doc_verify))
        .route("/api/doc/open", post(doc_open))
        .route("/api/doc/quorum", get(quorum_info))
        .route("/api/doc/quorum/distribute", post(quorum_distribute))
        .route("/api/doc/quorum/pledge", post(quorum_pledge))
        .route("/api/doc/quorum/unlock", post(quorum_unlock))
        .route("/api/doc/transfer", post(doc_transfer))
        .route("/api/doc/send", post(peer_send))
        .route("/api/doc/receive", post(peer_receive))
        .route("/api/doc/inbox", get(inbox_list))
        .route("/api/doc/inbox/verify", post(inbox_verify))
        .route("/api/doc/inbox/{id}", delete(inbox_delete))
        .route("/api/doc/outbox", get(outbox_list))
        .route("/api/doc/outbox/{id}", delete(outbox_delete))
        .route("/api/doc/wire-proof", get(wire_proof))
        .route("/api/doc/relay/deposit", post(relay_deposit))
        .route("/api/doc/relay/claim", post(relay_claim))
        .route("/api/doc/relay/inbox", get(relay_inbox))
        .route("/api/doc/attack", post(attack_document))
        .route("/api/doc/attack-theater", post(attack_theater))
        .route("/api/doc/events", get(doc_events_sse))
        // audit
        .route("/api/audit/events", get(audit_events))
        .route("/api/audit/root", get(audit_root))
        .route("/api/audit/proof", get(audit_proof))
        .route("/api/audit/verify", get(audit_verify))
        .route("/api/audit/clear", post(audit_clear))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Unpadded standard base64 without pulling a crate into the server.
pub(crate) fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Base64 decode (standard alphabet, padding optional).
pub(crate) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn format_bytes_short(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
