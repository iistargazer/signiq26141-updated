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

/// Mutable per-user state: session key, quorum, inbox, last seal.
#[derive(Default)]
pub struct Workspace {
    pub session: SealSession,
    /// Last sealed container (so /verify and quorum unlock can be demoed
    /// without re-uploading).
    pub last_sealed: Option<sealing::QsigDocument>,
    /// Documents received from peers, oldest first.
    pub inbox: Vec<InboxItem>,
    pub inbox_counter: u64,
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

/// Shared document-layer state: one audit ledger, per-user workspaces.
pub struct DocStateHolder {
    /// Workspace name -> state. Created on demand (login, run, receive…).
    /// Workspaces live for the whole process, so each mutex is `Box::leak`ed
    /// into a `&'static` — that lets `workspace()` hand out a MutexGuard
    /// without holding the HashMap lock or juggling Arc clones.
    pub workspaces: Mutex<HashMap<String, &'static Mutex<Workspace>>>,
    pub auth: Arc<AuthState>,
    /// Shared Merkle audit ledger (every user's events chain together).
    pub audit: Mutex<AuditLog>,
    pub audit_path: PathBuf,
    pub doc_events_tx: tokio::sync::broadcast::Sender<Arc<DocEvent>>,
    pub transfer_counter: AtomicU64,
}

impl DocStateHolder {
    /// Startup path: adopt a log reloaded from disk (`AuditLog::load_jsonl`).
    pub fn from_log(log: AuditLog, audit_path: PathBuf, auth: Arc<AuthState>) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1024);
        Self {
            workspaces: Mutex::new(HashMap::new()),
            auth,
            audit: Mutex::new(log),
            audit_path,
            doc_events_tx: tx,
            transfer_counter: AtomicU64::new(1),
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

/// Record the distilled QKD secret as a user's session key.
pub(crate) fn capture_session_secret(state: &MainState, user: &str, secret_hex: &str) {
    state
        .doc
        .workspace(user)
        .session
        .set_secret(secret_hex.to_string());
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
    let secret_hex = ws
        .session
        .secret_hex
        .clone()
        .ok_or_else(|| {
            bad_request(
                "no session key yet — run a QKD exchange first (POST /api/run) to derive the sealing key"
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
    let sealed = seal_document(
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
            "sealed '{}' ({} bytes, quorum: {})",
            req.name,
            content.len(),
            if use_quorum { format!("{threshold}-of-{shares_total}") } else { "none".into() }
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
    parsed: &sealing::QsigDocument,
    secrets: &[String],
) -> Option<(sealing::VerificationOutcome, String)> {
    let mut best: Option<(sealing::VerificationOutcome, String)> = None;
    for key in secrets {
        if let Ok(outcome) = verify_document(parsed, key) {
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

    let (outcome, commitment) = verify_against_workspace(&parsed, &secrets)
        .ok_or_else(|| internal_error("verification failed against all known keys".into()))?;
    let passed = outcome.passed();
    let note = outcome.note.clone();

    let (entry, audit_warning) = state.doc.audit_append(
        &username,
        "verify",
        "doc-vault",
        passed,
        &format!("verified '{}' — {}", parsed.meta.name, note),
        &parsed.meta.sha256,
    );

    Ok(Json(VerifyResponse {
        outcome,
        verified_with_commitment: Some(commitment),
        meta: Some(parsed.meta),
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
        let parsed = {
            let ws = state.doc.workspace(&username);
            match (&req.container_b64, &req.container) {
                (Some(b64), _) if !b64.is_empty() => {
                    let bytes = b64_decode(b64)
                        .ok_or_else(|| bad_request("container_b64 is not valid base64".into()))?;
                    parse_container(&bytes).map_err(bad_request)?
                }
                (_, Some(c)) if !c.is_empty() => parse_container(c).map_err(bad_request)?,
                _ => ws.last_sealed.clone().ok_or_else(|| {
                    bad_request("no container supplied and none sealed yet".into())
                })?,
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
        let sealed = seal_document(
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
        let item_id = deliver_local(&state, &to_user, &from_label, &container);
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
) -> Option<u64> {
    let parsed = parse_container(container).ok()?;
    let meta = parsed.meta.clone();
    let can_verify_now = {
        let mut can = false;
        if let Some(ws) = state.doc.try_workspace(to_user) {
            for key in ws.session.known_secrets() {
                if let Ok(o) = verify_document(&parsed, &key) {
                    if o.passed() {
                        can = true;
                        break;
                    }
                }
            }
        }
        can
    };
    let mut ws = state.doc.try_workspace(to_user)?;
    let id = ws.inbox_counter;
    ws.inbox_counter += 1;
    let note = if can_verify_now {
        "container accepted — session key present, ready to verify".to_string()
    } else {
        "container accepted — no matching session key yet".to_string()
    };
    ws.inbox.push(InboxItem {
        id,
        received_at: chrono_now(),
        from_peer: from_label.to_string(),
        meta: meta.clone(),
        container_b64: b64_encode(container),
        verified: if can_verify_now { Some(true) } else { None },
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
    let meta = parsed.meta.clone();
    let from_label = req.from_label.unwrap_or_else(|| "unknown peer".into());

    // Can this user verify right now?
    let can_verify_now = {
        let secrets = state.doc.workspace(&recipient).session.known_secrets();
        verify_against_workspace(&parsed, &secrets)
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
            meta: meta.clone(),
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

    Ok(Json(PeerReceiveResponse {
        accepted: true,
        item_id: id,
        meta: Some(meta),
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

    let (outcome, commitment) = verify_against_workspace(&parsed, &secrets)
        .ok_or_else(|| internal_error("verification failed against all known keys".into()))?;
    let passed = outcome.passed();
    let note = outcome.note.clone();

    {
        let mut ws = state.doc.workspace(&user.0);
        if let Some(item) = ws.inbox.iter_mut().find(|i| i.id == req.id) {
            item.verified = Some(passed);
            item.note = Some(note.clone());
        }
    }

    let (entry, audit_warning) = state.doc.audit_append(
        &user.0,
        "verify",
        &format!("inbox[{from_peer}]"),
        passed,
        &format!("verified inbound '{}' — {}", parsed.meta.name, note),
        &parsed.meta.sha256,
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
    let target_sha256 = doc.meta.sha256.clone();

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
                format!("flipped 8 ciphertext bytes of '{}' (GCM authentication must fail)", doc.meta.name),
                sealing::container_bytes(&doc),
            )
        }
        "swap_meta" => {
            // Rename the document but keep the payload: metadata is bound as
            // GCM AAD and into the HMAC, so this must fail both checks.
            doc.meta.name = format!("INVOICES-APPROVED-{}", doc.meta.name);
            (
                format!("swapped the document metadata to '{}'", doc.meta.name),
                sealing::container_bytes(&doc),
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
                sealing::container_bytes(&doc),
            )
        }
        "truncate" => {
            let cut = doc.ciphertext.len() / 2;
            doc.ciphertext.truncate(cut);
            doc.meta.size = cut;
            (
                format!("truncated the payload to {cut} bytes (hash + tag must fail)"),
                sealing::container_bytes(&doc),
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
    capture_session_secret(&state, &username, &secret);

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
        .route("/api/doc/seal", post(doc_seal))
        .route("/api/doc/verify", post(doc_verify))
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
        .route("/api/doc/attack", post(attack_document))
        .route("/api/doc/events", get(doc_events_sse))
        // audit
        .route("/api/audit/events", get(audit_events))
        .route("/api/audit/root", get(audit_root))
        .route("/api/audit/proof", get(audit_proof))
        .route("/api/audit/verify", get(audit_verify))
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
