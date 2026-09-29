//! SIH26141 — Quantum-Secured Pipeline API server.
//!
//! REST + SSE facade over the quantum / detection / crypto crates:
//!   GET  /api/health   — liveness probe
//!   POST /api/run      — full simulation (secure + attack scenarios) with live SSE progress
//!   POST /api/simulate — parameter sweep over intercept ratios
//!   GET  /api/events   — SSE stream of live run events
//!   /api/qds/*         — teleportation-based QDS signature lab (see qds_api.rs)
//!   /api/doc/*         — document sealing, verification, quorum unlock,
//!                        P2P transfer portal + live SSE (see doc_api.rs)
//!   /api/audit/*       — Merkle-tree audit log (events / root / proof)
//!   GET  /             — serves the built frontend from ../frontend/dist

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use auth::{AuthState, OptionalAuth};
use doc_api::{doc_router, DocStateHolder};
use qds_api::{qds_router, QdsStateHolder};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;

use crypto::{compute_message_hmac, verify_message_hmac};
use detection::ThreatDetector;
use quantum::{ChannelSession, QuantumKeyGenerator, SiftedKeyResult};

mod auth;
mod doc_api;
mod qds_api;
mod qds_keys;
mod qds_state;

const DEFAULT_PORT: u16 = 8080;
const DEFAULT_KEY_LENGTH: usize = 3000;
const MIN_KEY_LENGTH: usize = 500;
const MAX_KEY_LENGTH: usize = 200_000;
const DEFAULT_BASE_THRESHOLD: f64 = 0.15;
const DEFAULT_PACE_MS: u64 = 4;
const MAX_MESSAGE_LEN: usize = 10_000;

/// Live events broadcast on the SSE stream while a run executes.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RunEvent {
    /// Emitted after every batch of processed qubits.
    Progress {
        run_id: u64,
        scenario: String,
        processed: usize,
        total: usize,
        sifted: usize,
        mismatches: usize,
        qber: f64,
        /// Hoeffding-adjusted detection threshold at this sample size.
        threshold: f64,
    },
    /// Final verdict for one scenario.
    Result { run_id: u64, result: ScenarioResult },
    /// Emitted when the whole run is done.
    Done { run_id: u64 },
}

struct AppState {
    events_tx: broadcast::Sender<Arc<RunEvent>>,
    /// Last completed run per run_id, so late SSE subscribers can catch up.
    last_result: Mutex<Option<RunResponse>>,
    run_counter: AtomicU64,
    /// QDS signature-lab state (Trent + event log + last signature).
    qds: Mutex<QdsStateHolder>,
    /// Path of the persistent QDS security-event log (JSONL).
    qds_log_path: PathBuf,
    /// Document-sealing / transfer-portal / audit-log state.
    doc: DocStateHolder,
    /// Short-lived, one-reveal blinded challenge rounds (memory-only).
    blind_challenges: Mutex<HashMap<String, BlindChallengeRecord>>,
    /// The port the server actually bound (differs from the request only
    /// after a port-fallback; the frontend discovers it via /api/server-info
    /// and frontend/dist/server-port.json). Atomic because the listener is
    /// bound after state construction.
    bound_port: std::sync::atomic::AtomicU16,
    /// The host the server bound ("127.0.0.1" by default; 0.0.0.0 enables
    /// LAN access for the P2P transfer feature). Known before state
    /// construction, so a plain immutable string suffices.
    bound_host: String,
}

/// Extractor plumbing: the auth extractors resolve the session table through
/// the router state (`Arc<AppState>`), so expose the shared `AuthState`.
impl AsRef<AuthState> for Arc<AppState> {
    fn as_ref(&self) -> &AuthState {
        &self.doc.auth
    }
}

#[derive(Debug, Deserialize)]
struct RunRequest {
    key_length: Option<usize>,
    base_threshold: Option<f64>,
    /// Fraction of qubits Eve intercepts (0.0–1.0). None = two canonical
    /// scenarios (clean + full attack); Some(r) = one scenario at ratio r.
    intercept_ratio: Option<f64>,
    /// Environmental bit-flip probability per link (0.0–1.0), independent of
    /// any attack — fiber noise / turbulence model (feature 2).
    noise_rate: Option<f64>,
    /// Relay hops between Alice and Bob (0 = direct link; feature 1).
    relay_hops: Option<usize>,
    /// Message to authenticate with the derived key.
    message: Option<String>,
    /// Seed for reproducible runs.
    seed: Option<u64>,
    /// Per-batch pacing delay in ms so the live monitor is watchable. 0 = fast.
    pace_ms: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
struct ScenarioResult {
    scenario: String,
    intercept_ratio: f64,
    /// Environmental noise applied on this scenario (0.0 = clean fiber).
    #[serde(skip_serializing_if = "is_zero")]
    noise_rate: f64,
    /// Relay hops used on this scenario (0 = direct link).
    #[serde(skip_serializing_if = "is_zero_usize")]
    relay_hops: usize,
    /// Per-link relay statistics (empty for direct links).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relay_stats: Vec<quantum::relay::HopStats>,
    raw_key_length: usize,
    matching_bases_count: usize,
    sifted_key_length: usize,
    #[serde(rename = "qber")]
    mismatch_rate: f64,
    dynamic_threshold: f64,
    is_authentic: bool,
    /// Channel was within the configured decision line and the modeled
    /// entropy budget actually yielded a session key.
    key_distilled: bool,
    threat_flagged: bool,
    /// Three-way channel classification (secure / degraded / under_attack).
    channel_class: String,
    /// First differing bit index between Alice's and Bob's sifted keys, if any.
    first_divergence: Option<usize>,
    /// Internal only: the distilled session secret is deliberately NOT
    /// serialized (any client could otherwise read the raw sealing key).
    #[serde(skip_serializing)]
    derived_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_valid: Option<bool>,
    /// Security accounting for the distilled key (v3 post-processing):
    /// smooth min-entropy consumed, Toeplitz output length, achieved
    /// extractor epsilon, reconciliation leakage, finite-key verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    security: Option<SecurityAccounting>,
    /// Classical software-model CHSH diagnostic run alongside the QKD
    /// transmission. Its S > 2 + 3σ label applies only to sampled outcomes
    /// in this model; it is not device-independent physical certification.
    #[serde(skip_serializing_if = "Option::is_none")]
    bell_test: Option<BellTestReport>,
    /// Chernoff–Hoeffding statistical dossier computed from THIS run's
    /// actual measurement statistics (k mismatches over n sifted positions)
    /// — the bounds visualizer's live mode: every threshold ships with its
    /// own finite-sample proof, per run. None never (cheap to compute).
    #[serde(skip_serializing_if = "Option::is_none")]
    statistical_bounds: Option<detection::bounds::BoundsReport>,
    note: String,
}

/// The CHSH Bell-test paperwork for one run (see quantum::chsh).
#[derive(Debug, Serialize, Clone)]
struct BellTestReport {
    /// Sampled CHSH value from the synthetic classical model.
    s: f64,
    /// One-σ standard error of S from the finite sample.
    sigma: f64,
    /// Entangled pairs consumed by the test.
    rounds: usize,
    /// Model-relative diagnostic: sampled S clears 2 by 3 estimated σ.
    certified: bool,
    /// Margin over the classical bound, in units of σ.
    margin_sigma: f64,
    /// Channel visibility V = 1 − 2·noise; S scales with it.
    visibility: f64,
}

/// The leftover-hash-lemma paperwork for one distilled key — surfaced so
/// the dashboard can SHOW the security contract, not just assert it.
#[derive(Debug, Serialize, Clone)]
struct SecurityAccounting {
    /// Raw sifted positions entering the extractor.
    raw_bits: usize,
    /// Bits charged to Eve (basis-known positions).
    eve_bits: usize,
    /// Syndrome/parity bits disclosed during reconciliation.
    reconciliation_leakage: usize,
    /// Smooth min-entropy lower bound after the charges.
    min_entropy_bits: f64,
    /// Toeplitz extractor output length (bounded by LHL).
    output_bits: usize,
    /// LHL statistical-distance bound when the extractor seed is independent;
    /// absent for deterministic seeded simulations and legacy fallback paths.
    epsilon: Option<f64>,
    /// True when the statistical decision was settled (finite-key analysis).
    finite_key_ok: bool,
}

fn is_zero(v: &f64) -> bool {
    *v == 0.0
}

fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

fn finalize(
    scenario: &str,
    intercept_ratio: f64,
    noise_rate: f64,
    relay_hops: usize,
    relay_stats: Vec<quantum::relay::HopStats>,
    key_length: usize,
    tx: SiftedKeyResult,
    base_threshold: f64,
    message: Option<&str>,
) -> Result<ScenarioResult, String> {
    finalize_seeded(scenario, intercept_ratio, noise_rate, relay_hops, relay_stats, key_length, tx, base_threshold, message, 0)
}

/// `finalize` with an explicit extractor seed. When `pa_seed` is non-zero
/// the Toeplitz matrix is pinned to it: two laptops that ran the SAME
/// seeded QKD session (same sifted bits after reconciliation) then derive
/// the SAME session key — the P2P handshake. Zero = fresh CSPRNG draw.
fn finalize_seeded(
    scenario: &str,
    intercept_ratio: f64,
    noise_rate: f64,
    relay_hops: usize,
    relay_stats: Vec<quantum::relay::HopStats>,
    key_length: usize,
    tx: SiftedKeyResult,
    base_threshold: f64,
    message: Option<&str>,
    pa_seed: u64,
) -> Result<ScenarioResult, String> {
    let detector = ThreatDetector::new(base_threshold).map_err(|e| e.to_string())?;
    let eval = detector
        .evaluate_channel(tx.mismatch_rate, tx.matching_bases_count, noise_rate, tx.noise_rate)
        .map_err(|e| e.to_string())?;

    // ---- live statistical bounds (Feature 3, wired to real runs) --------
    // The exact-binomial p-value and both concentration bounds computed on
    // THIS run's numbers: k = observed mismatches, n = sifted positions.
    // This is what turns the threat verdict into mathematics a judge can
    // interrogate — the same numbers the detector used, now with receipts.
    let observed_mismatches = (tx.mismatch_rate * tx.matching_bases_count as f64).round() as usize;
    let statistical_bounds = detection::bounds::bounds_report(
        observed_mismatches.min(tx.matching_bases_count),
        tx.matching_bases_count,
        base_threshold,
        0.01,
        eval.dynamic_threshold,
    );

    let first_divergence = tx
        .sifted_key_bits
        .iter()
        .zip(tx.alice_sifted_bits.iter())
        .position(|(b, a)| b != a);

    // ---- modeled post-processing -------------------------------------------
    // On an accepted channel, reconcile the simulated bit strings and apply
    // Toeplitz hashing with an OS-CSPRNG or reproducibility seed. The entropy
    // estimate depends on the configured simulation/attack model; the LHL
    // bound is only reported for the independent OS-CSPRNG seed path. The
    // shared seeded demo intentionally makes no cryptographic privacy claim.
    let (derived_secret, security) = if eval.is_authentic {
        // Adaptive Cascade: the opening block follows the measured QBER
        // (0.73/QBER, Brassard–Salvail 1993) — cheaper at a clean channel,
        // finer at a noisy one.
        let rec = quantum::reconcile_adaptive(&tx.alice_sifted_bits, &tx.sifted_key_bits, tx.mismatch_rate, 3);
        let budget = pa::EntropyBudget {
            n: tx.sifted_key_bits.len(),
            eve_bits: ((tx.sifted_key_bits.len() as f64) * eval.eve_information_fraction) as usize,
            reconciliation_leakage: rec.leakage_bits,
        };
        let distilled = if scenario.starts_with("sweep-") || scenario == "blind-challenge" {
            None
        } else if pa_seed != 0 {
            pa::distill_seeded(&rec.bob_bits, budget, 1e-9, pa_seed)
        } else {
            pa::distill(&rec.bob_bits, budget, 1e-9, &mut rand::rngs::OsRng)
        };
        match distilled {
            Some(d) => {
                let accounting = SecurityAccounting {
                    raw_bits: budget.n,
                    eve_bits: budget.eve_bits,
                    reconciliation_leakage: budget.reconciliation_leakage,
                    min_entropy_bits: d.min_entropy_bits,
                    output_bits: d.output_bits,
                    epsilon: d.epsilon,
                    finite_key_ok: eval.finite_key_ok,
                };
                (Some(d.key_hex), Some(accounting))
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let mut result = ScenarioResult {
        scenario: scenario.to_string(),
        intercept_ratio,
        noise_rate,
        relay_hops,
        relay_stats,
        raw_key_length: key_length,
        matching_bases_count: tx.matching_bases_count,
        sifted_key_length: tx.sifted_key_bits.len(),
        mismatch_rate: eval.mismatch_rate,
        dynamic_threshold: eval.dynamic_threshold,
        is_authentic: eval.is_authentic,
        key_distilled: derived_secret.is_some(),
        threat_flagged: eval.threat_flagged,
        channel_class: eval.channel_class.as_str().to_string(),
        first_divergence,
        derived_secret,
        hmac_tag: None,
        hmac_valid: None,
        security,
        bell_test: None,
        statistical_bounds: Some(statistical_bounds),
        note: eval.note.to_string(),
    };

    // CHSH is included as a Monte-Carlo diagnostic generated from the same
    // requested channel parameters. It is not an independently implemented
    // physical Bell experiment or a device-independent security certificate.
    let bell = quantum::chsh::run_chsh(
        (key_length * 8).max(4_000),
        intercept_ratio.clamp(0.0, 1.0),
        noise_rate,
        &mut rand::rngs::OsRng,
    );
    result.bell_test = Some(BellTestReport {
        s: (bell.s * 1000.0).round() / 1000.0,
        sigma: (bell.sigma * 1000.0).round() / 1000.0,
        rounds: bell.rounds,
        certified: bell.certified(),
        margin_sigma: (bell.margin_sigma() * 10.0).round() / 10.0,
        visibility: (bell.visibility * 1000.0).round() / 1000.0,
    });

    if let (Some(secret), Some(msg)) = (&result.derived_secret, message) {
        let tag = compute_message_hmac(secret, msg.as_bytes()).map_err(|e| e.to_string())?;
        result.hmac_valid = Some(verify_message_hmac(secret, msg.as_bytes(), &tag).unwrap_or(false));
        result.hmac_tag = Some(tag);
    }

    Ok(result)
}

/// Convert a relay transmission into the pipeline's sifted-key result.
fn relay_to_sifted(rt: quantum::relay::RelayTransmission) -> (SiftedKeyResult, Vec<quantum::relay::HopStats>) {
    let tx = SiftedKeyResult {
        sifted_key_bits: rt.sifted_key_bits,
        alice_sifted_bits: rt.alice_sifted_bits,
        mismatch_rate: rt.mismatch_rate,
        matching_bases_count: rt.matching_bases_count,
        noise_rate: rt.noise_rate,
    };
    (tx, rt.hops)
}

/// Accumulate per-link relay statistics across consecutive batch chunks.
fn merge_hop_stats(base: &mut [quantum::relay::HopStats], add: &[quantum::relay::HopStats]) {
    for (b, a) in base.iter_mut().zip(add.iter()) {
        b.in_qubits += a.in_qubits;
        b.out_qubits += a.out_qubits;
        b.mismatches += a.mismatches;
        b.interceptions += a.interceptions;
        b.qber = if b.out_qubits == 0 {
            0.0
        } else {
            b.mismatches as f64 / b.out_qubits as f64
        };
    }
}

/// Emit a progress event on the SSE channel (Hoeffding-adjusted threshold).
fn emit_progress(
    events: &broadcast::Sender<Arc<RunEvent>>,
    run_id: u64,
    scenario: &str,
    processed: usize,
    total: usize,
    sifted: usize,
    mismatches: usize,
    base_threshold: f64,
) {
    let n = sifted as f64;
    let slack = if n > 0.0 {
        ((2.0_f64 / 0.05).ln() / (2.0 * n)).sqrt()
    } else {
        1.0
    };
    let threshold = (base_threshold + slack).min(1.0);
    let _ = events.send(Arc::new(RunEvent::Progress {
        run_id,
        scenario: scenario.to_string(),
        processed,
        total,
        sifted,
        mismatches,
        qber: if sifted == 0 { 0.0 } else { mismatches as f64 / sifted as f64 },
        threshold,
    }));
}

/// Runs one scenario with live per-batch progress events on the SSE channel.
/// `relay_hops == 0` uses the direct point-to-point channel; `> 0` routes
/// every qubit through the trusted-relay chain (feature 1).
#[allow(clippy::too_many_arguments)]
fn execute_scenario_streaming(
    events: &broadcast::Sender<Arc<RunEvent>>,
    run_id: u64,
    scenario: &str,
    intercept_ratio: f64,
    noise_rate: f64,
    relay_hops: usize,
    key_length: usize,
    base_threshold: f64,
    message: Option<&str>,
    seed: u64,
    pace_ms: u64,
) -> Result<ScenarioResult, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let qkg = QuantumKeyGenerator::new(key_length).map_err(|e| e.to_string())?;
    let alice_keys = qkg.generate_eigenstates(&mut rng);

    if relay_hops == 0 {
        // Direct link: incremental ChannelSession, one progress event per batch.
        let mut session = ChannelSession::new(intercept_ratio).with_noise(noise_rate);
        let batch = (key_length / 100).max(1);

        for (i, &(basis, state)) in alice_keys.iter().enumerate() {
            session.transmit(basis, state, &mut rng);
            if (i + 1) % batch == 0 || i + 1 == key_length {
                emit_progress(
                    events,
                    run_id,
                    scenario,
                    i + 1,
                    key_length,
                    session.sifted_count(),
                    session.mismatch_count(),
                    base_threshold,
                );
                if pace_ms > 0 && i + 1 < key_length {
                    std::thread::sleep(std::time::Duration::from_millis(pace_ms));
                }
            }
        }

        finalize_seeded(
            scenario,
            intercept_ratio,
            noise_rate,
            0,
            Vec::new(),
            key_length,
            session.finish(),
            base_threshold,
            message,
            seed,
        )
    } else {
        // Multi-hop: relay transmissions batched so the live monitor still
        // streams progress while each qubit traverses the full route.
        let route = quantum::relay::RelayRoute::new(relay_hops)
            .with_noise(noise_rate)
            .with_intercept(intercept_ratio);
        let batch = (key_length / 100).max(1);

        let mut sifted: Vec<u8> = Vec::new();
        let mut alice_bits: Vec<u8> = Vec::new();
        let mut mismatches = 0usize;
        let mut matching = 0usize;
        let mut hop_stats: Vec<quantum::relay::HopStats> = (0..route.link_count())
            .map(|link| quantum::relay::HopStats {
                hop: link,
                from: route.node_label(link),
                to: if link + 1 < route.link_count() {
                    route.node_label(link + 1)
                } else {
                    "Bob".into()
                },
                noise_rate,
                intercept_ratio,
                ..Default::default()
            })
            .collect();

        for (chunk_i, chunk) in alice_keys.chunks(batch).enumerate() {
            let rt = quantum::relay::simulate_relay_transmission(chunk, &route, &mut rng);
            sifted.extend_from_slice(&rt.sifted_key_bits);
            alice_bits.extend_from_slice(&rt.alice_sifted_bits);
            mismatches += (rt.mismatch_rate * rt.matching_bases_count as f64).round() as usize;
            matching += rt.matching_bases_count;
            merge_hop_stats(&mut hop_stats, &rt.hops);

            emit_progress(
                events,
                run_id,
                scenario,
                (chunk_i + 1).min(alice_keys.len()),
                key_length,
                matching,
                mismatches,
                base_threshold,
            );
            if pace_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(pace_ms));
            }
        }

        let tx = SiftedKeyResult {
            mismatch_rate: if matching == 0 {
                0.0
            } else {
                mismatches as f64 / matching as f64
            },
            matching_bases_count: matching,
            sifted_key_bits: sifted,
            alice_sifted_bits: alice_bits,
            noise_rate,
        };
        finalize(
            scenario,
            intercept_ratio,
            noise_rate,
            relay_hops,
            hop_stats,
            key_length,
            tx,
            base_threshold,
            message,
        )
    }
}

#[derive(Debug, Clone, Serialize)]
struct RunResponse {
    run_id: u64,
    /// The seed actually used (echoed so the dashboard can display why a
    /// run is reproducible: a typed-in seed re-produces identical results).
    seed: u64,
    results: Vec<ScenarioResult>,
    authenticated_message: Option<String>,
}

async fn health() -> &'static str {
    "ok"
}

/// Which port the server actually bound (differs from the request only after
/// a port-fallback). The frontend uses this to locate a fallback server.
async fn server_info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "host": state.bound_host.clone(),
        "port": state.bound_port.load(std::sync::atomic::Ordering::Relaxed)
    }))
}

pub(crate) fn bad_request(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
}

pub(crate) fn internal_error(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": msg })))
}

pub(crate) fn random_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(42)
}

fn validate_common(key_length: usize, base_threshold: f64) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if !(MIN_KEY_LENGTH..=MAX_KEY_LENGTH).contains(&key_length) {
        return Err(bad_request(format!(
            "key_length must be between {MIN_KEY_LENGTH} and {MAX_KEY_LENGTH}"
        )));
    }
    if !(0.0..=1.0).contains(&base_threshold) {
        return Err(bad_request("base_threshold must be between 0.0 and 1.0".into()));
    }
    Ok(())
}

async fn run_handler(
    State(state): State<Arc<AppState>>,
    user: OptionalAuth,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, (StatusCode, Json<serde_json::Value>)> {
    let key_length = req.key_length.unwrap_or(DEFAULT_KEY_LENGTH);
    let base_threshold = req.base_threshold.unwrap_or(DEFAULT_BASE_THRESHOLD);
    let pace_ms = req.pace_ms.unwrap_or(DEFAULT_PACE_MS).min(50);
    let message = req
        .message
        .unwrap_or_else(|| "SIH26141 Sensitive Financial Transaction Data".into());
    if message.len() > MAX_MESSAGE_LEN {
        return Err(bad_request(format!("message must be at most {MAX_MESSAGE_LEN} bytes")));
    }
    validate_common(key_length, base_threshold)?;

    let noise_rate = match req.noise_rate {
        Some(n) if !(0.0..=1.0).contains(&n) => {
            return Err(bad_request("noise_rate must be between 0.0 and 1.0".into()))
        }
        Some(n) => n,
        None => 0.0,
    };
    let relay_hops = match req.relay_hops {
        Some(h) if h > 4 => {
            return Err(bad_request("relay_hops must be at most 4 (demo scope)".into()))
        }
        Some(h) => h,
        None => 0,
    };

    let scenarios: Vec<(&str, f64)> = match req.intercept_ratio {
        Some(r) => {
            if !(0.0..=1.0).contains(&r) {
                return Err(bad_request("intercept_ratio must be between 0.0 and 1.0".into()));
            }
            vec![("custom", r)]
        }
        None => vec![("secure", 0.0), ("attack", 1.0)],
    };

    let run_id = state.run_counter.fetch_add(1, Ordering::SeqCst);
    let seed = req.seed.unwrap_or_else(random_seed);

    let state_clone = Arc::clone(&state);
    let response = tokio::task::spawn_blocking(move || -> Result<RunResponse, String> {
        let mut results = Vec::with_capacity(scenarios.len());
        for (i, (scenario, ratio)) in scenarios.iter().enumerate() {
            let result = execute_scenario_streaming(
                &state_clone.events_tx,
                run_id,
                scenario,
                *ratio,
                noise_rate,
                relay_hops,
                key_length,
                base_threshold,
                Some(&message),
                seed.wrapping_add(i as u64 * 0x9E37_79B9_7F4A_7C15),
                pace_ms,
            )
            .map_err(|e| format!("Scenario '{scenario}' failed: {e}"))?;
            let _ = state_clone
                .events_tx
                .send(Arc::new(RunEvent::Result { run_id, result: result.clone() }));
            results.push(result);
        }
        Ok(RunResponse {
            run_id,
            seed,
            results,
            authenticated_message: Some(message),
        })
    })
    .await
    .map_err(|e| internal_error(format!("Task join failure: {e}")))?
    .map_err(internal_error)?;

    *state.last_result.lock().unwrap() = Some(response.clone());
    // Any authenticated scenario's distilled secret becomes the calling
    // user's document-layer session key (sealing / P2P build on it).
    if let Some(secret) = response.results.iter().find_map(|r| r.derived_secret.clone()) {
        let username = user.0.clone().unwrap_or_else(|| "shared".into());
        doc_api::capture_session_secret(&state, &username, &secret, "qkd-legacy");
    }
    let _ = state.events_tx.send(Arc::new(RunEvent::Done { run_id }));
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
struct SimulateRequest {
    /// Intercept ratios to evaluate, e.g. [0.0, 0.1, 0.5, 1.0].
    intercept_ratios: Vec<f64>,
    key_length: Option<usize>,
    base_threshold: Option<f64>,
    /// Environmental bit-flip probability per link (feature 2).
    noise_rate: Option<f64>,
    /// Relay hops between Alice and Bob (feature 1).
    relay_hops: Option<usize>,
    seed: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SimulateResponse {
    run_id: u64,
    /// The seed actually used (blank seed in the UI = fresh random seed,
    /// echoed here so every chart can be attributed to its randomness).
    seed: u64,
    sweep: Vec<ScenarioResult>,
}

async fn simulate_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let key_length = req.key_length.unwrap_or(DEFAULT_KEY_LENGTH);
    let base_threshold = req.base_threshold.unwrap_or(DEFAULT_BASE_THRESHOLD);
    validate_common(key_length, base_threshold)?;
    let noise_rate = req.noise_rate.unwrap_or(0.0).clamp(0.0, 1.0);
    let relay_hops = req.relay_hops.unwrap_or(0).min(4);
    if req.intercept_ratios.is_empty() {
        return Err(bad_request("intercept_ratios must contain at least one value".into()));
    }
    if req.intercept_ratios.len() > 32 {
        return Err(bad_request("intercept_ratios must contain at most 32 values".into()));
    }
    for &r in &req.intercept_ratios {
        if !(0.0..=1.0).contains(&r) {
            return Err(bad_request("each intercept_ratio must be between 0.0 and 1.0".into()));
        }
    }

    let run_id = state.run_counter.fetch_add(1, Ordering::SeqCst);
    // Blank seed means fresh randomness here too — the dashboard labels the
    // "Seed (blank = random)" input, so a pinned default would make every
    // sweep visually identical. Callers who want reproducibility pass a seed.
    let seed = req.seed.unwrap_or_else(random_seed);

    let response = tokio::task::spawn_blocking(move || -> Result<SimulateResponse, String> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut sweep = Vec::with_capacity(req.intercept_ratios.len());
        for (i, &ratio) in req.intercept_ratios.iter().enumerate() {
            let qkg = QuantumKeyGenerator::new(key_length).map_err(|e| e.to_string())?;
            let keys = qkg.generate_eigenstates(&mut rng);
            let (tx, hop_stats) = if relay_hops > 0 {
                let route = quantum::relay::RelayRoute::new(relay_hops)
                    .with_noise(noise_rate)
                    .with_intercept(ratio);
                let rt = quantum::relay::simulate_relay_transmission(&keys, &route, &mut rng);
                relay_to_sifted(rt)
            } else {
                (
                    quantum::simulate_six_state_transmission_ratio(&keys, ratio, noise_rate, &mut rng),
                    Vec::new(),
                )
            };
            let result = finalize_seeded(
                &format!("sweep-{i}"),
                ratio,
                noise_rate,
                relay_hops,
                hop_stats,
                key_length,
                tx,
                base_threshold,
                None,
                seed,
            )
            .map_err(|e| format!("Sweep point {i} failed: {e}"))?;
            sweep.push(result);
        }
        Ok(SimulateResponse { run_id, seed, sweep })
    })
    .await
    .map_err(|e| internal_error(format!("Task join failure: {e}")))?
    .map_err(internal_error)?;

    Ok(Json(response))
}

#[derive(Debug, Clone, Serialize)]
struct BlindChallengeMeasurement {
    run_id: u64,
    key_length: usize,
    qber: f64,
    dynamic_threshold: f64,
    matching_bases_count: usize,
    mismatches: usize,
    channel_class: String,
    bell_test: Option<BellTestReport>,
}

/// Canonical reveal material includes both the hidden treatment and every
/// measurement returned to the judge. The salt remains server-side until the
/// one-time reveal; the client can then recompute the SHA-256 commitment.
fn blind_commitment_payload(
    treatment: &str,
    noise_percent: u8,
    intercept_percent: u8,
    seed: u64,
    measurement: &BlindChallengeMeasurement,
    salt: &str,
) -> String {
    let bell = measurement.bell_test.as_ref().map(|report| {
        format!(
            "{:016x}:{:016x}:{}:{}:{:016x}:{:016x}",
            report.s.to_bits(),
            report.sigma.to_bits(),
            report.rounds,
            report.certified,
            report.margin_sigma.to_bits(),
            report.visibility.to_bits(),
        )
    }).unwrap_or_else(|| "none".into());
    format!(
        "signiq-blind-challenge-v1|treatment={treatment}|noise={noise_percent}|intercept={intercept_percent}|seed={seed}|run_id={}|key_length={}|qber_bits={:016x}|threshold_bits={:016x}|sifted={}|mismatches={}|class={}|bell={bell}|salt={salt}",
        measurement.run_id,
        measurement.key_length,
        measurement.qber.to_bits(),
        measurement.dynamic_threshold.to_bits(),
        measurement.matching_bases_count,
        measurement.mismatches,
        measurement.channel_class,
    )
}

fn blind_commitment_hash(payload: &str) -> String {
    hex::encode(Sha256::digest(payload.as_bytes()))
}

#[derive(Clone)]
struct BlindChallengeRecord {
    run_id: u64,
    treatment: &'static str,
    explanation: &'static str,
    commitment: String,
    commitment_payload: String,
    noise_rate: f64,
    intercept_ratio: f64,
    seed: u64,
    result: ScenarioResult,
    created_at: Instant,
}

#[derive(Debug, Serialize)]
struct BlindChallengeStartResponse {
    challenge_id: String,
    commitment: String,
    measurement: BlindChallengeMeasurement,
}

#[derive(Debug, Deserialize)]
struct BlindChallengeRevealRequest {
    challenge_id: String,
    guess: String,
}

#[derive(Debug, Serialize)]
struct BlindChallengeRevealResponse {
    correct: bool,
    guess: String,
    treatment: String,
    explanation: String,
    commitment: String,
    commitment_payload: String,
    noise_rate: f64,
    intercept_ratio: f64,
    seed: u64,
    channel_class: String,
    measurement: BlindChallengeMeasurement,
}

/// Start a server-blinded, educational classification round. The server
/// measures one hidden treatment, commits to the treatment/settings/seed and
/// measured outcomes, and returns that commitment with the readout. The salt
/// and canonical payload stay server-side until the one-time reveal; this
/// detects changes after the commitment, not dishonest simulation by the server.
async fn blind_challenge_start(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BlindChallengeStartResponse>, (StatusCode, Json<serde_json::Value>)> {
    const KEY_LENGTH: usize = 12_000;
    const BASE_THRESHOLD: f64 = 0.15;
    const CASES: [(&str, f64, f64, u8, u8, &str); 3] = [
        ("clear", 0.0, 0.0, 0, 0, "No configured environmental noise or Eve interception."),
        ("environmental_noise", 0.08, 0.0, 8, 0, "8% software-modelled environmental bit-flip noise; no Eve interception."),
        ("interception", 0.0, 0.70, 0, 70, "Eve intercepted 70% of simulated qubits; no configured environmental noise."),
    ];

    let mut secret_rng = rand::rngs::OsRng;
    let case_index = secret_rng.gen_range(0..CASES.len());
    let (treatment, noise_rate, intercept_ratio, noise_percent, intercept_percent, explanation) = CASES[case_index];
    let seed = secret_rng.gen_range(0..=2_000_000_000u64);
    let salt = format!("{:016x}{:016x}", secret_rng.next_u64(), secret_rng.next_u64());
    let token = format!("{:016x}{:016x}", secret_rng.next_u64(), secret_rng.next_u64());
    let run_id = state.run_counter.fetch_add(1, Ordering::SeqCst);

    let result = tokio::task::spawn_blocking(move || -> Result<ScenarioResult, String> {
        let mut rng = StdRng::seed_from_u64(seed);
        let qkg = QuantumKeyGenerator::new(KEY_LENGTH).map_err(|e| e.to_string())?;
        let keys = qkg.generate_eigenstates(&mut rng);
        let tx = quantum::simulate_six_state_transmission_ratio(&keys, intercept_ratio, noise_rate, &mut rng);
        finalize_seeded(
            "blind-challenge",
            intercept_ratio,
            noise_rate,
            0,
            Vec::new(),
            KEY_LENGTH,
            tx,
            BASE_THRESHOLD,
            None,
            seed,
        )
    })
    .await
    .map_err(|e| internal_error(format!("Challenge task join failure: {e}")))?
    .map_err(internal_error)?;

    let measurement = BlindChallengeMeasurement {
        run_id,
        key_length: KEY_LENGTH,
        qber: result.mismatch_rate,
        dynamic_threshold: result.dynamic_threshold,
        matching_bases_count: result.matching_bases_count,
        mismatches: result
            .statistical_bounds
            .as_ref()
            .map(|bounds| bounds.interval.k)
            .unwrap_or_else(|| (result.mismatch_rate * result.matching_bases_count as f64).round() as usize),
        channel_class: result.channel_class.clone(),
        bell_test: result.bell_test.clone(),
    };
    let commitment_payload = blind_commitment_payload(
        treatment,
        noise_percent,
        intercept_percent,
        seed,
        &measurement,
        &salt,
    );
    let commitment = blind_commitment_hash(&commitment_payload);

    let now = Instant::now();
    let mut challenges = state.blind_challenges.lock().expect("blind challenge lock poisoned");
    challenges.retain(|_, challenge| now.duration_since(challenge.created_at) < Duration::from_secs(900));
    if challenges.len() >= 100 {
        if let Some(oldest) = challenges.iter().min_by_key(|(_, challenge)| challenge.created_at).map(|(id, _)| id.clone()) {
            challenges.remove(&oldest);
        }
    }
    challenges.insert(
        token.clone(),
        BlindChallengeRecord {
            run_id,
            treatment,
            explanation,
            commitment: commitment.clone(),
            commitment_payload,
            noise_rate,
            intercept_ratio,
            seed,
            result,
            created_at: now,
        },
    );

    Ok(Json(BlindChallengeStartResponse { challenge_id: token, commitment, measurement }))
}

async fn blind_challenge_reveal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BlindChallengeRevealRequest>,
) -> Result<Json<BlindChallengeRevealResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !matches!(req.guess.as_str(), "clear" | "environmental_noise" | "interception") {
        return Err(bad_request("guess must be clear, environmental_noise, or interception".into()));
    }
    let record = state
        .blind_challenges
        .lock()
        .expect("blind challenge lock poisoned")
        .remove(&req.challenge_id)
        .ok_or_else(|| bad_request("challenge expired or was already revealed; start a new round".into()))?;
    let actual_commitment = blind_commitment_hash(&record.commitment_payload);
    if actual_commitment != record.commitment {
        return Err(internal_error("blind challenge commitment did not verify".into()));
    }
    if record.created_at.elapsed() >= Duration::from_secs(900) {
        return Err(bad_request("challenge expired; start a new round".into()));
    }

    let measurement = BlindChallengeMeasurement {
        run_id: record.run_id,
        key_length: record.result.raw_key_length,
        qber: record.result.mismatch_rate,
        dynamic_threshold: record.result.dynamic_threshold,
        matching_bases_count: record.result.matching_bases_count,
        mismatches: record
            .result
            .statistical_bounds
            .as_ref()
            .map(|bounds| bounds.interval.k)
            .unwrap_or_else(|| (record.result.mismatch_rate * record.result.matching_bases_count as f64).round() as usize),
        channel_class: record.result.channel_class.clone(),
        bell_test: record.result.bell_test.clone(),
    };
    Ok(Json(BlindChallengeRevealResponse {
        correct: req.guess == record.treatment,
        guess: req.guess,
        treatment: record.treatment.into(),
        explanation: record.explanation.into(),
        commitment: record.commitment,
        commitment_payload: record.commitment_payload,
        noise_rate: record.noise_rate,
        intercept_ratio: record.intercept_ratio,
        seed: record.seed,
        channel_class: record.result.channel_class,
        measurement,
    }))
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.events_tx.subscribe();
    let replay = state.last_result.lock().unwrap().clone();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(ev) => Some(Ok::<_, std::convert::Infallible>(Event::default().data(
            serde_json::to_string(&*ev).unwrap_or_default(),
        ))),
        Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok::<_, std::convert::Infallible>(
            Event::default().data(format!("{{\"type\":\"lagged\",\"skipped\":{n}}}")),
        )),
    });
    let replay_events = tokio_stream::iter(replay).map(|r| {
        Ok::<_, std::convert::Infallible>(Event::default().data(
            serde_json::to_string(&RunEvent::Result { run_id: r.run_id, result: r.results.last().unwrap().clone() })
                .unwrap_or_default(),
        ))
    });
    Sse::new(tokio_stream::StreamExt::chain(replay_events, stream)).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    )
}

fn format_bytes(n: u64) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod blind_challenge_tests {
    use super::*;

    #[test]
    fn blind_round_commitment_binds_the_hidden_treatment_and_measurements() {
        let measurement = BlindChallengeMeasurement {
            run_id: 7,
            key_length: 12_000,
            qber: 0.08125,
            dynamic_threshold: 0.171,
            matching_bases_count: 4_000,
            mismatches: 325,
            channel_class: "degraded".into(),
            bell_test: Some(BellTestReport {
                s: 2.1,
                sigma: 0.02,
                rounds: 96_000,
                certified: true,
                margin_sigma: 5.0,
                visibility: 0.98,
            }),
        };
        let payload = blind_commitment_payload("environmental_noise", 8, 0, 26141, &measurement, "salt");
        let commitment = blind_commitment_hash(&payload);
        assert_eq!(commitment.len(), 64);
        assert_eq!(commitment, blind_commitment_hash(&payload));
        assert_ne!(
            commitment,
            blind_commitment_hash(&blind_commitment_payload("interception", 0, 70, 26141, &measurement, "salt")),
            "changing the hidden treatment must invalidate the commitment"
        );
        let mut changed_measurement = measurement;
        changed_measurement.mismatches += 1;
        assert_ne!(
            commitment,
            blind_commitment_hash(&blind_commitment_payload("environmental_noise", 8, 0, 26141, &changed_measurement, "salt")),
            "changing any displayed measurement must invalidate the commitment"
        );
    }
}

#[tokio::main]
async fn main() {
    let (events_tx, _) = broadcast::channel(1024);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    // HOST=0.0.0.0 exposes the API on the LAN — required for laptop-to-laptop
    // P2P document transfer; loopback remains the safe default.
    let host: std::net::IpAddr = std::env::var("HOST")
        .ok()
        .and_then(|h| h.parse().ok())
        .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
    let host_string = host.to_string();

    // Serve the built frontend when present (frontend/dist), else API-only.
    let static_dir = std::env::var("FRONTEND_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../frontend/dist")
        });

    // Persistent QDS security-event log next to the executable's workspace.
    let qds_log_path = std::env::var("QDS_EVENT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("qds_events.jsonl"));
    let qds_state = QdsStateHolder::new(qds_log_path.clone());
    // Report on the persisted QDS event log (kept append-only; the in-memory
    // event ring always starts fresh, but disk history stays readable).
    match std::fs::metadata(&qds_log_path) {
        Ok(m) => eprintln!(
            "qds event log: {} at {} (append-only, history preserved)",
            format_bytes(m.len()),
            qds_log_path.display()
        ),
        Err(_) => eprintln!("qds event log: none yet — will be created on first event"),
    }

    let audit_log_path = std::env::var("AUDIT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("audit_log.jsonl"));
    // Reload the persisted audit ledger so the Merkle chain (and its
    // non-repudiation story) survives process restarts.
    let (reloaded_log, skipped_lines) = match audit::AuditLog::load_jsonl(&audit_log_path) {
        Ok((log, skipped)) => (log, skipped),
        Err(e) => {
            eprintln!("warning: audit log reload failed ({e}) — starting with an empty ledger");
            (audit::AuditLog::new(), 0)
        }
    };
    let audit_entries = reloaded_log.len();
    let audit_chain_ok = reloaded_log.verify_chain().ok;

    // Per-user accounts (multi-user website). users.json survives restarts;
    // bearer-token sessions are memory-only by design.
    let users_path = std::env::var("USERS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("users.json"));
    let auth_state = Arc::new(AuthState::load(users_path));
    eprintln!("accounts: {} registered user(s)", auth_state.user_count());

    // The developer token enabling /api/audit/clear (ledger reset). When the
    // env var is absent the endpoint is permanently disabled on this server.
    let dev_token = std::env::var("DEVELOPER_TOKEN").ok().filter(|t| !t.trim().is_empty());
    let doc_state = DocStateHolder::from_log(
        reloaded_log,
        audit_log_path,
        Arc::clone(&auth_state),
        dev_token,
    );
    eprintln!(
        "audit ledger: {audit_entries} entr{} restored ({}); chain {}",
        if audit_entries == 1 { "y" } else { "ies" },
        if skipped_lines > 0 {
            format!("{skipped_lines} malformed line(s) skipped")
        } else {
            "no malformed lines".to_string()
        },
        if audit_chain_ok { "intact" } else { "BROKEN — persisted history was altered" },
    );

    let state = Arc::new(AppState {
        events_tx,
        last_result: Mutex::new(None),
        run_counter: AtomicU64::new(1),
        qds: Mutex::new(qds_state),
        qds_log_path,
        doc: doc_state,
        blind_challenges: Mutex::new(HashMap::new()),
        // Patched once the listener is bound (fallback may change it).
        bound_port: std::sync::atomic::AtomicU16::new(port),
        bound_host: host_string,
    });

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/server-info", get(server_info))
        .route("/api/run", post(run_handler))
        .route("/api/simulate", post(simulate_handler))
        .route("/api/blind-challenge/start", post(blind_challenge_start))
        .route("/api/blind-challenge/reveal", post(blind_challenge_reveal))
        .layer(axum::extract::DefaultBodyLimit::max(12 * 1024 * 1024))
        .route("/api/events", get(sse_handler))
        .merge(qds_router())
        .merge(doc_router())
        .layer(CorsLayer::permissive())
        .with_state(Arc::clone(&state));

    let app = if static_dir.join("index.html").exists() {
        app.fallback_service(
            tower_http::services::ServeDir::new(&static_dir)
                .append_index_html_on_directories(true),
        )
    } else {
        eprintln!("Note: no frontend build at {} — API-only mode.", static_dir.display());
        app
    };

    // Bind with a clear error message and, on Windows, a fallback: OS error
    // 10013 (PermissionDenied) happens when another process holds the port
    // OR when Windows excluded port ranges (Hyper-V / WinNAT reservations)
    // block it entirely — common right after a reboot. Fall back to the next
    // few ports so a demo never dies on a stale reservation.
    let addr = SocketAddr::from((host, port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            const MAX_FALLBACKS: u16 = 10;
            eprintln!(
                "warning: could not bind {addr} (os error 10013 — port held by another process or blocked by a Windows reserved port range)"
            );
            let mut bound = None;
            for offset in 1..=MAX_FALLBACKS {
                let candidate = SocketAddr::from((host, port + offset));
                match tokio::net::TcpListener::bind(candidate).await {
                    Ok(l) => {
                        eprintln!("falling back to {candidate}");
                        bound = Some(l);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            bound.unwrap_or_else(|| {
                panic!(
                    "failed to bind port {port} or any of the next {MAX_FALLBACKS} ports — free the port (netstat -ano | findstr {port}) or pick another: PORT=<port> cargo run -p server"
                )
            })
        }
        Err(e) => panic!("failed to bind port {port}: {e}"),
    };

    let bound_addr = listener.local_addr().expect("listener has a local address");
    state.bound_port.store(bound_addr.port(), std::sync::atomic::Ordering::Relaxed);
    if bound_addr.port() != port {
        // Publish the actual bound port so the dashboard can find the API
        // even after a fallback: the frontend probes /server-port.json
        // (served as a static asset from frontend/dist) when its same-origin
        // health check fails.
        let manifest = serde_json::json!({
            "requested_port": port,
            "actual_port": bound_addr.port(),
            "reason": "requested port unavailable (held by another process or blocked by a Windows reserved port range)"
        });
        let port_file = static_dir.join("server-port.json");
        match std::fs::write(&port_file, manifest.to_string()) {
            Ok(()) => eprintln!(
                "NOTE: serving on http://{bound_addr} instead of http://127.0.0.1:{port} — wrote {}",
                port_file.display()
            ),
            Err(e) => eprintln!(
                "NOTE: serving on http://{bound_addr}; could not write port manifest ({e}) — open this URL manually"
            ),
        }
    } else {
        // Clean up any stale manifest from a previous fallback run.
        let _ = std::fs::remove_file(static_dir.join("server-port.json"));
    }
    eprintln!("SIH26141 API server listening on http://{bound_addr}");
    eprintln!("Frontend: {}", static_dir.display());

    axum::serve(listener, app).await.expect("server error");
}
