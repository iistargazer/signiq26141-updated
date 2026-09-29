//! QDS API handlers: signature-lab endpoints over the shared QdsState.

use crate::qds_state::{run_attack, run_verify, QdsOutcome, QdsState};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

use qds::attacks::{
    attempt_channel_tampering, attempt_forgery, attempt_impersonation, attempt_replay,
    attempt_timestamp_forgery, attempt_unauthorized_verification,
};

/// Wrapper stored in AppState (avoids generic-state plumbing in handlers).
pub struct QdsStateHolder {
    pub inner: QdsState,
    pub last_signature: Mutex<Option<(qds::QuantumSignature, Vec<qds::TeleportResult>, String)>>,
}

impl QdsStateHolder {
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            inner: QdsState::new(16, 4, log_path),
            last_signature: Mutex::new(None),
        }
    }
}

type AppError = (StatusCode, Json<serde_json::Value>);
type AppState = crate::AppState;

fn bad_request(msg: String) -> AppError {
    crate::bad_request(msg)
}

#[derive(Debug, Deserialize)]
pub struct QdsSetupRequest {
    /// Signature qubits (message-hash bits used per signature).
    qubit_count: Option<usize>,
    /// Bell-pair depth per qubit (security multiplier).
    lambda: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct QdsSetupResponse {
    pub qubit_count: usize,
    pub lambda: usize,
    pub key_commitment: String,
    pub theory_forgery_probability: f64,
}

pub async fn qds_setup(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<QdsSetupRequest>,
) -> Result<Json<QdsSetupResponse>, AppError> {
    let qubit_count = req.qubit_count.unwrap_or(16);
    let lambda = req.lambda.unwrap_or(4);
    if !(4..=128).contains(&qubit_count) {
        return Err(bad_request("qubit_count must be between 4 and 128".into()));
    }
    if !(1..=16).contains(&lambda) {
        return Err(bad_request("lambda must be between 1 and 16".into()));
    }

    let mut holder = state.qds.lock().unwrap();
    holder.inner = QdsState::new(qubit_count, lambda, state.qds_log_path.clone());
    *holder.last_signature.lock().unwrap() = None;
    let pk = holder.inner.trent.lock().unwrap().public_key().clone();
    holder.inner.record(
        "setup",
        "key-generation",
        true,
        format!("Trent initialized {qubit_count} qubits x lambda={lambda}; key commitment published"),
    );
    Ok(Json(QdsSetupResponse {
        qubit_count: pk.qubit_count,
        lambda: pk.lambda,
        key_commitment: pk.correlation_commitment,
        theory_forgery_probability: qds::theory_forgery_probability(qubit_count, lambda),
    }))
}

#[derive(Debug, Deserialize)]
pub struct QdsSignRequest {
    message: String,
    seed: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct TeleportSample {
    pub position: usize,
    pub bell_outcome: u8,
    pub correction: String,
    pub raw_bit: u8,
    pub corrected_bit: u8,
}

#[derive(Debug, Serialize)]
pub struct QdsSignResponse {
    pub nonce: u64,
    /// The published signature bits (x,z pairs), hex-encoded.
    pub signature_hex: String,
    /// First few teleportation records for the UI.
    pub teleport_sample: Vec<TeleportSample>,
    pub qubit_count: usize,
    pub lambda: usize,
    pub theory_forgery_probability: f64,
    /// Result of Bob's initial verification at delivery time. The nonce is
    /// consumed by this acceptance, so any re-presentation later is a replay.
    pub initial_verification_accepted: bool,
    /// The signature's quantum-entropy timestamp binding (Feature 2), for
    /// dashboard display: window number, chain-link and tag prefixes.
    pub temporal: Option<TemporalBindingView>,
}

/// A display-friendly view of the temporal binding (no secrets — the tag
/// and chain are public commitments; prefixes only, to keep the payload
/// light while remaining verifiable-looking).
#[derive(Debug, Clone, Serialize)]
pub struct TemporalBindingView {
    pub window: u64,
    pub unix_ms: u64,
    pub entropy_prefix: String,
    pub chain_prefix: String,
    pub tag_prefix: String,
    pub valid_until_window: u64,
}

pub async fn qds_sign(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<QdsSignRequest>,
) -> Result<Json<QdsSignResponse>, AppError> {
    if req.message.is_empty() || req.message.len() > 2048 {
        return Err(bad_request("message must be 1..2048 bytes".into()));
    }
    let holder = state.qds.lock().unwrap();
    let mut trent = holder.inner.trent.lock().unwrap();
    let mut rng = match req.seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    let (sig, teleports) = qds::sign(req.message.as_bytes(), &mut trent, &mut rng);
    drop(trent);

    let (qubit_count, lambda) = {
        let t = holder.inner.trent.lock().unwrap();
        let pk = t.public_key();
        (pk.qubit_count, pk.lambda)
    };
    let theory = qds::theory_forgery_probability(qubit_count, lambda);

    let sample = teleports
        .iter()
        .take(6)
        .enumerate()
        .map(|(i, t)| TeleportSample {
            position: i,
            bell_outcome: t.outcome.0,
            correction: t.outcome.correction().as_str().to_string(),
            raw_bit: t.pre_correction_bit,
            corrected_bit: t.corrected_bit,
        })
        .collect();
    let signature_hex = hex::encode(&sig.correction_bits);
    let nonce = sig.nonce;

    holder.inner.record(
        "sign",
        "alice",
        true,
        format!(
            "signed message ({} chars) with nonce {nonce}; {} signature bits",
            &req.message.len(),
            sig.correction_bits.len()
        ),
    );

    // Simulate honest delivery: Bob verifies and accepts once. This consumes
    // the nonce, so the replay attack below is detected as a true replay.
    let sig_for_verify = sig.clone();
    let initial = run_verify(
        &holder.inner,
        "bob",
        "verify",
        req.message.as_bytes(),
        &sig_for_verify,
        "Bob's initial verification of the delivered signature.".into(),
    );
    // Signing advanced the notary's quantum clock (window N minted) and the
    // acceptance consumed it — persist the replay-trap memory.
    holder.inner.persist_replay_state();

    *holder.last_signature.lock().unwrap() = Some((sig, teleports, req.message.clone()));

    let temporal_view = sig_for_verify
        .temporal
        .as_ref()
        .map(|b| TemporalBindingView {
            window: b.issued.window,
            unix_ms: b.issued.unix_ms,
            entropy_prefix: b.issued.entropy_hex.chars().take(12).collect(),
            chain_prefix: b.issued.chain_hex.chars().take(12).collect(),
            tag_prefix: b.signature_tag_hex.chars().take(12).collect(),
            valid_until_window: b.valid_until_window,
        });

    Ok(Json(QdsSignResponse {
        nonce,
        signature_hex,
        teleport_sample: sample,
        qubit_count,
        lambda,
        theory_forgery_probability: theory,
        initial_verification_accepted: initial.report.accepted,
        temporal: temporal_view,
    }))
}

#[derive(Debug, Deserialize)]
pub struct QdsVerifyRequest {
    message: String,
    signature_hex: String,
    nonce: u64,
}

pub async fn qds_verify(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<QdsVerifyRequest>,
) -> Result<Json<QdsOutcome>, AppError> {
    let bits = hex::decode(&req.signature_hex)
        .map_err(|_| bad_request("signature_hex is not valid hex".into()))?;
    let commitment = {
        let holder = state.qds.lock().unwrap();
        let commitment = holder.inner.trent.lock().unwrap().public_key().correlation_commitment.clone();
        commitment
    };
    let sig = qds::QuantumSignature {
        correction_bits: bits,
        nonce: req.nonce,
        key_commitment: commitment,
        // Manual submissions carry no temporal binding — the trap classifies
        // them as pre-trap signatures and rejects. (The UI's genuine path
        // goes through /api/qds/sign, which mints a full binding.)
        temporal: None,
    };
    let holder = state.qds.lock().unwrap();
    Ok(Json(run_verify(
        &holder.inner,
        "manual",
        "verify",
        req.message.as_bytes(),
        &sig,
        "Manual verification of a supplied signature.".into(),
    )))
}

/// Runs all five attacks against the last genuine signature.
pub async fn qds_attacks(
    State(state): State<std::sync::Arc<AppState>>,
    raw: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<QdsOutcome>>, AppError> {
    let last = {
        let holder = state.qds.lock().unwrap();
        let last_opt = holder.last_signature.lock().unwrap().clone();
        last_opt
    };
    // `teleports` is no longer needed here: channel tampering now disturbs
    // the genuine signature bits directly (see attempt_channel_tampering).
    let (genuine, _teleports, message) = last.ok_or_else(|| {
        bad_request("no signature on file yet — sign a message first (POST /api/qds/sign)".into())
    })?;

    // Optional tamper-fraction control for the channel-tampering scenario
    // (?tamper_fraction=0.5 default; 0.0–1.0).
    let tamper_fraction = raw
        .get("tamper_fraction")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(qds::attacks::DEFAULT_TAMPER_FRACTION)
        .clamp(0.0, 1.0);

    let target: &[u8] = b"FORGED: attacker-chosen payload";
    let message_bytes = message.as_bytes();
    let mut rng = StdRng::from_entropy();

    let outcomes = {
        let holder = state.qds.lock().unwrap();
        let forgery = attempt_forgery(target, &mut holder.inner.trent.lock().unwrap(), &mut rng);
        let mut impersonation = attempt_impersonation(&genuine, &message_bytes, target);
        let replay = attempt_replay(&genuine, message_bytes);
        let tamper = attempt_channel_tampering(
            &genuine,
            tamper_fraction,
            message_bytes,
            &holder.inner.trent.lock().unwrap(),
            &mut rng,
        );
        let mut unauthorized =
            attempt_unauthorized_verification(&genuine, message_bytes, target);

        // Bob's initial verification at sign time consumed the genuine nonce,
        // so impersonation and unauthorized re-presentations would otherwise
        // be rejected as REPLAYS (nonce check fires before statistics) and
        // their real attack statistics — message-binding mismatch ~50% for a
        // transplant — would never be shown. Fresh nonces route them through
        // the statistics path; replay alone keeps the consumed nonce on
        // purpose (nonce reuse IS the replay attack).
        impersonation.signature.nonce = holder.inner.trent.lock().unwrap().issue_nonce();
        unauthorized.signature.nonce = holder.inner.trent.lock().unwrap().issue_nonce();

        let mut outcomes = Vec::with_capacity(5);
        outcomes.push(run_attack(&holder.inner, forgery, target));
        outcomes.push(run_attack(&holder.inner, impersonation, target));
        outcomes.push(run_attack(&holder.inner, replay, message_bytes));

        // Channel tampering: genuine correction bits, disturbed channel — a
        // fresh SESSION (advancing the notary's quantum clock to an
        // unconsumed window) plus a notary re-binding of the RECEIVED bits
        // (the honest noisy-delivery path) so the run demonstrates the
        // proportional measurement statistics rather than tripping the
        // temporal trap's sequence check.
        let mut sig = tamper.signature.clone();
        {
            let mut trent = holder.inner.trent.lock().unwrap();
            let mut rng2 = StdRng::from_entropy();
            let _fresh = qds::sign(message_bytes, &mut trent, &mut rng2);
            sig.nonce = trent.issue_nonce();
            sig.temporal = Some(trent.mint_temporal_for(&sig.correction_bits, sig.nonce));
        }
        outcomes.push(run_verify(
            &holder.inner,
            "attack",
            "channel_tampering",
            message_bytes,
            &sig,
            format!("{} ({:.0}% fraction)", tamper.description, tamper_fraction * 100.0),
        ));

        // Unauthorized verification: flagged as its own threat class even
        // though the captured signature itself would fail statistics anyway.
        let description = unauthorized.description.clone();
        let mut uo = run_attack(&holder.inner, unauthorized, target);
        // Annotate: the unauthorized party's verdict would be untrustworthy
        // — the attempt itself is the event we log for the dashboard.
        uo.description = description;
        outcomes.push(uo);

        // Timestamp forgery (Feature 2's dedicated attack): a fabricated
        // far-future quantum-entropy timestamp with a forged hash-chain
        // link — the temporal trap's chain check rejects it.
        let ts_forgery = attempt_timestamp_forgery(
            &mut holder.inner.trent.lock().unwrap(),
            target,
            &mut rng,
        );
        outcomes.push(run_attack(&holder.inner, ts_forgery, target));
        outcomes
    };
    Ok(Json(outcomes))
}

#[derive(Debug, Serialize)]
pub struct LambdaPoint {
    pub lambda: usize,
    pub theory: f64,
}

#[derive(Debug, Serialize)]
pub struct ForgeryAnalysis {
    pub qubit_count: usize,
    pub lambda: usize,
    pub trials: usize,
    pub monte_carlo_probability: f64,
    pub theory_probability: f64,
    /// Whole-signature forgery probability per lambda (log-scale chart).
    pub by_lambda: Vec<LambdaPoint>,
}

pub async fn qds_forgery_analysis(
    State(_state): State<std::sync::Arc<AppState>>,
) -> Json<ForgeryAnalysis> {
    let (qubit_count, lambda) = (8usize, 1usize); // small params so MC is meaningful
    let mut rng = StdRng::from_entropy();
    let trials = 20_000usize;
    let mc = qds::estimate_forgery_probability((qubit_count, lambda), trials, &mut rng);
    let by_lambda = (1..=8)
        .map(|l| LambdaPoint {
            lambda: l,
            theory: qds::theory_forgery_probability(qubit_count, l),
        })
        .collect();

    Json(ForgeryAnalysis {
        qubit_count,
        lambda,
        trials,
        monte_carlo_probability: mc,
        theory_probability: qds::theory_forgery_probability(qubit_count, lambda),
        by_lambda,
    })
}

pub async fn qds_events(
    State(state): State<std::sync::Arc<AppState>>,
) -> Json<serde_json::Value> {
    let holder = state.qds.lock().unwrap();
    let events = holder.inner.recent(100);
    Json(serde_json::json!({ "events": events }))
}

// ---------------------------------------------------------------------------
// Performance evaluation endpoint (Lap 2 evaluation deliverable)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct QdsMetricsRequest {
    /// Legitimate+attack cycles per scheme (statistical sample size).
    trials: Option<usize>,
    /// Seed for reproducible evaluation runs.
    seed: Option<u64>,
}

/// Run the repeatable performance/security evaluation and return the full
/// report: verification accuracy, detection rates, false alarms, forgery
/// probability, and per-operation timings for both QDS schemes.
pub async fn qds_metrics(
    State(state): State<std::sync::Arc<AppState>>,
    raw: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trials = raw
        .get("trials")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(50, 2_000);
    let seed = raw
        .get("seed")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(42);

    // CPU-bound: run off the async reactor. Hold no locks during the run.
    let report = tokio::task::spawn_blocking(move || qds::metrics::evaluate(trials, seed))
        .await
        .map_err(|e| internal_error(format!("Evaluation task join failure: {e}")))?;

    {
        let holder = state.qds.lock().unwrap();
        holder.inner.record(
            "metrics",
            "evaluation",
            true,
            format!(
                "performance evaluation over {trials} trials (seed {seed}): teleport accuracy {:.4}, six-state accuracy {:.4}",
                report.teleport.confusion.accuracy(),
                report.six_state.confusion.accuracy()
            ),
        );
    }
    Ok(Json(serde_json::to_value(&report).unwrap_or_default()))
}

fn internal_error(msg: String) -> AppError {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": msg })))
}

/// Build the QDS sub-router.
pub fn qds_router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/api/qds/setup", post(qds_setup))
        .route("/api/qds/sign", post(qds_sign))
        .route("/api/qds/verify", post(qds_verify))
        .route("/api/qds/attacks", get(qds_attacks))
        .route("/api/qds/forgery-analysis", get(qds_forgery_analysis))
        .route("/api/qds/metrics", get(qds_metrics))
        .route("/api/qds/events", get(qds_events))
        // Feature 3 — Chernoff–Hoeffding statistical confidence engine.
        .route("/api/stats/bounds", get(bounds_endpoint))
        // Feature 4 — multi-receiver consensus verification ring.
        .route("/api/qds/consensus-ring", post(consensus_ring))
}

/// Feature 3 — the statistical confidence dossier for an observed sample.
/// `?k=150&n=1000&threshold=0.15&noise=0.02&delta=0.01` returns the exact
/// binomial p-value, both concentration bounds, and the N-scaling threshold
/// curve the visualizer plots.
#[derive(Debug, serde::Serialize)]
pub struct BoundsResponse {
    pub interval: detection::bounds::ConfidenceInterval,
    pub curve: Vec<detection::bounds::ThresholdPoint>,
    pub verdict: detection::bounds::VerdictConfidence,
    pub chernoff_gain: f64,
}

pub async fn bounds_endpoint(
    raw: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<BoundsResponse>, AppError> {
    let k = raw
        .get("k")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(150);
    let n = raw
        .get("n")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1000)
        .clamp(1, 2_000_000);
    let threshold = raw
        .get("threshold")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.15)
        .clamp(0.0, 1.0);
    let noise_floor = raw
        .get("noise")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.02)
        .clamp(0.0, 1.0);
    let delta = raw
        .get("delta")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.01)
        .clamp(1e-9, 0.5);
    let k = k.min(n);
    let report = detection::bounds::bounds_report(k, n, noise_floor, delta, threshold);
    Ok(Json(BoundsResponse {
        interval: report.interval,
        curve: report.curve,
        verdict: report.verdict,
        chernoff_gain: report.chernoff_gain,
    }))
}

/// Feature 4 — run the multi-receiver consensus verification ring against
/// the last genuine signature (or one supplied in the body). Each member's
/// channel noise is an independent draw; a heavily-attacked member index
/// can be injected to show quorum tolerance.
#[derive(Debug, Deserialize)]
pub struct RingRequest {
    /// k of m required for unlock (default 3 of 5).
    pub k: Option<usize>,
    pub m: Option<usize>,
    /// Member identities (user account names). Defaults to the classic
    /// Bob/Charlie/Dave ring.
    pub members: Option<Vec<String>>,
    /// Index of a member whose channel is under attack (None = all honest).
    pub attacked_member: Option<usize>,
    /// Noise rate on the attacked member's channel (default 0.35).
    pub attack_noise: Option<f64>,
    /// Per-verifier gray-zone ceiling c2 (default 0.10).
    pub tolerance: Option<f64>,
    /// Optional RNG seed for reproducible demos.
    pub seed: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RingResponse {
    pub verdict: qds::consensus::RingVerdict,
}

pub async fn consensus_ring(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<RingRequest>,
) -> Result<Json<RingResponse>, AppError> {
    let (genuine, _teleports, message) = {
        let holder = state.qds.lock().unwrap();
        let last = holder.last_signature.lock().unwrap().clone();
        last.ok_or_else(|| {
            bad_request("no signature on file — sign first (POST /api/qds/sign)".into())
        })?
    };
    let k = req.k.unwrap_or(3).clamp(1, 32);
    let m = req.m.unwrap_or(5).clamp(1, 32);
    if req.k.is_some() && req.k.unwrap() > m {
        return Err(bad_request("k cannot exceed m".into()));
    }
    let member_names: Vec<String> = match req.members {
        Some(v) if v.len() == m => v,
        Some(v) if v.len() < m => {
            return Err(bad_request(format!(
                "{} member names given for a ring of {m}",
                v.len()
            )))
        }
        _ => (0..m)
            .map(|i| {
                [
                    "bob", "charlie", "dave", "erin", "frank", "grace", "heidi", "ivan",
                ]
                .get(i)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("receiver-{i}"))
            })
            .collect(),
    };
    let name_refs: Vec<&str> = member_names.iter().map(|s| s.as_str()).collect();
    let config = qds::consensus::RingConfig {
        k,
        m,
        noise_floor: 0.0,
        attacked_member: req.attacked_member,
        attack_noise: req.attack_noise.unwrap_or(0.35).clamp(0.0, 1.0),
    };
    let mut rng = match req.seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    let message_bytes = message.as_bytes();
    let holder = state.qds.lock().unwrap();
    let mut trent = holder.inner.trent.lock().unwrap();
    let verdict = qds::consensus::run_ring(
        message_bytes,
        &genuine,
        &mut trent,
        &config,
        req.tolerance.unwrap_or(0.10).clamp(0.0, 1.0),
        &mut rng,
        &name_refs,
    );
    let note = verdict.note.clone();
    let ok = verdict.quorum_ok;
    holder.inner.record(
        "verify",
        "consensus-ring",
        ok,
        format!("{note} — {k} of {m} required"),
    );
    Ok(Json(RingResponse { verdict }))
}
