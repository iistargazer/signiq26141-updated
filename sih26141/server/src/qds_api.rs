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
    attempt_unauthorized_verification,
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

    *holder.last_signature.lock().unwrap() = Some((sig, teleports, req.message.clone()));

    Ok(Json(QdsSignResponse {
        nonce,
        signature_hex,
        teleport_sample: sample,
        qubit_count,
        lambda,
        theory_forgery_probability: theory,
        initial_verification_accepted: initial.report.accepted,
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

        // Channel tampering: genuine correction bits, disturbed channel — use
        // a fresh nonce so the nonce check isn't the reason for rejection.
        let mut sig = tamper.signature.clone();
        sig.nonce = holder.inner.trent.lock().unwrap().issue_nonce();
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
}
