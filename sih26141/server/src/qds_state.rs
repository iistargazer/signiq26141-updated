//! Shared QDS session state for the server: one Trent notary instance plus
//! a persistent security-event log (deliverable 6: "Logging of security
//! events"). Events are appended as JSONL so they survive restarts and can
//! be audited offline.

use qds::{AttackAttempt, Trent, VerificationReport};
use rand::SeedableRng;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct QdsEvent {
    pub ts: String,
    pub kind: String, // "sign" | "verify" | "attack" | "setup"
    pub label: String,
    pub accepted: bool,
    pub detail: String,
}

pub struct QdsState {
    pub trent: Mutex<Trent>,
    pub log_path: PathBuf,
    pub log: Mutex<Vec<QdsEvent>>,
}

impl QdsState {
    /// `TRENT_SEED`, if set, pins the notary's correlation tables so every
    /// laptop running with the SAME seed derives the SAME Trent — a
    /// signature made on laptop A then verifies on laptop B. Unset → fresh
    /// entropy (single-server deployments never need to match another Trent).
    pub fn new(qubit_count: usize, lambda: usize, log_path: PathBuf) -> Self {
        let trent = match std::env::var("TRENT_SEED")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            Some(seed) => {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
                Trent::setup(qubit_count, lambda, &mut rng)
            }
            None => {
                let mut rng = rand::rngs::StdRng::from_entropy();
                Trent::setup(qubit_count, lambda, &mut rng)
            }
        };
        Self {
            trent: Mutex::new(trent),
            log_path,
            log: Mutex::new(Vec::new()),
        }
    }

    /// Append an event to the in-memory log and the JSONL file (best-effort).
    pub fn record(&self, kind: &str, label: &str, accepted: bool, detail: String) {
        let ev = QdsEvent {
            ts: chrono_now(),
            kind: kind.to_string(),
            label: label.to_string(),
            accepted,
            detail,
        };
        if let Ok(mut log) = self.log.lock() {
            log.push(ev.clone());
            if log.len() > 500 {
                let excess = log.len() - 500;
                log.drain(0..excess);
            }
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            let _ = writeln!(f, "{}", serde_json::to_string(&ev).unwrap_or_default());
        }
    }

    pub fn recent(&self, n: usize) -> Vec<QdsEvent> {
        self.log.lock().map(|l| l.iter().rev().take(n).cloned().collect()).unwrap_or_default()
    }
}

pub fn chrono_now() -> String {
    // RFC3339-ish local timestamp without pulling chrono; good enough for logs.
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let millis = d.subsec_millis();
    // Convert epoch to UTC date-time (civil-from-days algorithm).
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d_ = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d_:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Outcome payload for one QDS API scenario.
#[derive(Debug, Serialize)]
pub struct QdsOutcome {
    pub label: String,
    pub kind: String,
    pub report: VerificationReport,
    pub description: String,
    pub claimed_message: String,
    /// Second-verifier consensus (transferability, Gottesman–Chuang criterion 2).
    /// None for checks that are not full verifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charlie_agrees: Option<bool>,
}

/// Helper: run a verify against the shared Trent, record the event, and
/// build the API outcome. Includes Charlie's transferability consensus.
pub fn run_verify(
    state: &QdsState,
    label: &str,
    kind: &str,
    message: &[u8],
    signature: &qds::QuantumSignature,
    description: String,
) -> QdsOutcome {
    let mut trent = state.trent.lock().unwrap();
    let report = qds::verify(message, signature, &mut trent, 0.0);
    // Charlie consensus only meaningful when the signature was locally valid.
    let charlie = if report.accepted {
        let c = qds::verify_transferability(message, signature, &mut trent, 0.10);
        Some(c.accepted)
    } else {
        None
    };
    state.record(
        "verify",
        &format!("{label} [{kind}]"),
        report.accepted,
        format!(
            "{:?} — {} mismatches across {} positions — {}{}",
            report.verdict,
            report.mismatches,
            report.total_positions,
            report.reason,
            charlie.map(|ag| format!(" [Charlie consensus: {ag}]")).unwrap_or_default()
        ),
    );
    QdsOutcome {
        label: label.to_string(),
        kind: kind.to_string(),
        report,
        description,
        claimed_message: String::from_utf8_lossy(message).into_owned(),
        charlie_agrees: charlie,
    }
}

/// Helper for attack attempts produced by the attack module.
pub fn run_attack(
    state: &QdsState,
    attempt: AttackAttempt,
    message: &[u8],
) -> QdsOutcome {
    let kind_str = match attempt.kind {
        qds::AttackKind::Forgery => "forgery",
        qds::AttackKind::Impersonation => "impersonation",
        qds::AttackKind::Replay => "replay",
        qds::AttackKind::ChannelTampering => "channel_tampering",
        qds::AttackKind::UnauthorizedVerification => "unauthorized_verification",
    };
    run_verify(state, "attack", kind_str, message, &attempt.signature, attempt.description)
}
