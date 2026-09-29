//! Device-independent channel certification via the CHSH Bell test.
//!
//! **Scope.** This module samples synthetic outcome pairs from an idealized
//! CHSH correlation formula. It is a classical Monte-Carlo diagnostic used
//! to illustrate a threshold, not a simulation of detector hardware, a
//! loophole-free Bell experiment, or a device-independent security proof.
//! The theoretical CHSH bounds (classical 2 and Tsirelson 2√2) motivate the
//! displayed model, but a model-generated pass is not physical certification.
//!
//! **The model.** Pairs are produced in |Φ+⟩. Alice measures at angles
//! a₀ = 0°, a₁ = 45°; Bob at b₀ = 22.5°, b₁ = 67.5° — the canonical CHSH
//! geometry. Outcome pairs are sampled with P(same sign) = (1+E)/2 where
//! E(θa,θb) = cos(2(θa−θb)) is the quantum correlation of |Φ+⟩, giving
//! S = E(a₀,b₀) − E(a₀,b₁) + E(a₁,b₀) + E(a₁,b₁) = 2√2 in the honest limit.
//!
//! **Attack parameter.** The configured fraction blends the synthetic
//! correlation model with a more weakly correlated distribution. This is a
//! visualization assumption, not a physically derived interception channel.
//! The `certified()` helper is kept for API compatibility and means only that
//! this synthetic sample exceeded the selected model threshold.

use rand::Rng;

/// Canonical CHSH measurement angles (radians) for |Φ+⟩.
const A0: f64 = 0.0;
const A1: f64 = std::f64::consts::FRAC_PI_4; // 45°
const B0: f64 = std::f64::consts::FRAC_PI_8; // 22.5°
const B1: f64 = 3.0 * std::f64::consts::FRAC_PI_8; // 67.5°

/// Quantum correlation of |Φ+⟩ for analyzer angle difference θ.
fn quantum_correlation(theta: f64) -> f64 {
    (2.0 * theta).cos()
}

/// One outcome pair: A uniform ±1, B aligned with A with probability
/// p = (1 + E)/2 — the standard sampling of a two-outcome correlation.
fn sample_pair(e: f64, rng: &mut impl Rng) -> (i8, i8) {
    let a: i8 = if rng.gen_bool(0.5) { 1 } else { -1 };
    let b = if rng.gen_bool((1.0 + e) / 2.0) { a } else { -a };
    (a, b)
}

/// Result of one synthetic CHSH diagnostic campaign.
#[derive(Debug, Clone)]
pub struct ChshResult {
    /// The measured CHSH value, S = E(a₀,b₀) − E(a₀,b₁) + E(a₁,b₀) + E(a₁,b₁).
    pub s: f64,
    /// Standard error of S from the finite sample count.
    pub sigma: f64,
    /// Number of entangled pairs used.
    pub rounds: usize,
    /// Fraction of pairs Eve intercepted (diagnostic echo of the input).
    pub attack_fraction: f64,
    /// True (noiseless-model) quantum violation the channel should show.
    pub tsirelson: f64,
    /// Channel visibility V = 1 − 2·noise (fraction of quantum correlation
    /// surviving the noisy channel). S scales with V: even without Eve,
    /// noise above ~14.6% erases the violation.
    pub visibility: f64,
}

impl ChshResult {
    /// Tsirelson's bound, 2√2 — the hard ceiling for quantum correlations.
    pub const TSIRELSON: f64 = std::f64::consts::SQRT_2 * 2.0;
    /// The classical (local hidden variable) ceiling — Bell's theorem.
    pub const CLASSICAL: f64 = 2.0;

    /// Model-relative threshold only: the synthetic sample's S clears 2 by
    /// 3 estimated standard errors. This is not physical certification.
    pub fn certified(&self) -> bool {
        self.s > Self::CLASSICAL + 3.0 * self.sigma
    }

    /// Margin over the classical bound in units of σ (can be negative).
    pub fn margin_sigma(&self) -> f64 {
        (self.s - Self::CLASSICAL) / self.sigma.max(1e-12)
    }
}

/// Run `rounds` entangled-pair measurements with Eve intercepting a fraction
/// `attack_fraction` of Bob's photons (measuring in a random basis of her
/// own, re-preparing, forwarding). Returns the measured CHSH statistics.
///
/// Clean model (`attack_fraction` = 0): S is sampled near 2√2.
/// Increasing the attack fraction blends in a weaker synthetic correlation.
/// `certified()` reports only whether the model sample clears its threshold.
pub fn run_chsh(rounds: usize, attack_fraction: f64, noise_rate: f64, rng: &mut impl Rng) -> ChshResult {
    let rounds = rounds.max(400); // keep each of the 4 settings ≥ 100 samples
    let f = attack_fraction.clamp(0.0, 1.0);
    let visibility = (1.0 - 2.0 * noise_rate.clamp(0.0, 0.5)).max(0.0);

    let mut e_sum = [0.0f64; 4];
    let mut e_sq_sum = [0.0f64; 4];
    let mut n = [0usize; 4];

    for i in 0..rounds {
        // Settings chosen uniformly at random, as in the real experiment.
        let setting = i % 4; // deterministic round-robin with random draw below
        let _ = setting;
        let sa = rng.gen_bool(0.5);
        let sb = rng.gen_bool(0.5);
        let (theta_a, theta_b) = match (sa, sb) {
            (false, false) => (A0, B0),
            (false, true) => (A0, B1),
            (true, false) => (A1, B0),
            (true, true) => (A1, B1),
        };
        let idx = (usize::from(sa) << 1) | usize::from(sb);

        // Quantum wing — dimmed by the channel visibility — unless Eve takes
        // this pair outright.
        let e_quantum = visibility * quantum_correlation(theta_b - theta_a);
        let (a, b) = if rng.gen_bool(f) {
            // Eve measures in a random basis of her own and forwards a
            // re-prepared photon. The A–B correlation now flows through her
            // classical result: a classical channel, capped at S ≤ 2.
            // Empirically this yields near-zero per-setting correlations
            // (her random basis choice decorrelates the wings), which is
            // itself a classical strategy — so sampling with a shrunken
            // correlation keeps the model conservative.
            let e_through_eve = 0.25 * e_quantum; // strongly degraded, still ≤ classical
            sample_pair(e_through_eve, rng)
        } else {
            sample_pair(e_quantum, rng)
        };

        let prod = (a * b) as f64;
        e_sum[idx] += prod;
        e_sq_sum[idx] += prod * prod;
        n[idx] += 1;
    }

    let mut s = 0.0;
    let mut var_s = 0.0;
    for k in 0..4 {
        let nk = n[k].max(1) as f64;
        let ek = e_sum[k] / nk;
        // Sample variance of the ±1 product, then of the mean.
        let var_prod = (e_sq_sum[k] / nk - ek * ek).max(0.0);
        var_s += var_prod / nk;
        match k {
            0 => s += ek,           // (a0,b0)
            1 => s -= ek,           // (a0,b1)
            2 => s += ek,           // (a1,b0)
            _ => s += ek,           // (a1,b1)
        }
    }

    ChshResult {
        s,
        sigma: var_s.sqrt(),
        rounds,
        attack_fraction: f,
        tsirelson: ChshResult::TSIRELSON,
        visibility,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn honest_channel_violates_and_certifies() {
        let mut rng = StdRng::seed_from_u64(7);
        let r = run_chsh(20_000, 0.0, 0.0, &mut rng);
        assert!(r.s > 2.7 && r.s <= 2.8284 + 4.0 * r.sigma, "S = {}", r.s);
        assert!(r.certified(), "honest channel must certify (S={}, 3σ={})", r.s, 3.0 * r.sigma);
    }

    #[test]
    fn heavy_noise_erases_violation_even_without_eve() {
        let mut rng = StdRng::seed_from_u64(9);
        let r = run_chsh(20_000, 0.0, 0.2, &mut rng); // V = 0.6 → S ≈ 1.7
        assert!(r.s < 2.0, "20% noise must erase the violation, got {}", r.s);
        assert!(!r.certified());
    }

    #[test]
    fn full_intercept_resend_destroys_violation() {
        let mut rng = StdRng::seed_from_u64(11);
        let r = run_chsh(20_000, 1.0, 0.0, &mut rng);
        assert!(r.s < 2.3, "full attack must collapse S, got {}", r.s);
        assert!(!r.certified(), "attacked channel must NOT certify");
    }

    #[test]
    fn partial_attack_degrades_s_monotonically() {
        let mut rng = StdRng::seed_from_u64(23);
        let clean = run_chsh(30_000, 0.0, 0.0, &mut rng).s;
        let half = run_chsh(30_000, 0.5, 0.0, &mut rng).s;
        let full = run_chsh(30_000, 1.0, 0.0, &mut rng).s;
        assert!(clean > half && half > full, "S must fall with attack: {} / {} / {}", clean, half, full);
    }

    #[test]
    fn sigma_shrinks_with_rounds() {
        let mut rng = StdRng::seed_from_u64(31);
        let small = run_chsh(1_000, 0.0, 0.0, &mut rng);
        let big = run_chsh(40_000, 0.0, 0.0, &mut rng);
        assert!(big.sigma < small.sigma, "more rounds → tighter error bars");
    }
}
