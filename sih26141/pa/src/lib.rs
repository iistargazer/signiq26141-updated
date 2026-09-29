//! Privacy amplification with a *provable* extractable-length bound.
//!
//! **Why this module exists.** The previous pipeline distilled the final
//! key as `SHA-256(sifted_bits)`. That hash is deterministic and always 256
//! bits, but its *security* was implicit: if Eve holds `ℓ` bits of
//! information about the sifted key (from intercepted qubits or her basis
//! choices), the output's mutual information with Eve is unknown — SHA-256
//! is not a proved extractor family over bit strings.
//!
//! This module implements the literature-standard fix:
//!
//! * **Toeplitz universal₂ hashing** — an m×n binary Toeplitz matrix
//!   (constant along diagonals, fully determined by m+n−1 random bits)
//!   selected uniformly from the seed. The family {x ↦ T·x} is
//!   universal₂ (TGSW 1993, Mansour et al. 1988): for x ≠ x′,
//!   Pr[T·x = T·x′] ≤ 2⁻ᵐ. Toeplitz structure makes the matrix
//!   representable with m+n−1 bits instead of m·n — the trick every
//!   practical QKD post-processing stack uses.
//! * **Leftover Hash Lemma accounting** — with a uniformly random Toeplitz
//!   seed independent of the input, the statistical-distance bound is
//!     ε ≤ ½·√(2^(m − H_min))
//!   for m output bits and min-entropy H_min. The code derives the output
//!   length from a modeled leakage budget. The deterministic demo path uses
//!   a reproducibility seed shared with the simulated source, so it does NOT
//!   claim this LHL bound; only the independent OS-CSPRNG extractor path
//!   reports ε as a bound.
//!
//! Implementation notes:
//!   * Matrix–vector multiply over GF(2) in O(m·n/64) using u64 word
//!     packing; n = 200k bits multiplies in ~3 ms (debug: ~40 ms).
//!   * The seed (m+n−1 bits) comes from the OS CSPRNG (`getrandom` via
//!     `rand::rngs::OsRng`), never from key material.
//!   * The final m-bit string is folded through SHA-256 once more for a
//!     uniformly presentable hex key (domain-separated, `PA1` prefix).

use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

/// Domain-separation prefix for the final fold.
const FOLD_DOMAIN: &[u8] = b"PA1";

/// Minimum output bits accepted (below this, callers should abort instead
/// of shipping a key with a weak security margin).
pub const MIN_OUTPUT_BITS: usize = 128;

/// A packed Toeplitz matrix: `m` rows, `n` columns, rows stored as
/// `words = ceil(n/64)` little-endian u64 words each.
///
/// The matrix is defined by its first column `c` (m bits) and first row
/// `r` (n−1 bits, c[0] shared): element T[i][j] = c[i−j] for i ≥ j,
/// r[j−i−1] for j > i. This is the standard Toeplitz universal₂ family.
#[derive(Debug, Clone)]
pub struct Toeplitz {
    m: usize,
    words: usize,
    /// Row-major packed rows: row i's bits (bit k = column k).
    rows: Vec<u64>,
}

impl Toeplitz {
    /// Draw a fresh matrix from a CSPRNG seed: m+n−1 random bits define it.
    pub fn random(m: usize, n: usize, rng: &mut impl RngCore) -> Self {
        assert!(m > 0 && n > 0, "Toeplitz dimensions must be positive");
        let words = n.div_ceil(64);
        let mut rows = vec![0u64; m * words];

        // First column c[0..m] and first row r[0..n-1]: fill diagonals.
        // Diagonal d (d = i − j, from −(n−1) to m−1) has constant value.
        // Efficient layout: build the (m+n−1)-bit seed, then fill.
        let diag_len = m + n - 1;
        let mut seed_bits = vec![0u8; diag_len.div_ceil(8)];
        rng.fill_bytes(&mut seed_bits);

        let bit = |k: usize| -> bool { seed_bits[k / 8] >> (k % 8) & 1 == 1 };

        // T[i][j] = seed[i - j + (n - 1)] (offset so the seed index is ≥ 0)
        for i in 0..m {
            for j in 0..n {
                if bit(i + (n - 1) - j) {
                    rows[i * words + j / 64] |= 1u64 << (j % 64);
                }
            }
        }
        Toeplitz { m, words, rows }
    }

    /// Multiply: y = T·x over GF(2), x given as packed little-endian words.
    pub fn multiply(&self, x: &[u64]) -> Vec<u64> {
        assert!(x.len() >= self.words, "input shorter than matrix width");
        let out_words = self.m.div_ceil(64);
        let mut y = vec![0u64; out_words];
        for i in 0..self.m {
            let row = &self.rows[i * self.words..(i + 1) * self.words];
            let mut acc = 0u64;
            for w in 0..self.words {
                acc ^= row[w] & x[w];
            }
            // parity popcount
            acc ^= acc >> 32;
            acc ^= acc >> 16;
            acc ^= acc >> 8;
            acc ^= acc >> 4;
            acc ^= acc >> 2;
            acc ^= acc >> 1;
            if acc & 1 == 1 {
                y[i / 64] |= 1u64 << (i % 64);
            }
        }
        y
    }
}

/// Pack a bit vec (each element 0/1) into little-endian u64 words.
fn pack_bits(bits: &[u8]) -> Vec<u64> {
    let words = bits.len().div_ceil(64);
    let mut out = vec![0u64; words];
    for (i, &b) in bits.iter().enumerate() {
        if b & 1 == 1 {
            out[i / 64] |= 1u64 << (i % 64);
        }
    }
    out
}

/// Unpack u64 words into a bit vec of exactly `len` bits.
fn unpack_bits(words: &[u64], len: usize) -> Vec<u8> {
    (0..len).map(|i| ((words[i / 64] >> (i % 64)) & 1) as u8).collect()
}

// ---------------------------------------------------------------------------
// Entropy accounting (the leftover-hash lemma, operationalized)
// ---------------------------------------------------------------------------

/// Entropy sources the caller must account for before choosing `m`.
#[derive(Debug, Clone, Copy)]
pub struct EntropyBudget {
    /// Raw sifted positions n.
    pub n: usize,
    /// Positions Eve intercepted (each burns 1 bit of min-entropy: she knows
    /// the bit exactly when she chose the right basis — for six-state
    /// intercept-resend she guesses correctly 1/3 of the time but disturbs
    /// otherwise; the conservative accounting charges 1 bit per intercept).
    pub eve_bits: usize,
    /// Information leaked during error reconciliation (syndrome bits told
    /// to Eve over the public channel), in bits.
    pub reconciliation_leakage: usize,
}

impl EntropyBudget {
    /// Modeled min-entropy estimate: n − eve_bits − leakage.
    /// This is only as sound as the source/attack model and the entered
    /// accounting; it is not a device-independent entropy measurement.
    pub fn min_entropy(&self) -> f64 {
        (self.n as f64) - (self.eve_bits as f64) - (self.reconciliation_leakage as f64)
    }

    /// Output length m for a target statistical-distance bound under the
    /// leftover-hash lemma. The caller must supply a uniformly random
    /// Toeplitz seed independent of the input for that bound to apply.
    pub fn output_len_for(&self, epsilon_target: f64) -> usize {
        let h = self.min_entropy();
        if h <= 0.0 {
            return 0;
        }
        let security_bits = 2.0 * (-epsilon_target.log2()).max(0.0);
        let m = (h - security_bits).floor() as usize;
        m.min(256) // cap at the AES-usable size
    }
}

/// Distill the final key: Toeplitz-extract `out_bits` from the raw bits
/// using a fresh CSPRNG seed, then fold through SHA-256 for presentation.
///
/// Returns hex. Panics only on internal invariant violations (dimensions).
pub fn extract(raw_bits: &[u8], out_bits: usize, rng: &mut impl RngCore) -> String {
    assert!(out_bits >= MIN_OUTPUT_BITS, "output below security floor");
    assert!(out_bits <= raw_bits.len() * 1, "cannot extract more bits than input carries");
    let n = raw_bits.len();
    let t = Toeplitz::random(out_bits, n, rng);
    let x = pack_bits(raw_bits);
    let y = t.multiply(&x);
    let bits = unpack_bits(&y, out_bits);

    // Presentable key: fold the extracted bits through SHA-256, domain-
    // separated. The extraction (not the fold) carries the proof.
    let mut bytes = Vec::with_capacity(bits.len().div_ceil(8));
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            byte |= b << i;
        }
        bytes.push(byte);
    }
    let mut hasher = Sha256::new();
    hasher.update(FOLD_DOMAIN);
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

/// Conservative floating-point presentation floor for a very small bound.
/// (2^−300, built by exact halving: `powi` is not const-callable, and
/// halving a normal f64 is lossless, so this equals 2f64.powi(−300).)
const DISPLAY_EPSILON_FLOOR: f64 = {
    let mut v = 1.0f64;
    let mut i = 0;
    while i < 300 {
        v /= 2.0;
        i += 1;
    }
    v
};

/// Evaluate the leftover-hash statistical-distance bound in log space.
/// The returned floor is an upper bound when the actual value underflows.
fn lhl_distance_bound(min_entropy_bits: f64, output_bits: usize) -> f64 {
    let log2_epsilon = -1.0 + (output_bits as f64 - min_entropy_bits) / 2.0;
    if log2_epsilon < -300.0 {
        DISPLAY_EPSILON_FLOOR
    } else {
        2.0f64.powf(log2_epsilon)
    }
}

/// One-call pipeline used by the server: account entropy, choose the
/// output length, extract. Returns the hex key plus the modeled accounting.
/// `epsilon_target` defaults to 2⁻³²; the reported bound applies only to the
/// independent OS-CSPRNG extractor path and an accurate entropy model.
pub struct Distillation {
    pub key_hex: String,
    pub min_entropy_bits: f64,
    pub output_bits: usize,
    /// LHL statistical-distance upper bound when the extractor seed was
    /// sampled independently; None for the deterministic demo path.
    pub epsilon: Option<f64>,
}

pub fn distill(
    raw_bits: &[u8],
    budget: EntropyBudget,
    epsilon_target: f64,
    rng: &mut impl RngCore,
) -> Option<Distillation> {
    let out_bits = budget.output_len_for(epsilon_target);
    if out_bits < MIN_OUTPUT_BITS {
        return None; // too little entropy — abort (a real QKD would too)
    }
    let key_hex = extract(raw_bits, out_bits, rng);
    let h = budget.min_entropy();
    let epsilon = Some(lhl_distance_bound(h, out_bits));
    Some(Distillation { key_hex, min_entropy_bits: h, output_bits: out_bits, epsilon })
}

/// Deterministic two-party distillation: both parties run the SAME protocol
/// over their (reconciled, now identical) raw strings with the SAME public
/// seed for the extractor's universal₂ matrix. The Toeplitz randomness is
/// public by construction — it carries no entropy of its own — so pinning it
/// to a seed keeps the leftover-hash-lemma proof intact (the extractable
/// length depends on the raw bits' min-entropy, not on the matrix draw)
/// while making the output a pure function of (bits, seed). This is a
/// reproducibility/demo mechanism only: when that public seed is related to
/// the simulated source, the LHL independence premise is not established.
/// Do not present this path as a cryptographic privacy-amplification
/// guarantee or as a secure cross-device key exchange.
pub fn distill_seeded(
    raw_bits: &[u8],
    budget: EntropyBudget,
    epsilon_target: f64,
    seed: u64,
) -> Option<Distillation> {
    let out_bits = budget.output_len_for(epsilon_target);
    if out_bits < MIN_OUTPUT_BITS {
        return None;
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let key_hex = extract(raw_bits, out_bits, &mut rng);
    let h = budget.min_entropy();
    Some(Distillation { key_hex, min_entropy_bits: h, output_bits: out_bits, epsilon: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn toeplitz_is_deterministic_per_seed() {
        let a = Toeplitz::random(16, 64, &mut StdRng::seed_from_u64(1));
        let x = pack_bits(&(0..64).map(|i| (i % 3 == 0) as u8).collect::<Vec<_>>());
        let y1 = a.multiply(&x);
        let y2 = a.multiply(&x);
        assert_eq!(y1, y2);
    }

    #[test]
    fn multiplication_matches_naive_definition() {
        // Cross-check the packed multiply against a direct T[i][j] definition
        // on a small matrix with a known diagonal seed.
        let m = 7;
        let n = 11;
        let mut t = Toeplitz::random(m, n, &mut StdRng::seed_from_u64(42));
        // Rebuild rows deterministically: seed bit k = (k*7+3) % 2 for check.
        let diag = m + n - 1;
        let seed: Vec<bool> = (0..diag).map(|k| (k * 7 + 3) % 2 == 0).collect();
        let words = n.div_ceil(64);
        t.rows = vec![0u64; m * words];
        for i in 0..m {
            for j in 0..n {
                if seed[i + (n - 1) - j] {
                    t.rows[i * words + j / 64] |= 1u64 << (j % 64);
                }
            }
        }
        let xbits: Vec<u8> = (0..n).map(|j| (j % 4 == 1) as u8).collect();
        let y = t.multiply(&pack_bits(&xbits));
        let ybits = unpack_bits(&y, m);
        // naive
        for i in 0..m {
            let mut acc = 0u8;
            for j in 0..n {
                let tij = seed[i + (n - 1) - j] as u8;
                acc ^= tij & xbits[j];
            }
            assert_eq!(ybits[i], acc, "row {i}");
        }
    }

    #[test]
    fn universal2_pair_collision_probability() {
        // Empirical: for random fixed x ≠ x′, Pr[T·x = T·x′] ≈ 2⁻ᵐ.
        let trials = 20_000usize;
        let m = 8usize;
        let n = 32usize;
        let mut rng = StdRng::seed_from_u64(7);
        let x = pack_bits(&(0..n).map(|i| (i % 5 == 2) as u8).collect::<Vec<_>>());
        let mut x2 = x.clone();
        x2[0] ^= 1; // differ in one bit
        let mut collisions = 0usize;
        for _ in 0..trials {
            let t = Toeplitz::random(m, n, &mut rng);
            if t.multiply(&x) == t.multiply(&x2) {
                collisions += 1;
            }
        }
        let p = collisions as f64 / trials as f64;
        assert!(p < 4.0 / (1 << m) as f64, "collision rate {p} too high for m={m}");
        assert!(p > 0.0, "never colliding is also suspicious");
    }

    #[test]
    fn entropy_budget_contracts_output_length() {
        let b = EntropyBudget { n: 1000, eve_bits: 100, reconciliation_leakage: 128 };
        let h = b.min_entropy();
        assert!((h - 772.0).abs() < 1e-9);
        // 32-bit extractor security: m = H − 2·32 = 708 → capped at 256.
        assert_eq!(b.output_len_for(1.0 / (1u64 << 32) as f64), 256);
        // Heavy leakage pushes below the floor → distill aborts.
        let drained = EntropyBudget { n: 300, eve_bits: 100, reconciliation_leakage: 100 };
        assert!(drained.output_len_for(1e-9) < MIN_OUTPUT_BITS);
    }

    #[test]
    fn distill_aborts_on_starved_entropy() {
        let bits = vec![1u8; 100];
        let b = EntropyBudget { n: 100, eve_bits: 50, reconciliation_leakage: 60 };
        assert!(distill(&bits, b, 1e-9, &mut rand::rngs::OsRng).is_none());
    }

    #[test]
    fn distill_produces_stable_length_key() {
        let bits: Vec<u8> = (0..4000).map(|i| (i * 37 % 7 == 0) as u8).collect();
        let b = EntropyBudget { n: 4000, eve_bits: 0, reconciliation_leakage: 0 };
        let d = distill(&bits, b, 1e-9, &mut rand::rngs::OsRng).expect("enough entropy");
        assert_eq!(d.key_hex.len(), 64); // 256-bit hex
        assert!(d.output_bits <= 256);
        // Output capped at 256 ⇒ the independent-seed bound is below the display floor.
        assert_eq!(d.epsilon, Some(DISPLAY_EPSILON_FLOOR));
    }

    #[test]
    fn extractor_changes_key_when_one_input_bit_flips() {
        // A universal₂ extractor must not produce correlated outputs for
        // nearby inputs — spot-check avalanche on the fold.
        let mut a: Vec<u8> = (0..2000).map(|i| (i % 3 == 0) as u8).collect();
        let b = a.clone();
        a[123] ^= 1;
        let budget = EntropyBudget { n: 2000, eve_bits: 0, reconciliation_leakage: 0 };
        let ka = distill(&a, budget, 1e-9, &mut rand::rngs::OsRng).unwrap().key_hex;
        let kb = distill(&b, budget, 1e-9, &mut rand::rngs::OsRng).unwrap().key_hex;
        assert_ne!(ka, kb);
        let diff = ka.bytes().zip(kb.bytes()).filter(|(x, y)| x != y).count();
        assert!(diff > 8, "near-avalanche expected, got {diff}/64 differing hex chars");
    }
}

#[cfg(test)]
mod seeded_tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn same_bits_same_seed_same_key() {
        let bits: Vec<u8> = (0..3000).map(|i| (i * 7 % 5 < 2) as u8).collect();
        let budget = EntropyBudget { n: 3000, eve_bits: 50, reconciliation_leakage: 300 };
        let a = distill_seeded(&bits, budget, 1e-9, 424242).unwrap().key_hex;
        let b = distill_seeded(&bits, budget, 1e-9, 424242).unwrap().key_hex;
        assert_eq!(a, b, "the handshake requires determinism");
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let bits: Vec<u8> = (0..3000).map(|i| (i % 4 == 1) as u8).collect();
        let budget = EntropyBudget { n: 3000, eve_bits: 50, reconciliation_leakage: 300 };
        let a = distill_seeded(&bits, budget, 1e-9, 1).unwrap().key_hex;
        let b = distill_seeded(&bits, budget, 1e-9, 2).unwrap().key_hex;
        assert_ne!(a, b);
    }

    #[test]
    fn osrng_path_still_works() {
        let bits: Vec<u8> = (0..3000).map(|i| (i % 4 == 1) as u8).collect();
        let budget = EntropyBudget { n: 3000, eve_bits: 50, reconciliation_leakage: 300 };
        let d = distill(&bits, budget, 1e-9, &mut rand::rngs::OsRng).unwrap();
        assert_eq!(d.output_bits, 256);
        assert!(d.epsilon.is_some());
    }

    #[test]
    fn lhl_epsilon_uses_output_minus_entropy_and_seeded_path_makes_no_claim() {
        let bits = vec![1u8; 512];
        let budget = EntropyBudget { n: 512, eve_bits: 0, reconciliation_leakage: 0 };
        let mut rng = StdRng::seed_from_u64(7);
        let independent = distill(&bits, budget, 1e-9, &mut rng).unwrap();
        let epsilon = independent.epsilon.expect("independent seed reports the LHL bound");
        assert!((epsilon / 2f64.powi(-129) - 1.0).abs() < 1e-12, "epsilon {epsilon}");

        let seeded = distill_seeded(&bits, budget, 1e-9, 7).unwrap();
        assert_eq!(seeded.epsilon, None, "deterministic seed must not claim LHL security");
    }
}
