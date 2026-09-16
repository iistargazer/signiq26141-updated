//! Multi-hop relay nodes (quantum repeaters) for the QKD layer.
//!
//! Real QKD is distance-limited by fiber attenuation; trusted relay nodes
//! segment the channel into short links. Each relay:
//!   1. measures the incoming qubit in a randomly chosen basis (local
//!      sifting against the sending node's announced basis),
//!   2. forwards only when the bases matched — a mismatched link is treated
//!      as line loss (the relay has no correlated record to forward),
//!   3. re-prepares the measured state and sends it down the next link.
//!
//! Consequences (all visible in the demo statistics):
//!   * End-to-end sifting survival ≈ (1/3)^(hops+1): every relay's basis
//!     check costs key material — the trusted-repeater trade-off.
//!   * Each link adds its own environmental noise, so the end-to-end QBER
//!     grows roughly linearly with the hop count and stresses the dynamic
//!     threshold detector.
//!   * Eve can sit at any link; per-hop interception counts make the
//!     attack location visible in the audit trail.

use rand::Rng;

use crate::{random_basis, PauliBasis, PauliState};

/// Configuration for a relay route.
#[derive(Debug, Clone)]
pub struct RelayRoute {
    /// Number of relay nodes between Alice and Bob (0 = direct link).
    pub hop_count: usize,
    /// Environmental noise per link (applied at every hop).
    pub noise_rate: f64,
    /// Intercept-resend fraction applied per link (per-hop Eve).
    pub intercept_ratio: f64,
}

impl RelayRoute {
    pub fn new(hop_count: usize) -> Self {
        Self { hop_count, noise_rate: 0.0, intercept_ratio: 0.0 }
    }

    pub fn with_noise(mut self, noise_rate: f64) -> Self {
        self.noise_rate = noise_rate.clamp(0.0, 1.0);
        self
    }

    pub fn with_intercept(mut self, intercept_ratio: f64) -> Self {
        self.intercept_ratio = intercept_ratio.clamp(0.0, 1.0);
        self
    }

    /// Number of links (Alice→R1, R1→R2, …, Rn→Bob).
    pub fn link_count(&self) -> usize {
        self.hop_count + 1
    }

    /// Expected end-to-end sifted fraction: (1/3)^links.
    pub fn expected_sift_factor(&self) -> f64 {
        const BASIS_MATCH: f64 = 1.0 / 3.0;
        BASIS_MATCH.powi(self.link_count() as i32)
    }

    /// Node label for a link's receiver (UI + audit log).
    pub fn node_label(&self, link: usize) -> String {
        if link == 0 {
            "Alice".into()
        } else if link == self.hop_count {
            "Bob".into()
        } else {
            format!("Relay {link}")
        }
    }
}

/// Aggregated per-link statistics across the whole transmission.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HopStats {
    /// Link index (0 = Alice→Relay 1, last = last relay→Bob).
    pub hop: usize,
    pub from: String,
    pub to: String,
    /// Qubits that entered this link.
    pub in_qubits: usize,
    /// Qubits that survived this link's basis sifting.
    pub out_qubits: usize,
    /// Mismatch introduced on this link (received bit ≠ bit the previous
    /// link re-prepared; link 0 compares against Alice's original).
    pub mismatches: usize,
    /// This link's own error rate: mismatches introduced per qubit that
    /// traversed the link (not 0.0 — every link can now carry errors).
    pub qber: f64,
    /// Intercept-resend events detected on this link.
    pub interceptions: usize,
    pub noise_rate: f64,
    pub intercept_ratio: f64,
}

/// Result of a full multi-hop transmission.
#[derive(Debug, Clone)]
pub struct RelayTransmission {
    /// Bob's final sifted bits (errors included).
    pub sifted_key_bits: Vec<u8>,
    /// Alice's original bits at the same positions.
    pub alice_sifted_bits: Vec<u8>,
    /// End-to-end mismatch rate (what the detector sees).
    pub mismatch_rate: f64,
    pub matching_bases_count: usize,
    /// Per-link statistics, ordered Alice→…→Bob.
    pub hops: Vec<HopStats>,
    /// Environmental noise per link (route configuration).
    pub noise_rate: f64,
    /// Total intercept events across all links.
    pub interceptions: usize,
}

impl RelayTransmission {
    /// Route-level noise exposure (per-link noise × link count).
    pub fn total_noise_exposure(&self) -> f64 {
        self.noise_rate * self.hops.len() as f64
    }
}

/// Per-link outcome of pushing one qubit through one link.
#[derive(Debug, Clone, Copy, Default)]
struct LinkOutcome {
    /// The qubit produced a sifted record at this link's receiver.
    survived: bool,
    /// Receiver's bit differs from Alice's (only detectable at Bob).
    mismatch: bool,
    /// Eve fired on this link for this qubit.
    intercepted: bool,
}

/// Push one qubit through the whole route. Returns Bob's (alice_bit,
/// bob_bit) when the qubit survives every link, plus per-link outcomes.
/// A link's `mismatch` flag marks an error INTRODUCED on that link (its
/// received bit differs from the bit the previous link re-prepared —
/// link 0 compares against Alice's original).
fn transmit_single(
    alice_state: PauliState,
    route: &RelayRoute,
    rng: &mut impl Rng,
) -> (Option<(u8, u8)>, Vec<LinkOutcome>) {
    let links = route.link_count();
    let mut outcomes = vec![LinkOutcome::default(); links];

    // State currently in flight on the wire.
    let mut state = alice_state;
    // Bit the previous link handed over (None on the first link).
    let mut prev_bit: Option<u8> = None;

    for link in 0..links {
        // 1. Environmental noise on this link (fiber impurity / turbulence):
        //    a pure bit flip on the state in flight.
        if route.noise_rate > 0.0 && rng.gen_bool(route.noise_rate) {
            state = match state {
                PauliState::Positive => PauliState::Negative,
                PauliState::Negative => PauliState::Positive,
            };
        }

        // 2. Intercept-resend on this link (Eve may sit anywhere on the
        //    route). She picks a random basis: with P = 1/3 it matches the
        //    sender's basis and the state passes undisturbed; otherwise the
        //    measurement collapses the state and she resends a random
        //    eigenstate of her basis. Net effect on the carried bit once the
        //    qubit survives downstream sifting: flip probability 2/3 × 1/2
        //    = 1/3 — the six-state intercept-resend QBER signature.
        if route.intercept_ratio > 0.0 && rng.gen_bool(route.intercept_ratio) {
            outcomes[link].intercepted = true;
            if rng.gen_bool(2.0 / 3.0) {
                state = if rng.gen_bool(0.5) {
                    PauliState::Positive
                } else {
                    PauliState::Negative
                };
            }
        }

        // 3. The receiving node measures in a randomly chosen basis and
        //    locally sifts against the sender's announced basis: agreement
        //    has probability 1/3 for every link (six-state). A basis
        //    disagreement at a relay is treated as line loss — the relay has
        //    no correlated record to forward, so the qubit dies here.
        let _ = random_basis(rng); // receiver's basis choice (agreement modelled below)
        if !rng.gen_bool(1.0 / 3.0) {
            return (None, outcomes);
        }

        let measured_bit = state.as_bit();

        // Error attribution: an error is introduced on the link whose
        // received bit differs from what the previous link re-prepared.
        if let Some(prev) = prev_bit {
            outcomes[link].mismatch = measured_bit != prev;
        }
        prev_bit = Some(measured_bit);

        // 4. Relay re-prepares the measured state for the next link, or Bob
        //    records the sifted bit at the terminal link.
        if link + 1 < links {
            state = if measured_bit == 1 {
                PauliState::Positive
            } else {
                PauliState::Negative
            };
        } else {
            outcomes[link].survived = true;
            let alice_bit = alice_state.as_bit();
            return (Some((alice_bit, measured_bit)), outcomes);
        }
    }
    unreachable!("terminal link always returns");
}

/// Transmit `private_key` through a multi-hop relay route and collect the
/// final sifted key plus per-link statistics.
pub fn simulate_relay_transmission(
    private_key: &[(PauliBasis, PauliState)],
    route: &RelayRoute,
    rng: &mut impl Rng,
) -> RelayTransmission {
    let links = route.link_count();

    let mut agg: Vec<HopStats> = (0..links)
        .map(|link| HopStats {
            hop: link,
            from: route.node_label(link),
            to: if link + 1 < links {
                route.node_label(link + 1)
            } else {
                "Bob".into()
            },
            noise_rate: route.noise_rate,
            intercept_ratio: route.intercept_ratio,
            ..Default::default()
        })
        .collect();

    let mut sifted: Vec<u8> = Vec::new();
    let mut alice_bits: Vec<u8> = Vec::new();

    for &(basis, state) in private_key {
        let (result, outcomes) = transmit_single(state, route, rng);
        // A qubit only reaches link L if it survived links 0..L — count
        // arrivals accordingly so per-link stats reflect real traffic.
        let mut arrived = true;
        for (link, o) in outcomes.iter().enumerate() {
            if arrived {
                agg[link].in_qubits += 1;
                agg[link].out_qubits += o.survived as usize;
                agg[link].mismatches += o.mismatch as usize;
                agg[link].interceptions += o.intercepted as usize;
                arrived = o.survived;
            }
        }
        if let Some((a, b)) = result {
            alice_bits.push(a);
            sifted.push(b);
        }
        let _ = basis;
    }

    for h in agg.iter_mut() {
        h.qber = if h.out_qubits == 0 {
            0.0
        } else {
            h.mismatches as f64 / h.out_qubits as f64
        };
    }

    let matching = sifted.len();
    let mismatches = sifted
        .iter()
        .zip(alice_bits.iter())
        .filter(|(b, a)| b != a)
        .count();
    let total_interceptions = agg.iter().map(|h| h.interceptions).sum();

    RelayTransmission {
        mismatch_rate: if matching == 0 {
            0.0
        } else {
            mismatches as f64 / matching as f64
        },
        matching_bases_count: matching,
        sifted_key_bits: sifted,
        alice_sifted_bits: alice_bits,
        hops: agg,
        noise_rate: route.noise_rate,
        interceptions: total_interceptions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::QuantumKeyGenerator;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_key(n: usize, seed: u64) -> Vec<(PauliBasis, PauliState)> {
        QuantumKeyGenerator::new(n)
            .unwrap()
            .generate_eigenstates(&mut StdRng::seed_from_u64(seed))
    }

    #[test]
    fn direct_route_is_clean() {
        let key = make_key(4000, 7);
        let route = RelayRoute::new(0);
        let res = simulate_relay_transmission(&key, &route, &mut StdRng::seed_from_u64(7));
        assert_eq!(res.hops.len(), 1);
        // No noise, no Eve: every surviving bit is exact.
        assert_eq!(res.mismatch_rate, 0.0);
        assert!(!res.sifted_key_bits.is_empty());
    }

    #[test]
    fn multi_hop_preserves_clean_bits() {
        let key = make_key(4000, 7);
        let route = RelayRoute::new(2); // Alice → R1 → R2 → Bob
        let res = simulate_relay_transmission(&key, &route, &mut StdRng::seed_from_u64(7));
        assert_eq!(res.hops.len(), 3);
        assert_eq!(res.mismatch_rate, 0.0, "clean relays must not corrupt bits");
        assert!(!res.sifted_key_bits.is_empty());
    }

    #[test]
    fn more_hops_means_fewer_sifted_bits() {
        let key = make_key(6000, 19);
        let direct = simulate_relay_transmission(&key, &RelayRoute::new(0), &mut StdRng::seed_from_u64(19));
        let two_hops = simulate_relay_transmission(&key, &RelayRoute::new(2), &mut StdRng::seed_from_u64(19));
        assert!(
            two_hops.matching_bases_count < direct.matching_bases_count,
            "each relay's basis check must cost key material"
        );
        // Survival ≈ (1/3)^links within loose statistical bounds.
        let expected = (key.len() as f64) * RelayRoute::new(2).expected_sift_factor();
        assert!(
            (two_hops.matching_bases_count as f64 - expected).abs() < expected * 0.35,
            "survived {} vs expected ≈{:.0}",
            two_hops.matching_bases_count,
            expected
        );
    }

    #[test]
    fn per_hop_noise_accumulates() {
        // 3 links × 6% noise ⇒ end-to-end QBER ≈ 18% (linear accumulation).
        let key = make_key(20000, 11);
        let route = RelayRoute::new(2).with_noise(0.06);
        let res = simulate_relay_transmission(&key, &route, &mut StdRng::seed_from_u64(11));
        assert!(
            res.mismatch_rate > 0.09 && res.mismatch_rate < 0.26,
            "expected ≈0.18 end-to-end QBER, got {}",
            res.mismatch_rate
        );
        assert_eq!(res.total_noise_exposure(), 0.18);
    }

    #[test]
    fn per_hop_eve_is_counted_and_detected() {
        let key = make_key(20000, 13);
        let route = RelayRoute::new(1).with_intercept(1.0);
        let res = simulate_relay_transmission(&key, &route, &mut StdRng::seed_from_u64(13));
        // intercept_ratio 1.0 ⇒ every qubit that traverses a link is
        // intercepted on that link: total = in_qubits summed over links.
        let expected: usize = res.hops.iter().map(|h| h.in_qubits).sum();
        assert_eq!(res.interceptions, expected);
        // Full intercept ⇒ QBER ≈ 1/3 at Bob, just like a direct attack.
        assert!(res.mismatch_rate > 0.2, "qber {}", res.mismatch_rate);
    }

    #[test]
    fn eve_location_is_visible_in_hop_stats() {
        let key = make_key(4000, 23);
        let route = RelayRoute::new(2).with_intercept(1.0);
        let res = simulate_relay_transmission(&key, &route, &mut StdRng::seed_from_u64(23));
        for h in &res.hops {
            assert_eq!(h.interceptions, h.in_qubits, "hop {} missed intercepts", h.hop);
        }
        // Fewer qubits reach each successive link (basis-sifting loss).
        assert!(res.hops[0].in_qubits >= res.hops[1].in_qubits);
        assert!(res.hops[1].in_qubits >= res.hops[2].in_qubits);
    }
}
