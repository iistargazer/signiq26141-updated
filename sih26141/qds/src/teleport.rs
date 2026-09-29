//! Feature 1 — Bell-State Teleportation & Pauli Correction Engine.
//!
//! A genuine statevector simulation of quantum teleportation: complex
//! amplitudes, a real entangled EPR pair, a Bell-state measurement realized
//! as the standard CNOT-then-Hadamard circuit, projective measurement, and
//! Bob's conditional Pauli correction. Fidelity of the teleported state is
//! proven exactly 1.0 — for arbitrary superpositions, not just basis states.
//!
//! This is the Deliverable-1 core: "Bell-state entanglement, Quantum
//! teleportation process, Pauli correction operations, Projective
//! measurement rules."
//!
//! ## The statevector model
//!
//! A two-qubit register `|ψ⟩ = Σ c[i] |i⟩` with `i = q1·2 + q0` (qubit 0 is
//! Alice's message qubit before entanglement; afterwards qubit 0 is Alice's
//! half of the EPR pair and qubit 1 is Bob's half). All gates below act on
//! this register with the standard 2×2 or 4×4 unitaries over complex
//! amplitudes (`f64` real/imag pairs). Probabilities are |c[i]|², and the
//! Born rule governs the projective measurement — nothing is hard-coded.
//!
//! ## The teleportation protocol (Bennett–Brassard–Crépeau–Jozsa–Peres–Wootters 1993)
//!
//! 1. Alice holds message qubit |φ⟩ = α|0⟩ + β|1⟩.
//! 2. An EPR pair |Φ⁺⟩ = (|00⟩ + |11⟩)/√2 is distributed: Alice takes one
//!    half, Bob the other.
//! 3. Alice performs a **Bell-state measurement** on (message, her half) —
//!    realized as CNOT(message→half) then H(message), then a projective
//!    measurement of both qubits in the computational basis.
//! 4. Alice sends the two classical outcome bits to Bob.
//! 5. Bob applies the Pauli correction I / X / Z / ZX selected by the
//!    outcome; his qubit becomes exactly |φ⟩.
//!
//! The engine tracks the full 3-qubit register (message, Alice-half,
//! Bob-half) so every intermediate state is inspectable — the dashboard can
//! display amplitudes, and tests can assert fidelity and measurement
//! statistics directly.

use serde::Serialize;

// ---------------------------------------------------------------------------
// Complex amplitudes and the statevector
// ---------------------------------------------------------------------------

/// One complex amplitude (re + i·im).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Amplitude {
    pub re: f64,
    pub im: f64,
}

impl Amplitude {
    pub const ZERO: Amplitude = Amplitude { re: 0.0, im: 0.0 };

    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    pub fn modulus_squared(self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    fn mul(self, o: Amplitude) -> Amplitude {
        Amplitude::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
}

/// An n-qubit statevector over 2ⁿ complex amplitudes.
#[derive(Debug, Clone)]
pub struct StateVector {
    /// Amplitudes indexed by computational-basis state (qubit 0 = LSB).
    pub amplitudes: Vec<Amplitude>,
}

impl StateVector {
    /// |0…0⟩ with amplitude 1 on the all-zeros basis state.
    pub fn zero(n_qubits: usize) -> Self {
        let mut amplitudes = vec![Amplitude::ZERO; 1 << n_qubits];
        amplitudes[0] = Amplitude::new(1.0, 0.0);
        Self { amplitudes }
    }

    /// |b⟩ basis state.
    pub fn basis(n_qubits: usize, value: usize) -> Self {
        let mut amplitudes = vec![Amplitude::ZERO; 1 << n_qubits];
        amplitudes[value & ((1 << n_qubits) - 1)] = Amplitude::new(1.0, 0.0);
        Self { amplitudes }
    }

    pub fn n_qubits(&self) -> usize {
        self.amplitudes.len().trailing_zeros() as usize
    }

    /// Total probability — must be 1 up to floating error for valid states.
    pub fn norm_squared(&self) -> f64 {
        self.amplitudes.iter().map(|a| a.modulus_squared()).sum()
    }

    /// Normalize in place (guards against accumulated drift).
    pub fn normalize(&mut self) {
        let n = self.norm_squared().sqrt();
        if n > 1e-15 {
            for a in &mut self.amplitudes {
                a.re /= n;
                a.im /= n;
            }
        }
    }

    /// Apply a single-qubit 2×2 unitary `u` to qubit `target`.
    /// u is [[u00, u01], [u10, u11]] acting on (|0⟩, |1⟩).
    pub fn apply_single(&mut self, target: usize, u: [[Amplitude; 2]; 2]) {
        let bit = 1usize << target;
        for base in 0..self.amplitudes.len() {
            if base & bit == 0 {
                let i0 = base;
                let i1 = base | bit;
                let a0 = self.amplitudes[i0];
                let a1 = self.amplitudes[i1];
                self.amplitudes[i0] = u[0][0].mul(a0).add(u[0][1].mul(a1));
                self.amplitudes[i1] = u[1][0].mul(a0).add(u[1][1].mul(a1));
            }
        }
    }

    /// CNOT: control `c`, target `t`.
    pub fn apply_cnot(&mut self, control: usize, target: usize) {
        let cb = 1usize << control;
        let tb = 1usize << target;
        for base in 0..self.amplitudes.len() {
            if base & cb != 0 && base & tb == 0 {
                self.amplitudes.swap(base, base | tb);
            }
        }
    }

    /// Projective measurement of qubit `target` in the computational basis:
    /// collapses the state according to the Born rule and returns the
    /// observed classical bit.
    pub fn measure(&mut self, target: usize, rng: &mut impl rand::Rng) -> u8 {
        let bit = 1usize << target;
        let p1: f64 = self
            .amplitudes
            .iter()
            .enumerate()
            .filter(|(i, _)| i & bit != 0)
            .map(|(_, a)| a.modulus_squared())
            .sum();
        let outcome = if rng.gen::<f64>() < p1 { 1u8 } else { 0u8 };

        // Collapse: keep only amplitudes consistent with the outcome, then
        // renormalize (the projection operator's effect).
        for (i, a) in self.amplitudes.iter_mut().enumerate() {
            let keep = (i & bit != 0) == (outcome == 1);
            if !keep {
                *a = Amplitude::ZERO;
            }
        }
        self.normalize();
        outcome
    }
}

impl Amplitude {
    fn add(self, o: Amplitude) -> Amplitude {
        Amplitude::new(self.re + o.re, self.im + o.im)
    }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

/// Hadamard gate.
pub fn hadamard() -> [[Amplitude; 2]; 2] {
    let s = std::f64::consts::FRAC_1_SQRT_2;
    [
        [Amplitude::new(s, 0.0), Amplitude::new(s, 0.0)],
        [Amplitude::new(s, 0.0), Amplitude::new(-s, 0.0)],
    ]
}

/// Pauli-X (bit flip).
pub fn pauli_x() -> [[Amplitude; 2]; 2] {
    [
        [Amplitude::ZERO, Amplitude::new(1.0, 0.0)],
        [Amplitude::new(1.0, 0.0), Amplitude::ZERO],
    ]
}

/// Pauli-Z (phase flip).
pub fn pauli_z() -> [[Amplitude; 2]; 2] {
    [
        [Amplitude::new(1.0, 0.0), Amplitude::ZERO],
        [Amplitude::ZERO, Amplitude::new(-1.0, 0.0)],
    ]
}

// ---------------------------------------------------------------------------
// The teleportation engine
// ---------------------------------------------------------------------------

/// The four Bell states, labeled by their two-bit superscripts (Φ/Ψ, +/−).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BellState {
    PhiPlus,
    PhiMinus,
    PsiPlus,
    PsiMinus,
}

impl BellState {
    pub fn label(self) -> &'static str {
        match self {
            BellState::PhiPlus => "|Φ⁺⟩",
            BellState::PhiMinus => "|Φ⁻⟩",
            BellState::PsiPlus => "|Ψ⁺⟩",
            BellState::PsiMinus => "|Ψ⁻⟩",
        }
    }

    /// The two classical bits Alice broadcasts for this outcome.
    pub fn classical_bits(self) -> [u8; 2] {
        match self {
            BellState::PhiPlus => [0, 0],
            BellState::PsiPlus => [0, 1],
            BellState::PhiMinus => [1, 0],
            BellState::PsiMinus => [1, 1],
        }
    }

    /// Bob's Pauli correction for this outcome — the heart of teleportation.
    /// Φ⁺ → I, Ψ⁺ → X, Φ⁻ → Z, Ψ⁻ → X then Z (composition ZX).
    pub fn correction(self) -> PauliCorrection {
        match self {
            BellState::PhiPlus => PauliCorrection::I,
            BellState::PsiPlus => PauliCorrection::X,
            BellState::PhiMinus => PauliCorrection::Z,
            BellState::PsiMinus => PauliCorrection::ZX,
        }
    }
}

/// Bob's correction operator (single Paulis or the ZX composition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauliCorrection {
    I,
    X,
    Z,
    ZX,
}

impl PauliCorrection {
    pub fn label(self) -> &'static str {
        match self {
            PauliCorrection::I => "I",
            PauliCorrection::X => "X",
            PauliCorrection::Z => "Z",
            PauliCorrection::ZX => "Z·X",
        }
    }
}

/// A complete record of one teleportation round — everything the dashboard
/// needs to replay the physics.
#[derive(Debug, Clone, Serialize)]
pub struct TeleportationRecord {
    /// Alice's message qubit |φ⟩ = α|0⟩ + β|1⟩ (input amplitudes).
    pub input_alpha: Amplitude,
    pub input_beta: Amplitude,
    /// The Bell state Alice's measurement projected onto.
    pub bell_state: BellState,
    /// The two classical correction bits Alice sent.
    pub classical_bits: [u8; 2],
    /// Bob's correction operator.
    pub correction: PauliCorrection,
    /// Amplitudes of Bob's qubit AFTER correction (must equal the input).
    pub bob_alpha: Amplitude,
    pub bob_beta: Amplitude,
    /// |⟨φ|ψ_Bob⟩|² — 1.0 for ideal teleportation.
    pub fidelity: f64,
    /// Bob's qubit BEFORE correction, for forensics/attack analysis.
    pub bob_alpha_pre: Amplitude,
    pub bob_beta_pre: Amplitude,
}

/// Full result of one teleportation: the record plus the final 3-qubit
/// register (message+Alice collapsed, Bob corrected).
#[derive(Debug, Clone, Serialize)]
pub struct TeleportationResult {
    pub record: TeleportationRecord,
    /// Bob's half after correction, as a 2-amplitude vector.
    pub bob_state: [Amplitude; 2],
}

/// Teleport an arbitrary single-qubit state |φ⟩ = α|0⟩ + β|1⟩ from Alice to
/// Bob through a shared |Φ⁺⟩ EPR pair.
///
/// Register layout (3 qubits): q0 = Alice's message, q1 = Alice's EPR half,
/// q2 = Bob's EPR half. After the Bell measurement on (q0, q1) and the
/// classical broadcast, Bob's q2 holds |φ⟩ up to the Pauli correction.
pub fn teleport_state(
    alpha: Amplitude,
    beta: Amplitude,
    rng: &mut impl rand::Rng,
) -> TeleportationResult {
    // 3-qubit register: (message, alice-half, bob-half) = (q2, q1, q0) in
    // little-endian indexing: index = q2·4 + q1·2 + q0.
    let mut sv = StateVector::zero(3);

    // Prepare |φ⟩ = α|0⟩ + β|1⟩ on q2 (message): |φ⟩|00⟩ = α|000⟩ + β|100⟩
    // in (q2,q1,q0) little-endian indexing — amplitudes live only where
    // q1=q0=0, α on q2=0 and β on q2=1.
    for (i, a) in sv.amplitudes.iter_mut().enumerate() {
        let q2 = (i >> 2) & 1;
        let lower = i & 0b11; // q1,q0 must be 0
        *a = if lower == 0 {
            if q2 == 1 { beta } else { alpha }
        } else {
            Amplitude::ZERO
        };
    }

    // Prepare the EPR pair |Φ⁺⟩ on (q1, q0): H(q1) then CNOT(q1→q0).
    sv.apply_single(1, hadamard());
    sv.apply_cnot(1, 0);

    // --- Bell-state measurement on (message q2, alice-half q1) -------------
    // Standard circuit: CNOT(q2→q1), H(q2), measure both in Z basis.
    sv.apply_cnot(2, 1);
    sv.apply_single(2, hadamard());

    let m2 = sv.measure(2, rng); // message qubit → 1st classical bit
    let m1 = sv.measure(1, rng); // alice-half → 2nd classical bit

    // Map the measurement outcome to the Bell state that was projected:
    // (m2, m1) = (0,0) Φ⁺ · (0,1) Ψ⁺ · (1,0) Φ⁻ · (1,1) Ψ⁻
    let bell_state = match (m2, m1) {
        (0, 0) => BellState::PhiPlus,
        (0, 1) => BellState::PsiPlus,
        (1, 0) => BellState::PhiMinus,
        _ => BellState::PsiMinus,
    };

    // Bob's qubit (q0) BEFORE correction — read out its amplitudes. After
    // the collapse only basis states consistent with the measurement survive,
    // so ACCUMULATING over the register (a partial trace over the collapsed
    // qubits) picks out exactly the surviving amplitudes.
    let mut bob_pre = [Amplitude::ZERO; 2];
    for (i, a) in sv.amplitudes.iter().enumerate() {
        let q0 = i & 1;
        bob_pre[q0 as usize] = bob_pre[q0 as usize].add(*a);
    }

    // --- Bob applies the Pauli correction -----------------------------------
    match bell_state.correction() {
        PauliCorrection::I => {}
        PauliCorrection::X => sv.apply_single(0, pauli_x()),
        PauliCorrection::Z => sv.apply_single(0, pauli_z()),
        PauliCorrection::ZX => {
            sv.apply_single(0, pauli_x());
            sv.apply_single(0, pauli_z());
        }
    }

    let mut bob = [Amplitude::ZERO; 2];
    for (i, a) in sv.amplitudes.iter().enumerate() {
        let q0 = i & 1;
        bob[q0 as usize] = bob[q0 as usize].add(*a);
    }

    // Fidelity |⟨φ|ψ_Bob⟩|². Global phase is irrelevant; compare magnitudes
    // of the inner product directly (handles the −1 phases from Φ⁻/Ψ⁻).
    let inner = bob[0]
        .mul(Amplitude::new(alpha.re, -alpha.im))
        .add(bob[1].mul(Amplitude::new(beta.re, -beta.im)));
    let fidelity = inner.modulus_squared();

    let record = TeleportationRecord {
        input_alpha: alpha,
        input_beta: beta,
        bell_state,
        classical_bits: bell_state.classical_bits(),
        correction: bell_state.correction(),
        bob_alpha: bob[0],
        bob_beta: bob[1],
        fidelity,
        bob_alpha_pre: bob_pre[0],
        bob_beta_pre: bob_pre[1],
    };

    TeleportationResult {
        record,
        bob_state: bob,
    }
}

// ---------------------------------------------------------------------------
// Byte-level bridge: real teleportation records → protocol bit vectors
// ---------------------------------------------------------------------------

/// Teleport an entire byte vector, one qubit per *bit* (MSB first), and
/// return the Bell outcome index (0..4) per bit. This is what the QDS
/// signer consumes: the correction-bits sequence is now the record of
/// genuine Bell measurements over a statevector register.
pub fn teleport_bytes(bits: &[u8]) -> Vec<u8> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::from_entropy();
    bits.iter()
        .map(|&b| teleport_state(Amplitude::new((1 - b) as f64, 0.0), Amplitude::new(b as f64, 0.0), &mut rng).record.bell_state as usize as u8)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests — the physics must be *proven*, not claimed
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn epr_pair_exhibits_bell_correlations() {
        // |Φ⁺⟩ on 2 qubits: amplitudes 1/√2 on |00⟩ and |11⟩ only.
        let mut sv = StateVector::zero(2);
        sv.apply_single(1, hadamard());
        sv.apply_cnot(1, 0);
        assert!(close(sv.norm_squared(), 1.0));
        assert!(close(sv.amplitudes[0b00].re, std::f64::consts::FRAC_1_SQRT_2));
        assert!(close(sv.amplitudes[0b11].re, std::f64::consts::FRAC_1_SQRT_2));
        assert!(close(sv.amplitudes[0b01].modulus_squared(), 0.0));
        assert!(close(sv.amplitudes[0b10].modulus_squared(), 0.0));
    }

    #[test]
    fn teleportation_of_basis_states_is_exact() {
        let mut rng = StdRng::seed_from_u64(1);
        for (alpha, beta, name) in [
            (Amplitude::new(1.0, 0.0), Amplitude::ZERO, "|0⟩"),
            (Amplitude::ZERO, Amplitude::new(1.0, 0.0), "|1⟩"),
        ] {
            let r = teleport_state(alpha, beta, &mut rng);
            assert!(close(r.record.fidelity, 1.0), "fidelity for {name}");
            assert!(close(r.bob_state[0].modulus_squared(), alpha.modulus_squared()));
            assert!(close(r.bob_state[1].modulus_squared(), beta.modulus_squared()));
        }
    }

    #[test]
    fn teleportation_of_superpositions_is_exact_with_unit_fidelity() {
        // |+⟩, |−⟩, and a genuinely complex state — fidelity must be 1.0.
        let mut rng = StdRng::seed_from_u64(2);
        let s = std::f64::consts::FRAC_1_SQRT_2;
        for (alpha, beta) in [
            (Amplitude::new(s, 0.0), Amplitude::new(s, 0.0)),         // |+⟩
            (Amplitude::new(s, 0.0), Amplitude::new(-s, 0.0)),        // |−⟩
            (Amplitude::new(s, 0.0), Amplitude::new(0.0, s)),         // |i⟩ = (|0⟩+i|1⟩)/√2
            (Amplitude::new(0.6, 0.0), Amplitude::new(0.0, 0.8)),     // 0.6|0⟩ + 0.8i|1⟩
        ] {
            let r = teleport_state(alpha, beta, &mut rng);
            assert!(
                close(r.record.fidelity, 1.0),
                "fidelity {} for α=({},{}) β=({},{})",
                r.record.fidelity,
                alpha.re, alpha.im, beta.re, beta.im
            );
        }
    }

    #[test]
    fn bell_outcomes_are_uniform_over_the_four_states() {
        // The Born rule must give each Bell state ≈25% — Alice cannot choose
        // the outcome, which is exactly what makes it signature material.
        let mut counts = [0usize; 4];
        let mut rng = StdRng::seed_from_u64(3);
        let trials = 4000;
        for _ in 0..trials {
            let alpha = Amplitude::new(0.8, 0.0);
            let beta = Amplitude::new(0.6, 0.0);
            let r = teleport_state(alpha, beta, &mut rng);
            counts[r.record.bell_state as usize] += 1;
        }
        for (i, c) in counts.iter().enumerate() {
            let p = *c as f64 / trials as f64;
            assert!(
                (p - 0.25).abs() < 0.03,
                "Bell state {i} probability {p:.3} deviates from 0.25"
            );
        }
    }

    #[test]
    fn pre_correction_state_is_the_pauli_image_of_the_input() {
        // Bob's pre-correction state must be exactly the correction operator
        // applied to |φ⟩ — verifying the entanglement correlations, not just
        // the final answer. Magnitude pattern per outcome (Z is phase-only):
        //   Φ⁺ (I):  (|α|², |β|²)      Ψ⁺ (X):  (|β|², |α|²)
        //   Φ⁻ (Z):  (|α|², |β|²)      Ψ⁻ (ZX): (|β|², |α|²)
        let mut rng = StdRng::seed_from_u64(4);
        let (a2, b2) = (0.36, 0.64); // α=0.6, β=0.8
        for _ in 0..400 {
            let r = teleport_state(Amplitude::new(0.6, 0.0), Amplitude::new(0.0, 0.8), &mut rng);
            let p0 = r.record.bob_alpha_pre.modulus_squared();
            let p1 = r.record.bob_beta_pre.modulus_squared();
            let (want0, want1) = match r.record.correction {
                PauliCorrection::I | PauliCorrection::Z => (a2, b2),
                PauliCorrection::X | PauliCorrection::ZX => (b2, a2),
            };
            assert!(close(p0, want0) && close(p1, want1),
                "correction {:?}: pre-state probs ({p0:.3}, {p1:.3}), wanted ({want0:.3}, {want1:.3})",
                r.record.correction);
            assert!(close(r.record.fidelity, 1.0));
        }
    }

    #[test]
    fn classical_bits_match_correction_table() {
        assert_eq!(BellState::PhiPlus.classical_bits(), [0, 0]);
        assert_eq!(BellState::PsiPlus.classical_bits(), [0, 1]);
        assert_eq!(BellState::PhiMinus.classical_bits(), [1, 0]);
        assert_eq!(BellState::PsiMinus.classical_bits(), [1, 1]);
        assert_eq!(BellState::PsiMinus.correction(), PauliCorrection::ZX);
    }

    #[test]
    fn measurement_statistics_follow_the_born_rule() {
        // Measuring |+⟩ many times must give 50/50.
        let mut rng = StdRng::seed_from_u64(5);
        let mut ones = 0usize;
        let trials = 2000;
        for _ in 0..trials {
            let mut sv = StateVector::zero(1);
            sv.apply_single(0, hadamard());
            ones += sv.measure(0, &mut rng) as usize;
        }
        let p = ones as f64 / trials as f64;
        assert!((p - 0.5).abs() < 0.03, "P(1) = {p:.3} for |+⟩");
    }
}
