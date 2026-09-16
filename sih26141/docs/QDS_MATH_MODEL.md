# Deliverable 1 — Mathematical Model of the Teleportation-based QDS

Formal description of the signature protocol implemented in the `qds` crate,
covering every component named in the problem statement: **Bell-state
entanglement, quantum teleportation, Pauli correction operations, and
projective measurement rules.**

*Companion documents:* `PROJECT_GUIDE.md` (full theory + codebase tour) and
`JUDGE_PITCH.md` (presentation playbook). This document is the formal
reference — equations first, code pointers alongside.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| $\mathcal{B} = \{\ket{\Phi^+}, \ket{\Phi^-}, \ket{\Psi^+}, \ket{\Psi^-}\}$ | the four Bell states |
| $P \in \{I, X, Z, XZ\}$ | single-qubit Pauli operations |
| $m \in \{0,1\}^*$ | the message; $h = \text{SHA-256}(m)$ its digest |
| $q$ | signature qubits (message-hash bits used) |
| $\lambda$ | Bell-pair depth per qubit (security multiplier) |
| $A_1[i][j], A_2[i][j]$ | hidden Bell-correlation bits, $i \in [q],\ j \in [\lambda]$ |
| $x_{ij}, z_{ij}$ | the two published signature bits at position $(i,j)$ |

## 2. Bell-state entanglement (resource preparation)

Trent prepares $2\,q\lambda$ maximally-entangled pairs in the plus state:

$$
\ket{\Phi^+} = \tfrac{1}{\sqrt{2}}\left(\ket{00} + \ket{11}\right)
$$

One half of each pair goes to Alice; Trent retains the other half. The
entanglement correlations are the entire secret resource: **no classical bit
exists before measurement**, so nothing can be intercepted in transit.

*Simulation note:* the qds crate models a pair as the correlation structure
consumed by teleportation — Alice's Bell outcome is uniform over 4, and Bob's
raw half is conditionally determined (see §3).

## 3. Quantum teleportation of a payload qubit

Let Alice want to teleport the payload qubit $\ket{\psi} = \alpha\ket{0} + \beta\ket{1}$
(here: the computational-basis state encoding $x_{ij}$) using her half of a
$\ket{\Phi^+}$ pair. The joint initial state is

$$
\ket{\psi}_1 \otimes \ket{\Phi^+}_{23} =
\tfrac{1}{2}\Big[
\ket{\Phi^+}_{12}\ket{\psi}_3 + \ket{\Phi^-}_{12} X\ket{\psi}_3
+ \ket{\Psi^+}_{12} Z\ket{\psi}_3 + \ket{\Psi^-}_{12} XZ\ket{\psi}_3
\Big]
$$

Alice performs a **Bell measurement** on qubits 1 and 2. She obtains one of
four outcomes, uniformly at random and *not choosable by her*:

| Bell outcome | bits $(b_1 b_0)$ | Bob's state | Required Pauli correction |
|---|---|---|---|
| $\Phi^+$ | 00 | $\ket{\psi}$ | $I$ |
| $\Phi^-$ | 01 | $X\ket{\psi}$ | $X$ |
| $\Psi^+$ | 10 | $Z\ket{\psi}$ | $Z$ |
| $\Psi^-$ | 11 | $XZ\ket{\psi}$ | $XZ$ |

Alice transmits the two classical bits $(b_1 b_0)$; Bob applies the
corresponding **Pauli correction** and holds $\ket{\psi}$ exactly. The
unpredictability of the outcome — Alice cannot choose it, Eve cannot predict
it — is what makes the correction-bit stream signature material.

*Code:* `BellPair::bell_measure` (uniform outcome), `teleport_bit`
(raw half = payload XOR correction's bit-flip), `apply_correction`.

## 4. Key setup (quantum public key distribution)

For each position $(i,j)$, Trent and Alice share two correlation bits
$A_1[i][j], A_2[i][j]$ — each realized by a Bell pair; Alice "learns" them by
measuring her halves at signing time. The **public key** is the commitment

$$
\mathsf{pk} = \text{SHA-256}\big(A_1 \,\|\, A_2 \,\|\, \lambda\big)
$$

plus Trent's nonce registry. The raw correlations are never revealed — Trent
publishes only verification verdicts, so Bob (and Eve) learn nothing about the
key beyond accept/reject decisions.

## 5. Signature generation

Alice signs $m$ by computing the message qubits
$h_i = \text{SHA-256}(m)[i \bmod 32] \mathbin{\&} (1 \ll (i \bmod 8))$
for $i \in [q]$ (`message_qubits`), then for every position $(i,j)$:

1. **Payload:** $p_{ij} = h_i \oplus A_1[i][j]$ — teleported to Bob via §3
   (genuine Bell measurement + Pauli correction each time).
2. **Published bits:**
$$
x_{ij} = p_{ij} = h_i \oplus A_1[i][j], \qquad
z_{ij} = A_1[i][j] \oplus A_2[i][j]
$$
3. The signature is $\sigma = \big(\{x_{ij}, z_{ij}\},\ \mathsf{nonce},\ \mathsf{pk}\big)$.

The teleportation step contributes genuine quantum randomness per position
(Bell outcomes), though the *verification-relevant* content is the two
correlation-bound bits above — this separation keeps the simulation honest
about what the quantum layer contributes: unpredictability and
measurement-bound correlations.

## 6. Verification (projective measurement rules)

Bob asks Trent to check $\sigma' = (\{x'_{ij}, z'_{ij}\}, \mathsf{nonce}', \mathsf{pk}')$
against message $m'$. Trent evaluates, at each position, the two equations

$$
\textbf{(C1)}\quad x'_{ij} \oplus h'_i \overset{?}{=} A_1[i][j]
\qquad\qquad
\textbf{(C2)}\quad z'_{ij} \oplus A_1[i][j] \overset{?}{=} A_2[i][j]
$$

where $h' = \text{SHA-256}(m')$. A position **passes** iff both hold; let
$\mu$ = number of mismatched positions out of $N = q\lambda$. The decision
rule (statistical threshold, no ML):

$$
\mathsf{accept}(\sigma', m') \iff
\underbrace{\mathsf{nonce}' \text{ fresh}}_{\text{replay defense}}
\;\wedge\;
\underbrace{\mathsf{pk}' = \mathsf{pk}}_{\text{key binding}}
\;\wedge\;
\underbrace{\mu / N \le \tau}_{\text{measurement statistics}}
$$

with tolerance $\tau = 0$ in the noiseless simulation (the `detection`
crate's Hoeffding machinery provides $\tau > 0$ for noisy channels).
On acceptance the nonce is consumed and $(\text{SHA-256}(m), \mathsf{nonce})$
enters the public ledger.

*Theorem (deterministic correctness).* If $\sigma$ was produced by §5 over
$m$ with the key in force and is presented fresh, then C1 and C2 hold at
every position ($\mu = 0$), so the signature is accepted — "deterministic
acceptance of legitimate signatures" per the problem statement.
*Proof:* substitute $x_{ij} = h_i \oplus A_1$ into C1 (equality), and
$z_{ij} = A_1 \oplus A_2$ into C2 (equality). $\square$

*Code:* `qds::verify` — structural checks, replay check, then C1/C2
statistics.

## 7. Security analysis (forgery probabilities)

**Theorem (forgery bound).** A forger with no knowledge of $\{A_1, A_2\}$
who guesses each position's two bits uniformly succeeds at that position with
probability $1/4$ (both equations must hold simultaneously). Across $N$
independent positions:

$$
P_{\text{forge}} = \left(\tfrac{1}{4}\right)^{N} = 4^{-q\lambda}
$$

| $q$ | $\lambda$ | $P_{\text{forge}}$ |
|---|---|---|
| 16 | 4 | $4^{-64} \approx 2.9 \times 10^{-39}$ |
| 16 | 8 | $4^{-128} \approx 8.7 \times 10^{-78}$ (≈ 2⁻²⁵⁶) |
| 32 | 8 | $4^{-256} \approx 7.6 \times 10^{-155}$ |

*Monte-Carlo validation:* `estimate_forgery_probability` runs full
setup-+-forgery trials with random guessed signatures; at $(q{=}1,\lambda{=}1)$
the empirical rate converges to $0.25$ as predicted, and the API endpoint
`/api/qds/forgery-analysis` reports theory vs. simulation plus the λ-scaling
curve.

**Attack coverage:**

| Attack | Mechanism | Why it fails |
|---|---|---|
| Forgery | Guess $(x, z)$ at every position | $P \le 4^{-q\lambda}$; rejected with overwhelming probability |
| Impersonation | Re-present $\sigma_m$ as signature over $m' \ne m$ | C1 becomes $x \oplus h'_i = A_1$ — fails wherever $h'_i \ne h_i$ (≈ half of positions for any different digest) |
| Replay | Re-present an accepted $(\sigma, m)$ verbatim | Nonce registry: $\mathsf{nonce}$ already consumed ⇒ rejected before statistics |
| Channel tampering | Eve disturbs teleported qubits / correction bits | Genuine bits no longer satisfy C1/C2; mismatch ratio ∝ tamper fraction ⇒ exceeds $\tau$ |

**Information-theoretic character.** The only secret ever exposed to a
verifier is accept/reject; key bits enter published signatures exclusively
under XOR with the message digest, which is information-theoretically
uniformly random to anyone not knowing $\{A_1, A_2\}$. No computational
assumption (factoring, discrete log) appears anywhere in the argument —
matching the problem statement's requirement to preserve
information-theoretic security guarantees. (The SHA-256 commitment is the one
classical-cryptographic ingredient; treating it as a random oracle keeps the
commitment binding/hiding.)

## 8. Complexity

Signing: $O(q\lambda)$ Bell measurements + corrections; verification:
$O(q\lambda)$ XOR checks (each $O(1)$). Total $O(q\lambda)$ time, $O(q\lambda)$
key storage — for $q{=}16, \lambda{=}4$: 64 positions, microseconds on any
modern CPU, satisfying "low computational complexity" with no AI/ML
components anywhere in the pipeline.

## 9. Implementation map

| Model element | Code |
|---|---|
| Bell states / entanglement | `qds::BellPair` |
| Teleportation + Pauli corrections | `qds::teleport_bit`, `apply_correction`, `PauliOp`, `BellOutcome` |
| Key setup / commitment | `Trent::setup`, `QuantumPublicKey` |
| Signing | `qds::sign` |
| Verification (projective-measurement statistics) | `qds::verify`, `VerificationReport` |
| Nonce ledger / replay defense | `Trent::used_nonces`, `Trent::ledger` |
| Attack simulations | `qds::attacks::{attempt_forgery, attempt_impersonation, attempt_replay, attempt_channel_tampering}` |
| Forgery probability analysis | `theory_forgery_probability`, `estimate_forgery_probability` |
| Noisy-channel thresholds (c1/c2 sizing) | `qds::noisy::{noisy_thresholds, assess_mismatch}` |
| Six-state scheme (Weng et al.) | `qds::six_state::{build_session, sign_six_state, verify_six_state, classify}` |
| Repeatable evaluation | `qds::metrics::evaluate`, `/api/qds/metrics` |
| Transferability / non-repudiation | `qds::verify_transferability` |
| Security-event audit log | `server::qds_state::QdsState::record` → `qds_events.jsonl` |

---

## 9.1 Statistical tail events in the evaluation (finite-sample honesty)

The repeatable evaluation (`qds::metrics`) is a **bounded-error statistical
test**, so its detection rate at finite sample size is bounded away from 1 by
the same ε-vs-n law as §1.8 of the project guide. Concretely, at the dashboard
default (200 trials, seed 42):

* **Channel-tampering class (≈1 miss / 200):** the scenario disturbs 30% of
  qubits; the induced conclusive-mismatch rate over n ≈ 400 positions is
  Binomial(0.375, n) judged against c2 = 0.25. The gap is ≈ 2.7σ, so a
  one-in-~250 downward fluctuation is expected roughly once per 200 trials —
  observed exactly once.
* **Teleportation impersonation class (≈1 miss / 200):** message binding uses
  q = 8 digest bits in the evaluation, so two distinct messages collide on all
  signature-relevant bits with probability 2⁻⁸ = 1/256 per trial — again
  observed once in 200.

Both tails shrink exponentially with the corresponding security parameter
(n → ∞ and q → 16+ respectively). At the production signing parameters
(q = 16, λ = 4) the forgery bound of §7 remains 4⁻⁶⁴ ≈ 2.9 × 10⁻³⁹.

---

*Scope honestly noted: this is a classical simulation of the quantum
protocol (ideal Bell pairs, noiseless channel, no qubit storage). It models
the information structure of teleportation-based QDS faithfully; it does not
perform physical quantum operations.*

---

## 10. Relation to the literature

The framework operationalizes the three reference papers:

**Gottesman & Chuang (2001), "Quantum Digital Signatures" (arXiv:quant-ph/0105032).**
The foundational QDS protocol. From it we adopt:
- the **three-outcome verification semantics** — 1-ACC (valid and transferable),
  0-ACC (valid, transferability not guaranteed), REJ — §4 of the paper, our
  `Verdict` enum and dual thresholds `c1 ≤ mismatch < c2` (their acceptance /
  rejection thresholds);
- the **second security criterion (non-repudiation / transferability)**: if the
  first verifier reaches 1-ACC, any second verifier must reach non-REJ. This is
  implemented as `verify_transferability` — an independent, side-effect-free
  statistical re-check exposed as the "Charlie consensus" in the API/UI;
- the principle that a signature's security parameter must make failure
  probability *exponentially small* — our $4^{-q\lambda}$ bound (their
  $M$-copies-of-key security parameter plays the same role as our $\lambda$).

**Singh et al. (2023), "Securing Blockchain Transactions Using Quantum
Teleportation and Quantum Digital Signature" (Neural Processing Letters 55:3827).**
The application-layer blueprint. From it we adopt:
- the **three-stage pipeline**: sign at the sender → distribute via teleportation
  (EPR pairs, Bell measurement, two classical bits, Pauli correction at the
  receiver) → validate by counting incorrect keys — exactly our
  `sign` → `teleport_bit` → `verify` flow (their Fig. 5 ≙ our §5–§6);
- the **dual-threshold decision** on the mismatch count: accept if below $T_a$,
  reject if above $T_b$, uncertain between — our `Thresholds { c1, c2 }` and
  1-ACC / 0-ACC / REJ mapping ($T_a \equiv c_1$, $T_b \equiv c_2$);
- **double-spend / replay resistance** through one-time signature validity —
  their argument that a teleportation-consumed signature cannot be re-presented
  is realized concretely by our nonce ledger.

**Weng et al. (2021), "Secure and practical multiparty quantum digital
signatures" (arXiv:2104.12059).** The modern practical protocol. From it we adopt:
- the **six-state Pauli-eigenstate encoding** ($|{\pm x}\rangle, |{\pm y}\rangle,
  |{\pm z}\rangle$ with bit-value mapping) — the same state space as our QKD
  layer (`quantum::PauliBasis/PauliState`), unifying both halves of the project;
- **mismatching-rate estimation with threshold decision rules** — their core
  detection primitive (§III estimation step) is the same statistical rule as our
  `detection::ThreatDetector` with the Hoeffding finite-key margin;
- **consensus among verifiers** (their majority voting over recipients) —
  simplified to the two-verifier (Bob authenticator + Charlie verifier)
  transferability check appropriate for the three-party setting.

### 10.1 The six-state scheme as a second full implementation (`qds/src/six_state.rs`)

Beyond borrowing the state space, the framework implements Weng et al.'s
**key generation → estimation → messaging** protocol end to end as a second,
independent QDS scheme alongside the teleportation pipeline:

- **Key generation.** For each message value $m \in \{0,1\}$, Alice prepares
  $n$ six-state qubits, assigns each to one of the 12 encoding-set pairs
  (the set always contains her sent state), and recipients measure in
  uniformly random Pauli bases. The **conclusive-result rule**: an outcome
  equal to the *orthogonal partner* of a set member (same basis, opposite
  sign) is conclusive, with logic bit = the other member's bit. The ideal
  conclusive (click) rate $P_c = 1/6$ emerges naturally from the encoding —
  exactly the value the paper's protocol requires recipients to verify
  (`conclusive_bit`, `build_session`; test-asserted).
- **Estimation.** Test-bit sampling estimates the mismatching rate of
  conclusive results between Alice's string and each verifier's string
  (`estimate_mismatch`).
- **Messaging.** Alice publishes her untested string as the signature; the
  verifier's decision is the dual-threshold rule on the conclusive-mismatch
  rate ($c_1/c_2$, 1-ACC / 0-ACC / REJ) — `sign_six_state` /
  `verify_six_state`.
- **Detection layer.** The same conclusive-string statistics expose all five
  threat classes of the problem statement: a guessed string mismatches near
  the ½ floor, a transplanted string mismatches against the wrong message
  value, tampering raises the rate ∝ disturbance fraction, and a verifier
  without conclusive key material cannot produce any trusted verdict. The
  threshold-rule classifier `classify` attributes evidence to
  forgery / impersonation / replay / channel tampering / unauthorized
  verification — deterministic and explainable, no AI/ML.

**What is intentionally simplified** (and flagged as such): quantum memory,
weak coherent-state sources with decoy intensities, post-matching efficiency
techniques, and the multiparty (>3 participants) scaling of Weng et al. The
information structure — entanglement-based unclonable key material,
teleportation with Pauli corrections, statistical threshold verification,
transferability consensus — is modeled faithfully end to end.

### Reference list

1. D. Gottesman and I. Chuang, *Quantum Digital Signatures*, arXiv:quant-ph/0105032 (2001).
2. S. Singh, N. K. Rajput, V. K. Rathi, H. M. Pandey, A. K. Jaiswal, P. Tiwari,
   *Securing Blockchain Transactions Using Quantum Teleportation and Quantum Digital
   Signature*, Neural Processing Letters 55, 3827–3842 (2023).
3. C.-X. Weng, Y.-S. Lu, R.-Q. Gao, Y.-M. Xie, J. Gu, C.-L. Li, B.-H. Li, H.-L. Yin,
   Z.-B. Chen, *Secure and practical multiparty quantum digital signatures*,
   arXiv:2104.12059 (2021).
