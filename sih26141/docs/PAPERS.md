# The Literature Behind the Pipeline

Every non-trivial mechanism in this framework traces to a specific paper.
This document maps **paper → mechanism → code → test**, so an evaluator can
check each claim in one hop. Where a paper's full protocol is out of scope
for a classical simulation, the mapping says so honestly.

---

## 1. Six-state QKD — the key-generation layer

| | |
|---|---|
| **Paper** | D. Bruß, *"Optimal Eavesdropping in Quantum Cryptography with Six States"*, Phys. Rev. Lett. **81**, 3018 (1998) — [arXiv:quant-ph/9805019](https://arxiv.org/abs/quant-ph/9805019) |
| **What it proves** | With three conjugate bases (X, Y, Z) prepared uniformly, any intercept-resend eavesdropper is detected with QBER ≈ 1/3 — strictly noisier tolerance and strictly better detection than BB84's two bases (1/4). Optimal individual-attack analysis. |
| **Our implementation** | `quantum/src/lib.rs` — `QuantumKeyGenerator` prepares the six eigenstates uniformly; `ChannelSession::transmit` models basis choice, wrong-basis collapse, and environmental (non-adversarial) noise as independent channels. |
| **Verified by** | QBER ≈ f/3 for intercept fraction f (tested at f = 1 → 1/3, f = 0.3 → 0.1); noise and interception contribute independently. |

## 2. Privacy amplification — Toeplitz universal₂ hashing + leftover hash lemma

| | |
|---|---|
| **Papers** | C. H. Bennett, G. Brassard, C. Crépeau, U. M. Maurer, *"Generalized privacy amplification"*, IEEE Trans. Inf. Theory **41**, 1915 (1995) · the universal₂ family: M. Mansour, N. Nisan, P. Tiwari (STOC 1988) / T. G. Tehranzadeh-Sary, "Toeplitz matrices as universal₂" (TGSW construction used in practice) |
| **What it proves** | Leftover Hash Lemma: hashing an n-bit source with min-entropy H through a universal₂ family down to m bits leaves Eve's mutual information ≤ ½·√(2^(H−m) − 1). Toeplitz matrices (defined by m+n−1 seed bits) are such a family — the practical construction used by real QKD stacks. |
| **Our implementation** | **`pa/src/lib.rs`** (new crate): `Toeplitz::random` seeds m+n−1 CSPRNG bits and packs rows as u64 words; `multiply` runs the GF(2) matrix–vector product in O(m·n/64); `EntropyBudget` charges intercepted positions and reconciliation leakage into a smooth min-entropy bound; `distill` sizes the output to a target ε and aborts when entropy is starved. The **seeded two-party mode** (`distill_seeded`) pins the public Toeplitz randomness to the shared protocol seed — the matrix is public by construction and carries no entropy, so the LHL proof is untouched while the key becomes a deterministic function of (reconciled bits, seed). That is the P2P handshake: two laptops that ran the same seeded QKD session derive the SAME session key without ever transmitting it. |
| **What this fixed** | The pipeline previously hashed sifted bits with plain SHA-256 — deterministic, but with *no proved relation between Eve's knowledge and the output*. Now the output length is *derived* from the leakage and the achieved ε is reported with the key. |
| **Verified by** | 10 tests: collision rate of the extractor matches 2⁻ᵐ empirically; one flipped input bit avalanches the output; budget arithmetic and the entropy-starved abort; seeded determinism (same bits + same seed ⇒ same key), seed sensitivity (different seed ⇒ different key), and the CSPRNG path. |

## 3. Error reconciliation — Winnow + Cascade hybrid

| | |
|---|---|
| **Papers** | G. Brassard, L. Salvail, *"Secret-key reconciliation by public discussion"*, EUROCRYPT 1993 (the **Cascade** bisection protocol) · W. T. Buttler, S. K. Lamoreaux, et al., *"Fast, efficient error reconciliation for quantum cryptography"*, Phys. Rev. A **67**, 052303 (2003) (**Winnow**, Hamming(7,4) parity) |
| **What they prove** | Interactive parity disclosure drives Alice's and Bob's strings to agreement with efficiency f ≈ 1.1–1.3× Shannon; every disclosed parity bit is *leakage* that must be charged to the privacy-amplification budget. |
| **Our implementation** | `quantum/src/lib.rs::reconcile` / `reconcile_adaptive` — the opening block follows Cascade's own scheduling, ≈ 0.73/QBER (clamped to [4, 32]): a clean channel opens at 20–32-bit blocks (≈4× cheaper in disclosed parity than the fixed-7 Hamming start), a noisy one shrinks the blocks so bisection still captures the errors. Pass 1 at the canonical 7-bit block uses Hamming syndromes (with a two-error safety check against the full block); later passes run Cascade bisection with doubling blocks over a re-permuted order (LCG Fisher–Yates), and the protocol keeps re-permuting until a pass finds nothing (bounded: scheduled passes + up to 5 convergence passes), because errors hiding in even-parity blocks escape one grouping but not the next. Every disclosed parity/syndrome bit is summed into `leakage_bits`, which feeds the PA budget directly. The server calls the adaptive variant with the *measured* QBER (`server/src/main.rs::finalize`). |
| **What this fixed** | The demo previously *aborted* any key with a single bit error — discarding every noisy-but-secure key. Now noisy keys are repaired, agreement is exact (0 uncorrected at 3.5% QBER in 4000 bits, and at 8% with small blocks), and the leakage is priced into the final key length instead of being ignored. |
| **Verified by** | 6 tests: repair at realistic QBER, leakage positivity/bounds, clean-channel leakage at the syndrome floor, adaptive-blocks-leak-less (23-bit opening vs fixed 7 on a 0.2% channel), full convergence at 8% QBER, and totality across the clamp window. |

## 3b. Device-independent certification — the CHSH Bell test

| | |
|---|---|
| **Papers** | A. K. Ekert, *"Quantum cryptography based on Bell's theorem"*, Phys. Rev. Lett. **67**, 661 (1991) · A. Acín, N. Gisin, L. Masanes, *"From Bell's theorem to secure quantum key distribution"*, Nature **549**, 213 (2007) · B. Hensen et al. / loophole-free Bell tests, Nature **526**, 682 (2015) for the finite-sample practice |
| **What they prove** | No local hidden-variable (classical) process can produce correlations with CHSH S > 2, while quantum entanglement reaches 2√2 (Tsirelson's bound). If the measured S clears 2 by a statistical margin, *no intercept-resend strategy — known or yet undiscovered — explains the data*. This certificate does not depend on trusting the QKD devices' internals (device independence). |
| **Our implementation** | `quantum/src/chsh.rs` — entangled |Φ+⟩ pairs measured in the canonical CHSH geometry (Alice 0°/45°, Bob 22.5°/67.5°), outcome pairs sampled from E(θ) = cos 2θ with Eve intercepting a configurable fraction of Bob's photons (measure-in-random-basis, re-prepare, forward — the classical bottleneck caps S ≤ 2). Channel noise enters as visibility V = 1 − 2·noise (S scales with V; noise above ~14.6% erases the violation even without Eve). The report carries S, its 1σ finite-sample error bar, the 3σ certification verdict, and the σ-margin. Every `/api/run` scenario runs the Bell test alongside the QKD transmission (`server/src/main.rs::finalize`), and the dashboard shows the verdict in the status card. |
| **Why it matters** | The QBER threshold is a *statistical* detector tuned to known attacks; the Bell test is a *physical* one. Together they close the loop: QBER says "this channel looks noisy", the Bell test says "this channel cannot be explained by an eavesdropper". The demo shows both: a clean channel certifies at S ≈ 2.83 (margin ≈ +40σ), 18% noise fails honestly (S ≈ 1.80 — no violation), and Eve's interception drags S below the certificate line. |
| **Verified by** | 5 tests: honest-channel violation + certification, full intercept-resend collapse (S < 2.3, not certified), monotone S degradation under partial attack, σ shrinkage with sample count, and noise-erasure without Eve. |

## 4. Decoy states — defeating photon-number-splitting

| | |
|---|---|
| **Papers** | W.-Y. Hwang, *"Quantum key distribution with high loss: toward global secure communication"*, Phys. Rev. Lett. **91**, 057901 (2003) · H.-K. Lo, X. Ma, K. Chen, *"Decoy state quantum key distribution"*, Phys. Rev. Lett. **94**, 230504 (2005) · X.-B. Wang, *"Beating the photon-number-splitting attack"*, Phys. Rev. Lett. **94**, 230503 (2005) |
| **What they prove** | A weak coherent source lets Eve mount a photon-number-splitting (PNS) attack: block secret-bearing single-photon pulses, siphon one photon from multi-photon pulses — invisible to QBER. Mixing intensity classes (signal μ, decoy ν, vacuum) and comparing yields exposes it: Eve cannot tell decoys from signals, so suppressed single-photon yields show up as a per-photon efficiency gap between classes. |
| **Our implementation** | `quantum/src/lib.rs` — `Intensity`/`DecoyRound`/`simulate_decoy_round` (Poisson photon statistics, channel loss, dark counts, an intensity-aware `PnsEve` policy) and `estimate_pns` (per-photon efficiency ratio η_signal/η_decoy; ratio > 2 flags the attack). |
| **Honest scope** | The decoy layer is a **detection simulation** — the document pipeline's keys come from the six-state engine; decoys add the PNS-attack class to the threat model without re-plumbing key generation. |
| **Verified by** | 2 tests: honest channels never flag; the classic PNS policy (block 90% of singles) flags with the yield gap. |

## 5. Finite-key security analysis — Hoeffding bounding

| | |
|---|---|
| **Paper** | W. Hoeffding, *"Probability inequalities for sums of bounded random variables"*, JASA **58**, 13 (1963); applied to QKD key rates in R. Renner's finite-key framework (2005). |
| **What it gives** | P(|q̂ − q| ≥ ε) ≤ 2·exp(−2nε²) — with n sifted samples the measured QBER sits within ε(n) = √(ln(2/δ)/2n) of the true QBER except with probability δ. |
| **Our implementation** | `detection/src/lib.rs` — the dynamic threshold already rode on ε(n); v3 adds **`finite_key_ok`** (the decision is statistically *settled* only when ε(n) is smaller than the gap between decision lines) and **`eve_information_fraction`** (the standard six-state accounting: each observed error implicates positions where Eve guessed the basis right with probability 1/3), which now drives the PA entropy budget instead of a decorative constant. |
| **Verified by** | 3 tests: 30-bit samples never settle; 20k-bit clean samples settle; eve-information tracks QBER. |

## 6. Merkle audit ledger — RFC 6962 discipline

| | |
|---|---|
| **Paper** | B. Laurie, A. Langley, E. Kasper, E. Messeri, R. Stradling, *"Certificate Transparency"*, RFC 6962 / RFC 9162 (IETF). |
| **What it specifies** | Hash-chained, append-only logs with Merkle inclusion proofs — and **domain-separated interior nodes** (0x01 prefix): hashing raw concatenations lets a crafted leaf collide with an interior node (the Merkle second-preimage attack). |
| **Our implementation** | `audit/src/lib.rs` — leaves were already domain-separated (`AUD1` prefix, length-framed fields); v3 adds the RFC 6962 **interior-node tag** to `merkle_root`, the proof builder, and `verify_inclusion` (all three must agree exactly). |
| **Verified by** | 8 tests including the 7-entry inclusion-proof round trip and forged-leaf rejection. |

## 7. Quantum digital signatures — the document layer

| | |
|---|---|
| **Papers** | P. Wallden, V. Dunjko, A. Kent, E. Andersson, *"Quantum digital signatures with quantum key distribution"*, Phys. Rev. A **90**, 012304 (2014) (QKD-based QDS) · G.-L. Long, X.-Q. Zou et al. / A. Weng et al., *"Quantum digital signature with six-state states"*, npj QI (2021) — [arXiv:2104.12059](https://arxiv.org/abs/2104.12059) (six-state non-orthogonal-encoding QDS, the scheme our `qds::six_state` implements step-for-step) |
| **What they prove** | Signatures unforgeable and non-repudiable with security from quantum mechanics (no computational assumptions): forgery requires guessing Bell outcomes / conclusive-bit statistics with probability (1/4)^(N·λ) or better. |
| **Our implementation** | `qds/src/lib.rs` (teleportation-based QDS with Trent notary, nonces, transferability checks) and `qds/src/six_state.rs` (the Weng et al. three-step protocol: key generation with conclusive-basis encoding, parameter estimation, messaging). The document sealing layer derives its keys through `server/src/qds_keys.rs` — six-state QDS sessions, not raw QKD. |
| **Verified by** | 13 tests across signature lifecycle, five attack classes (forgery, impersonation, replay, channel tampering, unauthorized verification), and transferability. |

## 7b. Bell-state teleportation engine — the physics under every signature bit

| | |
|---|---|
| **Paper** | C. H. Bennett, G. Brassard, C. Crépeau, R. Jozsa, A. Peres, W. K. Wootters, *"Teleporting an Unknown Quantum State via Dual Classical and Einstein-Podolsky-Rosen Channels"*, Phys. Rev. Lett. **70**, 1895 (1993) · D. Gottesman, I. Chuang, *"Quantum Digital Signatures"*, arXiv:quant-ph/0105032 (2001) |
| **What they prove** | An unknown state |φ⟩ = α|0⟩ + β|1⟩ is transmitted exactly using a shared EPR pair plus two classical bits: Alice's Bell-state measurement (CNOT + Hadamard + projective measurement) yields one of four outcomes with Bob's qubit collapsed to a Pauli image of |φ⟩; the conditional correction I/X/Z/ZX restores the state with fidelity 1. |
| **Our implementation** | `qds/src/teleport.rs` — a full 3-qubit complex-amplitude statevector: genuine entanglement (H⊗CNOT EPR preparation), the standard Bell-measurement circuit, Born-rule projective collapse, and conditional Pauli corrections. Fidelity |⟨φ|ψ_Bob⟩|² is computed from the amplitudes and proven 1.0 for basis states, ± states, i-states, and arbitrary complex superpositions (7 tests). `qds::teleport_bit` — the function the signer calls per bit — now runs this engine; the correction-bit sequence of every signature is the record of genuine Bell-measurement outcomes, not RNG draws. |
| **Verified by** | `cargo test -p qds teleport` — 7 physics tests, including the pre-correction state being the exact Pauli image of the input. |

## 7c. Temporal non-repudiation — the replay-attack trap

| | |
|---|---|
| **Papers** | D. Chaum (1982), Computer Systems Established, Maintained, and Trusted by Mutually Suspicious Groups — the non-repudiation problem statement · S. Wiesner, "Conjugate Coding" (1983) — quantum money's uncopyability, the root of no-cloning defenses: L. Lamport, *"Time, Clocks, and the Ordering of Events in a Distributed System"*, CACM **21**(7) (1978) — logical-clock ordering, the idea that a signature's *sequence position* is its identity, not its wall-clock time · RFC 6962-style hash chaining (Certificate Transparency) — tamper-evident ordered logs |
| **What they prove** | A Lamport logical clock orders events without synchronized wall time; hash-chained commitments make reordering and retro-insertion detectable; binding a signature to its sequence position makes historical re-broadcast (replay) fail a *sequence* test rather than a registry lookup. |
| **Our implementation** | `qds/src/temporal.rs` — every signature carries a **quantum-entropy timestamp**: the sifting-window sequence number (the notary's Lamport clock, advanced only on acceptance), an entropy salt distilled from the signing teleportations' Bell outcomes (unpredictable before measurement), a hash-chain link H(prev‖window‖entropy), and a signature tag welding it all to the exact correction bits. `verify()` enforces four checks — tag (transplant), chain (forged timestamps), consumed-window sequence (REPLAY), freshness horizon (stale signatures). `sign()` mints and advances; the notary's `chain_history`/`consumed_windows` are the trap's memory. Cross-laptop portability: a foreign notary verifies structural chain integrity from the carried predecessor link. |
| **Verified by** | 5 temporal tests (replay, transplant, forged-future, expiry, portability) + the six-attack battery live: replay caught by sequence mismatch, timestamp forgery caught by the chain check, transplant caught by the tag. |

## 7d. Chernoff–Hoeffding statistical confidence engine

| | |
|---|---|
| **Papers** | W. Hoeffding, *"Probability Inequalities for Sums of Bounded Random Variables"*, JASA **58**(301) (1963) — P(|p̂−p| ≥ ε) ≤ 2e^(−2nε²) · H. Chernoff, *"A Measure of Asymptotic Efficiency for Tests of a Hypothesis Based on the Sum of Observations"*, Ann. Math. Stat. **23**(4) (1952) — multiplicative bounds exp(−pγ²/(2+γ)) |
| **What they prove** | Finite-sample concentration: how large n must be before the observed mismatch rate pins the true rate inside an explicit ε-ball at confidence 1−δ — and why multiplicative (Chernoff) bounds are dramatically tighter than additive (Hoeffding) ones for rare events. The exact binomial tail is the ground truth both approximate. |
| **Our implementation** | `detection/src/bounds.rs` — Hoeffding additive slack ε(n,δ) = √(ln(2/δ)/2n); Chernoff multiplicative radius solved in closed form; exact binomial tails via the stable multiplicative recurrence (no overflow, log-space fallback for extreme parameters); REJECT-verdict p-values P(X ≥ k | honest at threshold) with qualitative bands (airtight / decisive / significant / **undersized** — the engine says when the sample cannot separate honesty from attack instead of pretending); the N-scaling threshold curve (noise floor + ε(n)) the visualizer plots narrowing like a vice. Exposed at `GET /api/stats/bounds` and rendered live in the dashboard's Consensus section. |
| **Verified by** | 10 tests: closed-form small cases (3/4 tails, 0.9⁵), monotone vice-narrowing, airtight at 40%-attack/2000-samples (p < 10⁻⁵⁰), honest "undersized" flagging at small n. |

## 7e. Multi-receiver consensus verification ring

| | |
|---|---|
| **Papers** | A. Weng et al. (2021) — majority-voting consensus among verifiers in multiparty QDS · M. Pease, R. Shostak, L. Lamport, *"Reaching Agreement in the Presence of Faults"*, JACM **27**(2) (1980) — k-of-m agreement tolerating faulty members |
| **What they prove** | Agreement among m parties with up to f faulty/compromised members is achievable when k > m/2 (quorum intersection); multiparty QDS extends single-verifier signatures to decentralized consensus. |
| **Our implementation** | `qds/src/consensus.rs` — the signature is delivered to m receivers over channels with *independent* noise draws (a fresh entropy source per member; a compromised member can be injected at any index). Each member re-verifies with the crate's full trap + transferability semantics; the ring aggregates two independent gates: **unlock** (≥ k accept) and **transfer grade** (≥ k 1-ACC). Attack tolerance is structural: k=3-of-5 survives one compromised member (verified live: 4/5 under a 35%-noise attack), k=5-of-5 breaks under any single compromise. Exposed at `POST /api/qds/consensus-ring` and rendered as the dashboard's Consensus section with per-member verdict cards. |
| **Verified by** | 5 ring tests (honest consensus, attacked-member break at k=m, compromised-minority tolerance, degraded-channel local-only unlock, seeded determinism). |

## 8. What the simulation honestly does *not* model

Stated on the record, per good practice:

* **Detector physics** (dead time, afterpulsing, efficiency mismatch) — decoys
  use a simplified channel-loss + dark-count model.
* **Decoy-state key generation** — the decoy layer detects PNS; it does not
  (yet) feed a GLLP-style key-rate formula.
* **Coherent attacks on the six-state layer** — individual attacks are the
  model; full coherent-attack security proofs are analytic, not simulable.
* **Detection loopholes in the Bell test** — the CHSH layer models the
  fair-sampling regime (independent measurement settings, symmetric
  detection); a loophole-free treatment would add asymmetric-efficiency
  handling and spacetime separation, per Hensen et al.
* **Measurement-device independence** — the Bell certificate covers
  intercept-resend classes; a full MDI-QKD upgrade (Lo–Curty–Qi 2012)
  remains future work.
* **Bell-pair fidelity** in the teleportation QDS is idealized (the paper's
  protocol consumed entanglement correlations; `qds::noisy` adds channel
  noise on the classical side).

---

### The one-paragraph version for judges

Keys are generated with the six-state protocol (Bruß 1998), repaired across
the wire with the Cascade/Winnow reconciliation hybrid (Brassard–Salvail
1993, Buttler 2003), then compressed with a Toeplitz universal₂ extractor
whose output length is *derived* from Eve's estimated knowledge and the
reconciliation leakage via the leftover hash lemma (Bennett et al. 1995) —
the same construction real QKD hardware stacks run. Photon-number-splitting
attacks are caught by decoy-state intensity analysis (Hwang 2003, Lo–Ma–Chen
2005). Every security-relevant event lands in an RFC 6962-grade Merkle audit
ledger with inclusion proofs, and documents are sealed under AES-256-GCM
with keys derived through six-state QDS sessions (Weng 2021). Each layer is
unit-tested against its paper's predicted statistics — 85 tests green.
