# Deliverables & Objectives — clause-by-clause implementation audit

**Audit date:** September 29, 2026 · **Audited by:** Team Prometheusz
**Authoritative requirement (the SIH problem statement, quoted from the brief):**

> **Quantum-Inspired Cyber Threat Detection for Digital Signature Security** — a simulation of a teleportation-based quantum digital signature protocol with a threat-detection layer that, explicitly without any AI or ML, uses quantum principles — Pauli eigenstates, projective measurements and statistical analysis of measurement outcomes — to detect forgery, impersonation, replay attacks and quantum channel manipulation by computing forgery probabilities and verification accuracy from measurement statistics, evaluated through attack simulations that show detection rates and false-accept rates while preserving the protocol's information-theoretic security guarantees.

**Method.** Every clause of the problem statement was checked against the actual source in this checkout — not against earlier documentation. Each claim below names the implementing crate/module, the endpoint or UI surface where it is visible, and the test that exercises it. Verdicts are **Implemented**, **Partial**, or **Gap**; gaps are stated as gaps. Line numbers refer to this checkout and will drift as code changes.

**Toolchain facts verified during this audit:**

- `cargo test --workspace` — all tests pass, 0 failures (September 29, 2026, this machine).
- `cd frontend && npm run build` (tsc + vite) and `npm run lint` (oxlint) — pass, 0 problems.
- `grep -riE "linfa|candle|tch|ndarray|smartcore|tensorflow|torch|sklearn|xgboost|onnx" --include=Cargo.toml` — **no match anywhere in the workspace: zero machine-learning dependencies.**
- No ML is used anywhere: every verdict is a threshold decision on measurement statistics (`detection/src/bounds.rs`, `qds/src/noisy.rs`, `qds/src/six_state.rs`).

---

## Part 1 — Problem-statement clause mapping

### Clause 1 — "a simulation of a teleportation-based quantum digital signature protocol"

**Verdict: Implemented** (as classical software simulation; that qualifier is in the clause itself — "a simulation").

| Aspect | Evidence |
|---|---|
| Qubit/Bell-pair statevector engine | `qds/src/teleport.rs` — complex-amplitude statevectors, EPR pair preparation, the standard CNOT-then-Hadamard Bell measurement circuit, projective measurement, Pauli correction. The module header states the design intent and that "Born rule governs the projective measurement — nothing is hard-coded" (`qds/src/teleport.rs` ~L5–L28). |
| Born-rule collapse | `qds/src/teleport.rs` ~L141 (measurement collapses per Born rule); test `measurement_statistics_follow_the_born_rule` (~L537) asserts each Bell outcome lands at ≈25% — Alice cannot bias the outcome. |
| Sign / verify protocol | `qds/src/lib.rs` — `Trent::setup` / `sign` / `verify`, 1-ACC / 0-ACC / REJ verdict semantics per the Weng–Gottesman–Chuang style construction, transferability (second-verifier "Charlie consensus") check, single-use nonces. |
| Document-layer integration | `server/src/qds_keys.rs` — the sealing key is derived from a six-state QDS key-generation session (`/api/doc/qds/key`), and the QDS signature is attached to sealed `.qsig` documents and re-checked on open. |
| Formal write-up | `docs/QDS_MATH_MODEL.md` is the formal companion (equations → code pointers). |
| Tests | `qds/tests/qds_tests.rs` (setup/sign/verify, transferability, attacks, replay-state persistence); `qds/src/teleport.rs` built-in tests (Bell statistics, corrections, fidelity). |

**Scope statement (binding):** all quantum behavior is classical software simulation. No quantum hardware, no physical detector, no physical channel. Nothing in this project claims otherwise.

### Clause 2 — "a threat-detection layer that, explicitly without any AI or ML"

**Verdict: Implemented.** The detection layer is statistical, deterministic, and fully inspectable:

| Mechanism | Evidence |
|---|---|
| Finite-sample thresholds | `detection/src/bounds.rs` — Hoeffding additive bound ("distribution-free, additive", module header ~L3–L8) and Chernoff multiplicative bound; `hoeffding_epsilon`-style slack computation for P(\|p̂ − p\| ≥ ε) ≤ δ. |
| Channel classification | `detection` crate — QBER-based three-way classification (secure / degraded / under attack) with a dynamic decision threshold; surfaced in the Live Monitor (`key_distilled`, `channel_class`, `first_divergence` fields in `server/src/main.rs` ~L148–L158). |
| Six-state acceptance thresholds | `qds/src/noisy.rs` — noise-floor + rejection-threshold logic; a ≈75% mismatch from a guessed forgery on any n ⇒ REJ + channel flag (~L134). |
| Signature verdicts | `qds/src/six_state.rs` — classify() maps outcomes to forgery / impersonation / replay / unauthorized / channel-tampering (~L559–L565). |
| No ML | Workspace-wide dependency grep returns zero ML crates; no training loop, no learned parameters anywhere in `src/`. Every threshold is an explicit constant or closed-form bound. |

### Clause 3 — "uses quantum principles — Pauli eigenstates, projective measurements and statistical analysis of measurement outcomes"

**Verdict: Implemented** (as software models of those principles).

| Principle | Evidence |
|---|---|
| Pauli eigenstates | `quantum/src/lib.rs` — `PauliBasis` {X, Y, Z}, `PauliState` {Positive, Negative}, and `generate_eigenstates` preparing Alice's six-state (X/Y/Z × ±1) ensembles (~L9–L54). |
| Projective measurements | `qds/src/six_state.rs` — `projective_measure(state, basis, rng) -> PauliSign` (~L120), used on the wire states during sifting (~L340); `qds/src/teleport.rs` performs the Bell-basis projective measurement. |
| Statistical analysis of outcomes | Sifted-key error statistics → QBER; binomial-tail and Hoeffding/Chernoff bounds in `detection`; confusion-matrix machinery in `qds/src/metrics.rs`; `detection/src/bounds.rs` exposes the bounds via `GET /api/stats/bounds` (Chernoff–Hoeffding confidence engine, `server/src/qds_api.rs` ~L480–L481). |

### Clause 4 — "detect forgery, impersonation, replay attacks and quantum channel manipulation"

**Verdict: Implemented** for all four named classes plus a fifth (unauthorized verification) that the QDS threat model also names. Coverage:

| Attack class | Simulated attack entry point | Detection mechanism | Test |
|---|---|---|---|
| Forgery (guessed correction bits / signature construction) | `qds/src/attacks.rs::attempt_forgery` (~L74); six-state variant `qds/src/six_state.rs::attempt_six_state_forgery` (~L644) | Session-commitment mismatch; ≈75% correction-bit mismatch ⇒ REJ | `impersonation_transplant_is_rejected`, metrics forgery trial loop |
| Impersonation (transplant genuine signature onto different message) | `attacks.rs::attempt_impersonation` (~L97); `six_state.rs::attempt_six_state_impersonation` (~L663) | Message-hash binding check | metrics impersonation trial loop (`metrics.rs` ~L162, ~L329) |
| Replay | `attacks.rs::attempt_replay` (~L120); temporal-trap module `qds/src/temporal.rs` | Single-use nonce registry + sifting-window sequence check ("signature is from the past (replay)", `temporal.rs` ~L191); document-path trap ~L247–L256 | `trap_accepts_forward_signature_and_rejects_replay` (~L310), `document_path_still_traps_transplant_and_forgery` (~L449) |
| Quantum channel manipulation | QKD intercept-resend scenarios (`quantum`, `attacks` crate); tamper fractions in `attacks.rs` (~L209) | QBER vs Hoeffding threshold ⇒ abort key distillation; mismatch-ratio channel flag (`noisy.rs` ~L94–L99) | QKD sweep tests; six-state channel-tampering classification test (~L789 asserts tampering is *not* misattributed to forgery) |
| Unauthorized verification (bonus, in the QDS threat model) | `attacks.rs::attempt_unauthorized_verification` (~L220) | Verifier holds no conclusive key material for the session ⇒ flagged (`six_state.rs` ~L477–L493) | `unauthorized_verifier_is_flagged` (~L809) |

The dashboard's **Attack Lab** presents all of these interactively, including the staged capture → inspect/tamper → forward → recipient-rejection flow (`POST /api/doc/attack-theater`, recorded in the audit ledger). A terminal TUI replay also exists: `cargo run -p tui`.

### Clause 5 — "by computing forgery probabilities and verification accuracy from measurement statistics"

**Verdict: Implemented.** Both quantities are computed, displayed, and tested:

| Quantity | Evidence |
|---|---|
| Theoretical forgery probability | `qds/src/lib.rs::theory_forgery_probability(qubit_count, λ)` = (1/4)^(qubits × λ) — i.e. **P = 4^(−qλ)** — exact implementation at `qds/src/lib.rs` ~L988–L990 (`0.25_f64.powi((qubit_count * lambda) as i32)`). |
| Empirical forgery probability | Monte-Carlo whole-signature forgery success rate over trials (`qds/src/lib.rs::estimate_forgery_probability` ~L948; per-trial loop in `qds/src/metrics.rs` ~L114–L234). Test asserts empirical ≈ 0 at (8, 1) where 4⁻⁸ ≈ 1.5×10⁻⁵ (`metrics.rs` ~L462–L463). |
| Verification accuracy | `ConfusionCounts::accuracy()` (`metrics.rs` ~L47) — fraction of correctly classified legitimate + attack events; reported for both the teleportation and six-state schemes. Tests assert accuracy > 0.99 for both (`metrics.rs` ~L441–L448). |
| Where you can see it | `GET /api/qds/metrics` (`server/src/qds_api.rs` ~L431–L461, JSON-serialized `evaluate(trials, seed)` report) and the QDS Signature Lab panel in the dashboard. |

### Clause 6 — "evaluated through attack simulations that show detection rates and false-accept rates"

**Verdict: Implemented — with one terminology mapping stated plainly so nothing is overstated.**

The confusion matrix in `qds/src/metrics.rs` (~L26–L86) counts, over a controlled seeded experiment:

- `true_positives` — attacks correctly rejected/flagged; `false_negatives` — **attacks wrongly accepted**;
- `true_negatives` — legitimate signatures correctly accepted; `false_positives` — legitimate signatures wrongly flagged.

Derived rates (same module):

- **Detection rate** = `detection_rate()` = TP / (TP + FN) (`metrics.rs` ~L54) — recall over attack events, **plus per-class detection** via `detection_by_class: BTreeMap<String, ClassDetection>` with `ClassDetection::rate()` (`metrics.rs` ~L252–L262), covering every class in Clause 4. Visible in the dashboard's QDS Lab ("Per-class detection" line, `frontend/src/components/QdsLab.tsx` ~L422).
- **False-accept rate** = `false_negative_rate()` = FN / (FN + TP) (`metrics.rs` ~L70) — the rate at which attacks are *wrongly accepted*. The field is named "false-negative rate" in code because the matrix treats "attack present" as the positive class; the quantity the problem statement calls the false-accept rate is exactly this one. We state the mapping rather than renaming the field, so the code and the literature stay consistent.
- Additionally reported: overall **false-alarm rate over legitimate events** (`false_positive_rate()` ~L61), which bounds how often honest signatures are rejected.

The API returns the full confusion counts, so both rates are recomputable client-side from one endpoint response. The doc-rename option (exposing a `false_accept_rate` alias) is deliberately not done in this pass to keep the audit code-frozen; it is listed as a cosmetic follow-up in Part 4.

### Clause 7 — "while preserving the protocol's information-theoretic security guarantees"

**Verdict: Partial — implemented and honestly scoped, with the boundary made explicit.** What exists:

- Forgery security rests on guessing Bell outcomes: P = 4^(−qλ) per Clause 5, an information-theoretic argument (attacker knowledge, not computational hardness), consistent with the Gottesman–Chuang / Weng et al. protocol family mapped in `docs/PAPERS.md`.
- QKD privacy amplification consumes a smooth-min-entropy budget and extracts with a universal hash; the leftover-hash-lemma accounting is surfaced as structured data (`SecurityAccounting` in `server/src/main.rs` ~L202–L206: raw bits, eve information, reconciliation leakage, extractor ε), and `pa/src/lib.rs` enforces a conservative bound (`lhl_distance_bound`, floor 2⁻³⁰⁰).
- Replay/temporal guarantees come from sequence-window and nonce logic — unconditional, not hardness-based.

The boundary: the *protocol arguments* are information-theoretic, but the *implementation* is a classical simulation with modeled noise; simulations demonstrate the statistics, they do not certify physical devices. This project therefore claims "the simulated protocol preserves the modeled information-theoretic guarantees" and nothing stronger.

---

## Part 2 — Repository deliverables (the six tracked items)

| # | Deliverable | Verdict | Evidence and scope |
|---|---|---|---|
| 1 | Mathematical model of teleportation-based QDS | **Implemented as a statevector simulation** | `docs/QDS_MATH_MODEL.md`; `qds/src/teleport.rs` (complex amplitudes, EPR preparation, Bell measurement, Born-rule collapse, Pauli corrections, fidelity). Classical software only. |
| 2 | Quantum-inspired threat-detection framework | **Implemented in the stated simulation model** | `detection` (QBER classification, finite-sample bounds), `qds/src/six_state.rs` (six-state verification + attack classification). Seeded software experiments; no real-world/hardware guarantee claimed. |
| 3 | Signature generation and verification module | **Implemented** | `qds` — teleportation signing/verification, single-use nonces, 1-ACC/0-ACC/REJ, transferability, plus the second six-state QDS model; `server/src/qds_keys.rs` binds QDS signatures to sealed documents. |
| 4 | Attack-simulation module | **Implemented for the listed simulated attacks** | `qds/src/attacks.rs`, `qds/src/metrics.rs`, QKD channel scenarios, dashboard Attack Lab (`/api/doc/attack-theater`), TUI. Educational simulator — not a signed incident-report service. |
| 5 | Performance metrics / evaluation | **Implemented** | `/api/qds/metrics` reports verification accuracy, per-class detection, false-accept (false-negative) and false-alarm rates, forgery estimates, operation timings; `qds/src/metrics.rs` + tests give repeatable seeded evaluation. Timings are machine-specific. |
| 6 | Software framework / prototype | **Implemented as an educational prototype** | Axum API, React dashboard, SSE monitoring, document vault, peer transfer, accounts, quorum workflows, TUI, persistent JSONL + Merkle audit ledger. Not production cryptography; not a deployed service. |

---

## Part 3 — Standing scope decisions (do not regress)

These were audited in a previous phase and remain deliberate decisions, recorded so a future contributor does not "helpfully" undo them:

- **No signed forensic flight recorder.** `/api/audit/*` already provides a persisted hash-chained Merkle event log with inclusion proofs and export; the dashboard can verify a bundle's internal consistency offline (`frontend/src/auditEvidence.ts`). What does **not** exist: a standalone `forensics/` incident-report format, a report-signing key, or publisher-authenticated roots. A Merkle root proves internal consistency only; publisher identity requires an independently trusted copy of the expected root. Recorded as a gap, not hidden.
- **No key-revocation lifecycle.** A QKD abort and a rejected signature are not revocation. There is no revocation list, registry, or signed revocation event — adding one casually would create misleading security semantics.
- **No `main_app -- --demo-attack`.** The browser Attack Lab + TUI already cover the demonstration; a third replay would duplicate them.

## Part 4 — Honest gaps and follow-ups

1. **Terminology alias (cosmetic):** the API could expose `false_accept_rate` as an explicit alias of `false_negative_rate()` to match the problem statement's vocabulary verbatim. The underlying quantity already exists (Clause 6); only the field name differs.
2. **No physical certification:** simulated noise models demonstrate statistics; they cannot certify hardware. Always stated, never waived.
3. **No signed incident reports / publisher-authenticated audit roots** (see Part 3).
4. **No revocation lifecycle** (see Part 3).
5. **Timing metrics are machine-specific**; seeded metrics are reproducible only where a seed is provided.
6. **Deployment configuration ships in the repo** (Dockerfile + Render Blueprint; operator walkthrough kept local, see the handbook's configuration section); `frontend/vercel.json` still holds a placeholder API origin pending the provider decision.

## Part 5 — Reproducing this audit

```sh
cargo test --workspace            # protocol, metrics, attacks, audit, sealing tests
cd frontend && npm run build && npm run lint   # dashboard build + lint
cargo run -p server               # then: GET /api/qds/metrics?trials=200&seed=42
```

`GET /api/qds/metrics` returns both schemes' confusion matrices, per-class detection, forgery probabilities (empirical + theoretical) and timings — the exact numbers behind Clauses 5 and 6. Dependency grep from the toolchain facts above re-checks the no-AI/ML clause in one line.
