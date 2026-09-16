# SIH26141 Judging Book — Quantum-Secured Pipeline

**One document to walk into the judging round with.** It consolidates the
pitch (`JUDGE_PITCH.md`), the full guide (`PROJECT_GUIDE.md`), the formal
model (`QDS_MATH_MODEL.md`), and the run instructions
(`DASHBOARD_RUN_GUIDE.md`) — with the verified status of this exact build.

**Build status (verified Sept 15, 2026, on this machine — v2 build):**

| Check | Result |
|---|---|
| `cargo test --workspace` | **66 passed, 0 failed** (11 crates) |
| `cargo build --workspace` | zero warnings; TUI compiles clean |
| Frontend build (`tsc -b && vite build`) | clean, no type errors |
| Live endpoint smoke test | all 18 endpoints OK — QKD run/sweep/SSE, QDS setup/sign/verify/attacks/forgery-analysis/metrics/events, **v2: doc seal/verify/quorum/unlock/transfer, audit + proof**, static dashboard |
| Parameter responsiveness (UI) | verified: 50k vs 20k qubits change sifted counts; 25% vs 15% threshold moves the decision line; blank seed = fresh randomness per run; typed seed = bit-identical reproduction (shown in the event log as `seed <n> · <qubits> qubits · threshold <x>%`); **fiber noise → degradation warning; relay hops → route strip + (1/3)^links yield** |
| Demo-path behavior | QBER = 0.337 ≈ 1/3 on full attack ✓ · all 5 QDS attacks rejected ✓ · HMAC verified on secure channel ✓ · audit log written ✓ · **single-byte tamper caught ✓ · k−1 quorum rejected, k-of-m unlocks ✓ · transfer end-to-end verified ✓ · inclusion proof re-verifies ✓** |

---

## 1. The one-page summary (say this first)

Modern signatures (RSA, ECDSA) die to Shor's algorithm; "harvest now,
decrypt later" is already happening. This project is a **single software
framework with two integrated quantum-security layers**, security from
**physics, decisions from statistics, zero AI/ML**:

1. **Six-state QKD** — distributes a shared secret over a simulated quantum
   channel. Eavesdropping is *detectable, not preventable*: intercept-resend
   forces QBER → f/3 (f = fraction intercepted). A two-sided **Hoeffding
   bound** sets a finite-sample threshold; compromised channels **abort**
   key distillation; clean channels distill a 256-bit key via SHA-256
   privacy amplification and HMAC-authenticate messages.
2. **Teleportation-based QDS** — signs messages with Bell-pair
   entanglement + quantum teleportation (Pauli corrections), per
   Gottesman–Chuang 2001 verdict semantics (**1-ACC / 0-ACC / REJ** +
   transferability/"Charlie consensus"). Forgery requires guessing every
   Bell outcome: **P(forgery) = 4^(−qλ)** ≈ 2.9×10⁻³⁹ at default params.
   All five threat classes — forgery, impersonation, replay, channel
   tampering, unauthorized verification — are detected by explicit
   threshold rules, with a **persistent JSONL audit log**.
3. **The product layer (v2)** — the seven scenario features that turn the
   two quantum layers into a working system: **trusted relay routes**
   ((1/3)^links yield, per-hop interception stats), a **noise filter with
   3-way detection** (secure / Channel Degradation Warning / attack —
   nature flips bits, Eve collapses bases), **`.qsig` document sealing**
   (HMAC under the QKD session key; one flipped byte fails instantly), a
   **P2P transfer portal** with a live per-stage log, a **hash-chained
   Merkle audit ledger** with inclusion proofs (forensic non-repudiation),
   a **ratatui TUI dashboard** (`cargo run -p tui`), and **Shamir k-of-m
   threshold authorization** (any k−1 shares leak zero information).

A Rust API server (axum) drives both layers; a React dashboard makes every
step visible live — converging QBER/threshold lines, a teleportation trace
table, and a λ-scaling forgery-probability chart.

The three papers in the problem statement are implemented specifically, not
"inspired by": GC01's verdict semantics and transferability criterion;
Singh et al. 2023's sign → teleport → validate pipeline (nonce ledger ≙
double-spend resistance); Weng et al. 2021's six-state encoding and
mismatch-rate thresholds, implemented **as a second complete QDS scheme**.

---

## 2. Deliverables map (their table → our artifacts)

| Deliverable | Where |
|---|---|
| 1. Math model of teleportation-based QDS | `docs/QDS_MATH_MODEL.md` (Bell states, teleportation derivation, C1/C2 verification equations, forgery theorem, complexity) |
| 2. Threat-detection framework | `detection` crate (Hoeffding) + `qds::verify` + `qds::six_state::classify` — all 5 attack classes, no ML |
| 3. Signature generation & verification module | `qds::sign`/`verify`/`verify_transferability`; six-state twin `sign_six_state`/`verify_six_state` |
| 4. Attack simulation module | `qds::attacks` (5 classes) + QKD intercept-resend; tamper fraction adjustable; all tested |
| 5. Performance evaluation | `qds::metrics` + `/api/qds/metrics` + dashboard panel: accuracy, detection rate, false alarms, forgery prob. (MC vs theory), timings; seeded/reproducible |
| 6. Software framework / prototype | `server` (REST + SSE) + `frontend` dashboard + `qds_events.jsonl` audit log |

Constraints: no AI/ML ✓ · deterministic acceptance of honest signatures ✓
(theorem + test) · low complexity ✓ (O(qλ), ~20–30 µs measured) ·
information-theoretic verification path ✓ · prototype + docs ✓.

---

## 3. Numbers you must know cold (with one-line derivations)

| Number | Value | Why |
|---|---|---|
| Full intercept-resend QBER | **1/3** | Eve wrong basis 2/3 × wrong bit 1/2 (six-state, 3 bases) |
| Partial eavesdropping QBER | **f/3** | linearity; asserted by unit test |
| Detection crossover (20k qubits, base 15%) | **f ≈ 50–55%** | measured on this build: 50% → 16.05% < 16.66% ≤ 18.97% @ 55% |
| Hoeffding margin | **ε = √(ln(2/δ)/2n)**, δ=0.05 | shrinks like 1/√n |
| Sifting yield | **~1/3** | 3 bases; 20k qubits → ~6,650 sifted (measured 6,649) |
| Forgery probability | **4^(−qλ)** | guess both bits at each of qλ positions |
| At (16, λ=4) | **≈ 2.9×10⁻³⁹** | 4⁻⁶⁴ |
| 128-bit security | λ ≥ 4 at q=16 | 4⁻¹²⁸ ≈ 2⁻²⁵⁶ at λ=8 |
| MC validation | 20,000 trials → 0.25 @ (1,1) | matches theory exactly |
| Per-op cost | **~20–30 µs** sign/verify | measured; O(qλ) |
| Evaluation accuracy | **> 99.9%**, 0 false alarms | 200 trials, seed 42 |
| Relay yield, k relays | **(1/3)^(k+1)** | independent per-link sifting; 2 relays ⇒ 1/27 ≈ 740 bits @ 20k |
| Noise vs attack line | **noise floor + ε(n)** vs **0.25** | degradation warning between the two; attack aborts above 0.25 |
| Shamir threshold | **k−1 shares ⇒ zero info** | degree-(k−1) polynomial, one point short (GF(251)) |
| Tamper detection | **1 flipped byte ⇒ instant fail** | HMAC over (meta ‖ file) under the QKD key |
| Merkle proof cost | **O(log n) hashes** | sibling path re-derives the root |
| Tests | **57 passing** | 13 qds unit + 16 qds int + 11 quantum + 9 sealing + 5 audit + 3 QKD int |

**Why the metrics panel shows 99.9% and not 100%** (judges may probe):
finite-sample tail of a bounded-error statistical test — the 30%-tampering
scenario sits ~2.7σ above the rejection threshold at n≈400 (one slip in 200
is the expected Binomial tail), and the evaluation's teleport-impersonation
probe uses q=8 digest bits (collision prob 2⁻⁸ = 1/256). Both tails shrink
exponentially with their security parameter. Full write-up:
`PROJECT_GUIDE.md` §3.10, `QDS_MATH_MODEL.md` §9.1.

---

## 4. The 5-minute demo script (full script in JUDGE_PITCH.md)

Start the app first: `cargo run -p server` → http://127.0.0.1:8080
(see `DASHBOARD_RUN_GUIDE.md`).

1. **QKD catch-the-eavesdropper (2 min)** — *Run Secure + Attack*.
   Left card: QBER 0.00%, AUTHENTIC, key + HMAC. Right card: red line
   converges to exactly 1/3, THREAT FLAGGED, "key distillation aborted".
   Narrate the dashed Hoeffding thresholds tightening — "a formula you can
   write on a napkin, not a model you have to trust."
2. **Sweep (1 min)** — *Run parameter sweep*. Bars track theory f/3; the
   threshold crossing sits near 50–55% at the default 20k qubits. "The
   theory *predicts* the simulation — that's what makes this a verification
   tool." Click it twice with the seed box blank: the bars wiggle between
   runs (fresh randomness) — then type seed 777 in the Seed box, run twice,
   and point at the event log: identical `seed 777` provenance, identical
   numbers. That's the reproducibility-for-audit story in ten seconds.
3. **QDS Signature Lab (2–3 min)** — ① keys (P(forgery) < 10⁻³⁹ chip) →
   ② sign (teleportation trace table: Bell outcomes 00–11, Pauli
   corrections I/X/Z/XZ, Bob verified 1-ACC, single-use nonce) → ③ all 5
   attacks rejected → ④ forgery-analysis chart (each λ ≈ ×1000 harder to
   forge) → ⑤ evaluation panel (accuracy > 99.9%, zero false alarms,
   microsecond timings, seeded/reproducible).
4. **The v2 product layer (3–4 min)** ⭐ the differentiator —
   a. **Noise + relays**: drag Fiber noise to 8%, run → the secure card
      shows `⚠ degradation warning` with keys *still distilled*; then run
      the attack → `✗ under attack`, distillation aborted. Drag Relay
      hops to 2, run → route strip Alice → R1 → R2 → Bob, sifted drops to
      ~1/27. "The detector separates two physical processes."
   b. **Seal + tamper**: Quantum Document Vault → drop any file → Seal →
      download `.qsig` → re-verify the original (green) → flip one byte
      (open in Notepad, change a character) → Verify (red, instantly).
   c. **Quorum**: toggle Shamir quorum seal 3-of-5 → seal → unlock with 2
      officers (rejected) → 3 officers ("unlocked via quorum 3-of-5").
   d. **Transfer portal**: pick a file, 2 hops, Send → live log streams
      sifting/noise/unseal/verify; verdict green; 3 new ledger entries.
   e. **Forensics**: in the Vault's Merkle Audit Ledger press **proof** on
      any row → sibling hashes + recomputed root. "Prove one entry
      without revealing the log."
5. **If asked**: open `qds_events.jsonl` in Notepad — every sign/verify/
   attack persisted with timestamp + verdict (deliverable: logging); the
   v2 Merkle ledger additionally hash-chains and proves every entry.
6. **Fallback if the browser misbehaves**: `cargo run -p tui` — the TUI
   dashboard runs the same engine in the terminal (sparkline, relay route,
   s/v/t/w vault demos); `cargo run -p main_app` as the last resort.

---

## 5. Judge Q&A — the eight that actually get asked

**"Is this a real quantum computer?"** — No; a faithful classical
simulation of the protocol's information structure (like a flight
simulator for aerodynamics). The problem statement asks for a software
framework with mathematical modelling, attack simulation and security
analysis — that's exactly this.

**"How do you know a warning is noise, not an attacker?"** — Physics, not
heuristics: environmental noise flips polarizations but never changes a
basis; only a *measurement* collapses a state, and wrong-basis collapse
is what drives QBER toward the 1/3 ceiling. QBER explainable by the
configured noise floor + Hoeffding margin ⇒ degraded (usable, logged);
above the intercept ceiling ⇒ attack (abort). Two different physical
processes leave two different signatures.

**"Why trusted relays and not quantum repeaters?"** — Because that's
what every deployed QKD network is (SECOQC, Tokyo, Beijing–Shanghai):
true repeaters need quantum memory that is still lab-stage. Our relays
measure-and-forward, so yield collapses (1/3)^links — we make that cost
*visible* rather than hide it.

**"How is this different from post-quantum cryptography?"** — PQC is
*computational* security (new hard math). Ours is *information-theoretic*:
security from physics, valid against unbounded adversaries.
Complementary; our QKD keys can even feed PQC/AES.

**"Where's the AI/ML?"** — The problem statement forbids relying on it.
Every verdict is an explicit threshold rule on measured mismatch rates —
more explainable than any model: I can derive each alarm on a whiteboard.

**"What stops Eve intercepting a little?"** — Nothing, and that's honest
physics: partial interception raises QBER proportionally; the Hoeffding
margin tightens as samples accumulate; privacy amplification compresses
away residual information. Detection-vs-yield is *the* QKD trade-off and
our sweep chart shows it live.

**"Isn't SHA-256 a weakness if you claim information-theoretic security?"**
— The verification path (XOR correlation checks) needs no computational
assumption. SHA-256 appears only in auxiliary roles (commitment, message
binding) analyzed as a random oracle — the standard treatment — and the
simplified PA step is flagged honestly in the docs.

**"Forgery probability — where does 10⁻³⁹ come from?"** — Two secret bits
per position; a forger guesses both at every one of 64 positions:
(1/4)⁶⁴ ≈ 2.9×10⁻³⁹. A 20k-trial Monte-Carlo on small parameters
converges to exactly the theoretical 1/4 per position — the chart in
step ④ shows theory and simulation agreeing.

**"What stops one officer unlocking a quorum document alone?"** — Shamir:
the key is the constant term of a random degree-(k−1) polynomial over
GF(251); k−1 points are mathematically one point short, and *any* key
value is consistent with them — zero information, not a policy. k shares
reconstruct by Lagrange interpolation; each share carries a commitment
so fake shares are rejected before reconstruction.

**"How do I know the audit log wasn't edited after the fact?"** — Every
leaf hashes its content *plus the previous leaf*; a Merkle root commits
to the whole history, `.qsig` containers pin the root at seal time, and
`verify_chain` re-derives everything and names the exact sequence number
where any edit breaks the chain. Inclusion proofs verify one entry in
O(log n) against the pinned root.

Deeper answers for all of these: `JUDGE_PITCH.md` Part C.

---

## 6. Honest limitations (volunteer two, it builds trust)

1. Classical simulation (ideal Bell pairs; the channel is noiseless
   *except* the environmental noise you dial in and any attack) — models
   the information structure faithfully, no physical qubits.
2. No error-correction stage and simplified privacy amplification
   (fixed SHA-256, not universal₂ sized by entropy budget) — both marked
   in code and docs with the roadmap item they map to.
3. Early `.qsig` containers (format v1) used a demo-grade XOR keystream —
   the current v2 format seals with **AES-256-GCM** (metadata as
   associated data); v1 is kept only for backward-compatible verification.
   The load-bearing primitives (SHA-256, HMAC, Shamir GF(251)) were
   standard throughout — and we say the history before judges find it.

Full list (11 items) with roadmap: `PROJECT_GUIDE.md` Part 6.

---

## 7. Document index

| Doc | Use it for |
|---|---|
| `FEATURES_V2.md` | **The seven v2 features in depth** — theory, math, code mapping, demo lines for relays / noise / sealing / transfer / Merkle / TUI / quorum |
| `DASHBOARD_RUN_GUIDE.md` | **Starting the app** — prerequisites, commands, smoke test, troubleshooting |
| `DASHBOARD_GUIDE.md` | **What everything on the page means** — element-by-element explainer for the QKD, QDS, Doc Vault and Transfer Portal sections, with a parameter-responsiveness matrix |
| `JUDGE_PITCH.md` | The full spoken script: opener, demo narration, Q&A, flashcards, room checklist |
| `PROJECT_GUIDE.md` | Complete theory from zero + codebase walkthrough + verification state |
| `QDS_MATH_MODEL.md` | Formal model: Bell/teleportation derivation, C1/C2, forgery theorem, literature mapping |
| `../README.md` | Repo overview, API table, quickstart |

**Final pre-flight:** tests pass → server up → pill green → 5-click smoke
test → laptop charged, browser zoom up, Slack closed. You're ready.
