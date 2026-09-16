# Dashboard Explainer — Every Element, Both Layers (QKD + QDS) + Product Layer

**What this is:** a complete, element-by-element explanation of everything
visible on the SIH26141 dashboard at `http://127.0.0.1:8080` — what each
control does, what each number means, where it comes from in the backend,
and what should (and shouldn't) change when you interact with it.

**How to read this doc:** sections follow the page top-to-bottom. QKD =
the key-distribution half of the page (sections 2–7). QDS = the Signature
Lab half (section 8 — the deepest section, per the problem statement's
focus). Sections 10–12 cover the **v2 product layer**: the Quantum
Document Vault (seal/verify/quorum + Merkle ledger) and the P2P Transfer
Portal. Section 13 is a responsiveness matrix: what changes when you touch
each control — use it to verify the app is behaving before a demo.

*Companion docs:* `DASHBOARD_RUN_GUIDE.md` (how to start the app),
`JUDGING_BOOK.md` (what to say), `PROJECT_GUIDE.md` (full theory),
`QDS_MATH_MODEL.md` (the formal math behind section 8),
`FEATURES_V2.md` (the deep-dive behind sections 10–12).

---

## 1. Page orientation

One page, ten regions, top to bottom (v2 additions marked ⊕):

```
┌──────────────────────────────────────────────────────────┐
│ ① HEADER        title · API pill · Run button             │
│ ② PARAMETERS    sliders & inputs (⊕ noise, ⊕ relay hops)  │
│ ③ STATUS CARDS  verdict per scenario (⊕ 3-way + routes)   │
│ ④ LIVE MONITOR  streaming QBER chart + per-scenario stats │
│ ⑤ SWEEP PANEL   QBER vs eavesdropping-intensity bars      │
│ ⊕ ⑥ DOC VAULT   seal · verify · quorum · Merkle ledger    │
│ ⊕ ⑦ TRANSFER    P2P portal with live pipeline log         │
│ ⑧ KEY MATERIAL  derived secret + HMAC result              │
│ ⑨ QDS LAB       ① keys ② sign ③ attacks ④ forgery ⑤ eval  │
│    FOOTER       "educational prototype" disclaimer        │
└──────────────────────────────────────────────────────────┘
```

Everything talks to one Rust server (axum) on one port. The QKD half
(①–⑤, ⑧) streams live over Server-Sent Events while a run executes; the
QDS half (⑨) is request/response — each button click is one API call —
and every click leaves an entry in the persistent audit log
(`qds_events.jsonl`). The v2 product layer (⑥⑦) talks to the new
`/api/doc/*` and `/api/audit/*` endpoints and appends to the **Merkle
audit ledger** (hash-chained, with inclusion proofs — §11 below).

The theme is deliberate: deep-space navy with a nebula glow and faint
grid lattice, photon-cyan for live channel data, entanglement-violet for
cryptographic material (keys, tags, proofs), amber strictly for the
degradation warning, red strictly for attacks. Corner brackets on each
panel echo "measurement frames"; monospace is used for every number so
telemetry reads as telemetry.

---

## 2. Header

| Element | What it does | Behind the scenes |
|---|---|---|
| **Title + subtitle** | Identifies the project: six-state QKD + Hoeffding-bound detection. | static |
| **● API online pill** | Green = browser can reach the server. Gray "checking…" = probing. Red "API offline" = no server. | Polls `/api/health` every 10 s. If same-origin fails, it auto-discovers a fallback port (reads `server-port.json`, then probes 8081–8090) and retargets silently — the pill turns green by itself. |
| **Run Secure + Attack** (button) | Starts the QKD simulation: two scenarios back-to-back — a clean channel and a fully intercepted one. Disabled while running. | `POST /api/run` with all ② parameters. Progress streams back on `/api/events` (SSE); the button re-enables on the `done` event. In custom-ratio mode (see ②) it reads "Run Custom Scenario". |

**Demo tip:** point at the pill first — "full stack, one port" — then click Run.

---

## 3. Experiment Parameters (QKD controls)

Every control here affects the **next** run. The event log (section 4)
echoes the values actually used for each run.

| Control | Range / default | What it really does |
|---|---|---|
| **Key length** | 1,000–100,000 qubits (default 20,000) | How many qubits Alice prepares and sends. More qubits ⇒ more sifted bits (~1/3 survive) ⇒ tighter Hoeffding margin (ε ∝ 1/√n) ⇒ better detection. *This is the detection-vs-yield trade-off made tangible.* |
| **Base QBER threshold** | 0–50% (default 15%) | The noise/alarm line before statistical correction. The real decision uses `base + ε(n)`. Lower = more sensitive (flags weaker attacks, risks false alarms on noise); higher = tolerant. The dashed "base %" line on the live chart tracks this slider. |
| **Streaming pace** | 0–20 ms/batch (default 6) | Artificial per-batch delay so the live chart is watchable. Pure theater — compute itself is microseconds. Set 0 for instant results. |
| **Custom attack ratio** (checkbox) | off | Replaces the two canonical scenarios (clean + full attack) with ONE scenario at your chosen interception fraction. The status cards and chart reconfigure to a single "Custom Intercept Ratio" card. |
| **Eve intercept ratio** (slider, custom mode only) | 0–100% (default 30%) | Fraction of qubits Eve measures-and-resends. Expected QBER ≈ ratio/3 (30% → ~10%). |
| **Fiber noise** ⊕ (slider) | 0–12% (default 0%) | Environmental bit-flip probability per qubit — fiber impurities / turbulence. A pure polarization flip in flight that **never changes the basis** — the physical property separating it from Eve. At 8% with no attacker, QBER settles ≈ 8% and the verdict is *secure* while it stays under noise-floor + ε(n); above that but under the **15% attack line** it's a **Channel Degradation Warning** (amber). Shows a small `degradation filter` chip when non-zero. Applies to the sweep too. |
| **Relay hops** ⊕ (slider) | 0–4 (default 0) | Number of trusted relay nodes between Alice and Bob. Each link sifts independently (1/3 survival per link), so yield ≈ (1/3)^(hops+1) — at 2 hops, ~740 sifted bits from 20k qubits. Shows a `{hops+1} links` chip. Each link also applies its own fiber noise and can host its own Eve. Status cards render the route strip; the transfer portal has its own independent hops slider. |
| **Seed (blank = random)** | number or blank | **Blank = fresh randomness every run** — the server draws a time-based seed and echoes it in the event log. **Typed = fully reproducible**: same seed + same parameters re-produce bit-identical results (keys, QBER, signatures). The placeholder shows the last used seed so you can reproduce any run. Judges ask about this: seeded runs are the audit story. |
| **Authenticated message** | free text | The payload HMAC-signed with the distilled key on the secure scenario (and shown in the Key Material panel). Compromised channels produce no key ⇒ no HMAC. |

**Common trap:** if a seed is typed in, results are *supposed* to repeat
identically. Blank the box to see fresh randomness. (Each run logs
`seed <n> · <qubits> qubits · threshold <x>%` — if those don't match the
sliders, the page is stale; hard-refresh.)

---

## 4. Status cards (one per scenario)

Two cards in default mode — **Secure Channel** (green accent) and
**Intercept-Resend Attack** (red accent); one card in custom mode.

| Element | Meaning |
|---|---|
| **Verdict chip** (3-way, v2) | `✓ secure` — QBER within noise floor + ε(n). `⚠ degradation warning` (amber chip, amber top-bar) — QBER above what the configured fiber noise can explain, but below the **15% attack line** (`ATTACK_QBER_LINE = 0.15`): **environmental, not adversarial; keys still distilled**, event logged. `✗ under attack` — QBER above the attack line ⇒ **key distillation aborted**. `streaming…` / `idle` while not finished. The card's top energy bar matches: cyan pulsing while streaming, green / amber / red on the verdict. |
| **Measured QBER** | Fraction of *sifted* bits Bob got wrong. Clean channel: 0.00% (deterministic in the noiseless sim). Full attack: →1/3 (six-state physics: Eve wrong basis 2/3 × wrong bit 1/2). With noise n% and no attack: ≈ n%. |
| **Dynamic threshold** | `base + √(ln(2/δ)/2n)` at final sample size (δ=0.05). The statistically safe alarm line — watch it converge downward during a run. |
| **Sifted key bits** | Bits surviving basis sifting (~1/3 of raw direct; (1/3)^(hops+1) with relays — 20,000 → ~6,650 direct, ~740 at 2 hops). |
| **Relay route strip** ⊕ (when hops > 0) | One glowing cyan dot per link — **red when that link saw an interception** (hover a dot for per-link stats). Below it the node chain `Alice → Relay 1 → … → Bob` and the key-survival percentage (sifted/raw). |

Below each card on a threat: *"Eavesdropping detected — QBER exceeds the
finite-key bound. Key distillation aborted."* — the abort **is** the
security feature: no compromised key ever exists to leak.

---

## 5. Live Channel Monitor

Appears while/after a run.

**Per-scenario stat blocks:**

| Stat | Meaning |
|---|---|
| **status chip** | `channel stable` vs `⚠ QBER above threshold` (live comparison as data streams) |
| **transmitted %** | progress through the raw qubits |
| **sifted bits** | surviving bits so far |
| **mismatches** | wrong bits among sifted so far |
| **live QBER** | running mismatch rate |

**The chart** — the demo centerpiece:

- **Solid lines** — live QBER per scenario. Secure: flat at 0%. Attack:
  climbs and converges to ≈33.3%.
- **Dashed lines (same colors)** — the Hoeffding-adjusted threshold at the
  current sample size: starts lenient (few samples) and **tightens toward
  the base threshold** as n grows. The visible convergence *is* the
  finite-key statistics lesson.
- **Gray dashed "base X%" line** — the base threshold from the slider
  (label updates with the slider).

**Event log** (right/below): timestamped verdict lines, newest first.
Every run/sweep adds a **provenance line**:
`Run #12: 1/2 scenarios authentic · seed 1844674… · 50,000 qubits ·
threshold 15%` — the exact randomness and parameters used, so any result
can be reproduced or audited.

---

## 6. Sweep panel — "QBER vs. Eavesdropping Intensity"

Click **Run parameter sweep**: measures the full attack curve by
simulating 11 interception levels (0%–100% in 10% steps) at the current
key length.

| Element | Meaning |
|---|---|
| **Blue bars (Measured QBER)** | simulated result at each intercept ratio |
| **Dark bars (Theoretical ratio/3)** | the physics prediction QBER = f/3 |
| **Red dashed threshold line** | the Hoeffding threshold at that sample size; bars crossing it are flagged |

**What to say:** the blue and dark bars track each other without tuning —
"the theory *predicts* the simulation." Detection crossover at the default
20k qubits and 15% base: **50–55% interception** (below that, Eve's added
QBER hides under the statistically-safe band — the honest detection-vs-
yield trade-off; more qubits push the crossover lower).

The sweep uses the seed box rules too (blank = fresh randomness per
sweep; typed = identical bars every time, provenance logged).

---

## 7. Key Material & Message Authentication panel

Appears after a run completes — one block per scenario.

**Secure scenario (clean channel):**

| Element | Meaning |
|---|---|
| `✓ secure key established` | detector accepted the channel |
| **Derived secret (SHA-256 PA)** | the 256-bit key distilled from all sifted bits (privacy amplification; simplified — real QKD uses a universal₂ hash sized by an entropy budget, flagged in docs) |
| **HMAC-SHA256 tag** | authentication tag over your message text with that key |
| `verified` chip | tag recomputed and matched in **constant time** (timing-attack-safe comparison) |

**Attack scenario (compromised channel):**

> `✗ key distillation aborted` — *Channel compromised at 33.69% QBER —
> first divergent sifted bit at index #2. No shared secret produced.*

The **first divergent bit index** is forensic detail: where Alice's and
Bob's keys first disagree — evidence of disturbance, and proof that no
secret was distilled.

---

## 8. ⚛ QDS Signature Lab (the deep section)

The teleportation-based Quantum Digital Signature lab. Five numbered
steps, top to bottom. Participants: **Trent** (notary/distribution
center), **Alice** (signer), **Bob** (verifier), **Charlie** (second
verifier for transferability). Formal math: `QDS_MATH_MODEL.md`.

### 8.1 Step ① — "Generate quantum keys"

**What happens on click:** Trent (`Trent::setup`) creates fresh secret
Bell-correlation tables A1, A2 — for each of q×λ positions two hidden
bits realized by Bell pairs shared with Alice — and publishes only their
hash. Any previous signature state is cleared (you must re-sign after
re-keying).

| Element | Meaning |
|---|---|
| **`Key: 16 qubits × λ=4 Bell rounds`** | Security parameters: q signature qubits × λ Bell-pair depth = 64 secret positions per signature. Defaults are the API's (16, 4). |
| **`P(forgery) < 10^-38` chip** | Whole-signature forgery bound: a forger must guess both hidden bits at every position: P = (1/4)⁶⁴ = 4⁻⁶⁴ ≈ 2.9×10⁻³⁹. The chip shows the ceiling exponent. |
| **`27b04e6e8b728a…` (commitment)** | The public key: SHA-256(A1‖A2‖λ). Only a commitment is public — the correlations themselves never leave Trent/Alice. **Changes on every regeneration** (fresh randomness) — quick visual check the button works. |

### 8.2 Step ② — "Sign via teleportation"

**What happens on click:** for each of the 64 positions (i,j), Alice
teleports the payload bit `m_i ⊕ A1[i][j]` (m = SHA-256 of your message,
one bit per qubit): a Bell measurement with a uniformly random outcome
she cannot choose, two classical bits sent, Bob applies the Pauli
correction. She publishes two signature bits per position:
`x = m_i ⊕ A1[i][j]` (message binding) and `z = A1[i][j] ⊕ A2[i][j]`
(secondary-correlation binding). Then Bob verifies on delivery — which
**consumes the single-use nonce**.

| Element | Meaning |
|---|---|
| **`✓ Bob verified · 1-ACC (transferable)`** | Bob's on-delivery verification passed with zero mismatches ⇒ verdict 1-ACC per Gottesman–Chuang: valid **and** safe to forward to other verifiers. (`✗ delivery failed` would mean the quantum channel corrupted the signature in transit.) |
| **`nonce 1 (single-use)`** | Trent's replay-defense registry number, consumed by Bob's acceptance. Re-presenting this signature later = replay = rejected. Nonces increment per signing session and reset when keys are regenerated. |
| **`128 signature bits`** | 2 published bits × 64 positions. |
| **Teleportation trace table** | The actual teleportation log, first 6 qubits: **qubit** = position; **Bell outcome** = the 2-bit measurement result (00/01/10/11, uniformly random — the signature's randomness source); **Pauli correction** = what Bob applies (I/X/Z/XZ, mapped from the outcome); **raw bit** = Bob's bit *before* correction; **corrected** = after — always equals the intended payload (ideal teleportation; watch raw flip exactly when the correction is X or ZX). |
| **Signature (correction bits)** | The published signature as hex (0/1 bytes): 128 bits. **Bound to the message** — change one character of the message and re-sign: the signature is completely different (the message-hash bits feed every position). |
| **Tamper fraction slider (0–100%, default 50%)** | Controls scenario ③'s channel-tampering attack: what fraction of teleported qubits Eve disturbs in flight. Each disturbed position flips one published bit, so mismatches scale ∝ fraction (0% → 0 mismatches and the tampered signature is honestly *accepted* — no disturbance, no false alarm; 100% → every position mismatches). |

### 8.3 Step ③ — "Launch all 5 attacks"

Runs all five threat classes from the problem statement against the last
genuine signature, each verified through the same `qds::verify` pipeline
and appended to the audit log. Every row:

- **name + verdict chip** (`REJ` / `0-ACC` / `1-ACC` — genuine signatures
  get 1-ACC; every attack here must show REJ),
- **accept/reject chip** (`✓ rejected` is the *good* outcome for an
  attack; `✗ accepted (bad!)` would mean a missed attack — expect none),
- **description** of the attacker's move,
- **statistics line** — real measured evidence from the verification
  equations: `mismatches/total positions · match ratio`. One nuance:
  **replay** shows *"blocked before statistics — nonce/commitment check"*
  — correct and worth saying aloud: a replayed signature is caught by the
  nonce registry *before* any statistics run, because nonce reuse IS the
  attack.
- **Charlie consensus** where applicable — the transferability re-check
  (GC01 security criterion 2).

| Row | What the attacker does | Why it fails (what the stats show) |
|---|---|---|
| **Forgery (guessed Bell outcomes)** | Fabricates all 128 correction bits uniformly at random under a fresh nonce | Both verification equations (C1: x⊕m_i =? A1; C2: z⊕A1 =? A2) are random per position ⇒ ~75% mismatch (e.g. 49/64). Success would need ALL positions right: 4⁻⁶⁴ ≈ 10⁻³⁹. |
| **Impersonation (signature transplant)** | Takes the genuine signature and presents it as covering a *different* message (e.g. "transfer 999 QCO") | The message-hash bits change ⇒ C1 (message binding) fails wherever the digests differ (~half of positions — e.g. 24/64). Signatures are mathematically welded to their message. |
| **Replay (nonce reuse)** | Re-presents the accepted signature verbatim | Nonce registry: already consumed ⇒ rejected **before statistics**. This is the double-spend defense from the blockchain paper. |
| **Channel tampering (qubits disturbed in flight)** | Genuine bits, but the slider-fraction of teleported qubits disturbed | Disturbed positions decode inconsistently ⇒ mismatch rate ∝ tamper fraction, exceeding the rejection threshold above ~10%. Slide the slider and watch the mismatch count climb 0 → 64. |
| **Unauthorized verification (no key material)** | A party without Trent's correlation tables attempts verification of a captured signature | The attempt is flagged as its own threat class; the re-presented bits also fail statistics (same ~62% match as a transplant) on a fresh nonce. No verdict reached without key material can be trusted. |

**Why fresh nonces for impersonation/unauthorized but not replay:** the
genuine nonce was consumed by Bob's delivery acceptance; re-presenting it
is definitionally replay. Impersonation and unauthorized rows are given
fresh nonces deliberately so their *statistical* failure modes are
visible rather than masked by the nonce check — five rows, five distinct
teachable failure reasons.

### 8.4 Step ④ — Forgery probability analysis

**What happens on click:** `GET /api/qds/forgery-analysis` — a
20,000-trial Monte-Carlo at small parameters (q=8, λ=1) plus the theory
curve.

| Element | Meaning |
|---|---|
| **Hint line** | States the law P = (1/4)^(qubits×λ) and reports MC vs theory (MC ≈ 0.0 at these params — one success would already be lucky; the test suite validates MC≈0.25 where it's measurable). |
| **Bars (log₁₀ P, λ=1..8)** | Each extra Bell round λ multiplies forgery difficulty ×~1,000 (one more quarter: 10^log10(4) ≈ ×1,000). |
| **Green "128-bit security" line** | log₁₀(2⁻²⁵⁶) = −77… shown at −30 on the λ-axis for readability; the chip in ① carries the exact bound. Crossover ≈ λ=4 at q=16 — "we exceed 128-bit at λ=4." |

This panel is **deliberately static** — it plots a theory curve; it
doesn't respond to the other controls (that's by design, not a bug).

### 8.5 Step ⑤ — Performance evaluation (Lap 2 metrics)

**What happens on click:** `GET /api/qds/metrics?trials=200&seed=42` —
the repeatable evaluation engine over **both** QDS schemes (the
teleportation pipeline AND the six-state Weng-et-al scheme that shares
the QKD layer's encoding).

| Metric (both cards) | Meaning |
|---|---|
| **Verification accuracy** | fraction of legitimate+attack events classified correctly (expect >99.9%) |
| **Detection rate** | TP/(TP+FN) over attack events |
| **False positives / negatives** | false alarms on legitimate signatures (expect 0) / missed attacks (expect 0–1 — the finite-sample tail, see §3.10 of the project guide) |
| **Forgery probability (MC vs theory)** | empirical guessed-signature success vs 4^(−qλ) |
| **Per-class detection (six-state card)** | detection % for each of the 5 attack classes in the six-state scheme |
| **sign / verify** | wall-clock per operation (~20–30 µs — the "low complexity" deliverable, measured not claimed) |

**Note:** this panel is **seeded and deterministic by design** (trials=200,
seed=42) — clicking it twice gives identical numbers, which is the point:
an evaluation an auditor can reproduce. The event log records each
evaluation run.

### 8.6 "Theoretical basis & references" (collapsible)

Maps every mechanism to its paper: Gottesman–Chuang 2001 (verdict
semantics 1-ACC/0-ACC/REJ, transferability), Singh et al. 2023
(sign→teleport→validate pipeline, Ta/Tb thresholds ≙ c1/c2, replay
resistance), Weng et al. 2021 (six-state encoding, mismatch-rate
thresholds — implemented as the second full scheme). Good "where's the
literature?" moment.

---

---

## 10. ⊕ Quantum Document Vault (seal · verify · quorum · ledger)

The product layer — turns the QKD session key into document security.
Prerequisite: run a **secure QKD scenario** once (the header chip shows
`session key ready` with the key commitment; without it the vault shows
`no session key — run a QKD exchange first`). Deep-dive: `FEATURES_V2.md`
features 3, 7, 5.

### 10.1 Column ⟨ 1 · SEAL ⟩

| Element | What it does |
|---|---|
| **Dropzone** | Pick any file (PDF/image/text). Shows its name + size once loaded. |
| **Shamir quorum seal** (toggle) | Off = seal under the raw session key. On = split the key k-of-m first: two selects appear (threshold k 2–5, shares m 2–8, m ≥ k). The container records the quorum spec + per-officer commitments; unlocking later requires k shares. |
| **Seal → .qsig** | Uploads the file, seals it server-side, and returns the container for **download** as `<name>.qsig`. Result block shows the key commitment and (if quorum) the officer count. A `seal` entry lands in the Merkle ledger with the file's SHA-256. |

### 10.2 Column ⟨ 2 · VERIFY / UNLOCK ⟩

| Element | What it does |
|---|---|
| **Verify against session key** | Re-submits the container: server AES-256-GCM decrypts the payload (metadata bound as associated data), recomputes the HMAC and payload hash. Verdict box: green `✓ document verified: AES-GCM payload, HMAC tag and payload hash all match…` or red with the **precise failed check** — container format / key commitment ("sealed under a different session key — key possibly compromised") / GCM tag mismatch / HMAC tag mismatch / payload hash mismatch. Every verify is a `verify` ledger entry. **Demo move:** re-upload the original file with one byte changed → instant red. |
| **Officer pills** (quorum seals, same-screen mode) | One pill per officer (`OFF-01…OFF-0m`), toggle to present their shares. |
| **Unlock with selected shares** | Fewer than k → red: `unlock rejected — only N valid shares (need k)`. k or more → green: `✓ k-of-m quorum met — document unlocked via quorum k-of-m`, and the outcome is a `quorum` ledger entry. **Demo move:** toggle 2 of 3 → rejected; toggle 3 → unlocked. |
| **Multiparty: distribute shares to user accounts** | After a quorum seal, assign each `OFF-xx` share to a registered username (datalist autocomplete) → **Distribute shares →**. Shares go into server-side custody — holders never see the bytes. The result line lists `user←OFF-x` assignments. |
| **Unlock with N pledged shares →** | Appears once cross-account pledges arrive. Calls the pledged unlock: ≥ k pledges → green `unlocked via quorum k-of-m` (pledges consumed); below k → rejected. |
| **🔑 Custody card (officers see this)** | If your account holds a distributed share, the Vault shows *"You hold officer OFF-0x (distributed by ⟨sealant⟩)"* and a **Pledge my share →** button — pledging commits your approval; the bytes never touch your browser. |

### 10.3 Section ⟨ 3 · MERKLE AUDIT LEDGER ⟩

| Element | What it does |
|---|---|
| **Badges** | `chain ✓` (full chain re-verified OK), `root ⟨12 hex⟩` (hover = full Merkle root), `N entries`. |
| **Entry table** | seq / kind (`seal` `verify` `flag` `transfer` `quorum` `system`) / ✓✗ / detail / truncated leaf hash (hover = full). Rows from a rejected event are highlighted red. |
| **proof button (per row)** | Fetches `GET /api/audit/proof?seq=N` and renders the inclusion proof inline: the leaf hash, each sibling (`L:`/`R:` labeled), and the recomputed root — verified server-side. *"Prove entry 6 is in the log without revealing the log."* |

---

## 11. ⊕ P2P Transfer Portal — Alice → Relays → Bob

The live-motion scene: one file, the whole pipeline, narrated stage by
stage. Independent controls from the top-of-page sliders (deliberate —
you can demo transfers without touching the experiment parameters).

| Element | What it does |
|---|---|
| **File dropzone** | The file to transmit (it is sealed, transmitted, unsealed, verified — the plaintext itself never "travels" unencrypted in the model). |
| **Relay hops** | 0–5. Topology strip below updates live: `⟨Alice⟩ --- ⟨Relay 1⟩ …` with dashed links; the *next* node to act **blinks** during the transfer. |
| **Fiber noise** | Per-link environmental noise 0–15%. |
| **Shamir quorum** (toggle + k) | Seal the transferred file under a k-of-m split; Bob's unseal then reconstructs the key from k shares before verifying. |
| **Send securely** | Starts the SSE transfer. |
| **Live log** (terminal pane) | One line per stage: stage glyph + node label + detail — e.g. `⟨A⟩ hashing file (12.3 KB)` → `⟨K⟩ deriving session key` → `⟨A⟩ sealing .qsig` → per-hop `⟨R1⟩ sifting 3,412 qubits · noise flips 102` → `⟨B⟩ reconstructing key from 3 shares` → `⟨B⟩ HMAC verified ✓`. Colors: cyan = quantum stages, violet = crypto, green = success, red = failure. |
| **Hop chips** (on completion) | Per-link stats: name, sifted counts, interceptions (red chip when Eve hit that link). |
| **Verdict box** | Green: delivered + verified (+ audit seq). Red: which stage failed (key aborted under attack, seal rejected, HMAC mismatch). |

Every transfer appends `seal` + `transfer` + `verify` entries to the
Merkle ledger in §10.3 — say that out loud during the demo.

---

## 11b. ⊕ Peer-to-Peer Transfer — real laptop → laptop (accounts)

Distinct from §11: this panel moves an **actual encrypted container over
the network** between user accounts/machines. Files ≤ 5 MB.

| Element | What it does |
|---|---|
| **File to send** | Any file ≤ 5 MB; it is sealed under your session key on **Send**. |
| **Recipient username** | The addressee's account. Datalist shows all registered users (`/api/auth/users`). |
| **Send to user →** | Delivers into that account's inbox **on this server** (two accounts can share one laptop). |
| **…or remote laptop API base URL** | e.g. `http://192.168.1.42:8080` (the peer server must run with `HOST=0.0.0.0`) or the Render URL. **Send to laptop →** POSTs the container to the peer's `/api/doc/receive`, addressed to the same username there. |
| **copy this machine's base URL** | Convenience button to share this server's address. |
| **Verdict box** | `✓ delivered — container accepted into the inbox` (with peer inbox id) or the precise failure (unknown user, unreachable peer). |
| **Inbox** | Documents received from peers: name, size, sender, time, verify-state chip. **verify** runs the full check against *your* session keys and records the verdict in the ledger; **dismiss** removes the item. |

Only the AES-GCM ciphertext travels — without the session key the peer
sees nothing readable. "Both machines ran the same seeded QKD exchange"
is the demo's shared-key convention (see `FEATURES_V2.md` feature 8).

---

## 11c. ⚔ Attack Lab — Mallory vs the seal

The adversary's own panel. Mallory (her account, ideally her own laptop)
captures a `.qsig` container — it is public ciphertext — and attacks it:

| Element | What it does |
|---|---|
| **Capture dropzone** | The intercepted container (e.g. the downloaded `.qsig`). |
| **Attack mode** | `tamper_bytes` (flip ciphertext bytes — GCM auth must fail) · `swap_meta` (rename the document — metadata is GCM associated data) · `re-seal (forge)` (Mallory's own commitment + tag — key-commitment mismatch) · `truncate` (cut the payload — hash + tag fail). |
| **Attacker label** | Provenance for the audit trail (`mallory` by default). |
| **Run attack →** | Server mangles the container per the mode and returns Mallory's forgery + a description of what she did. The attempt is **immediately recorded in the ledger as an `attack` event** and broadcast on the SSE event stream. |
| **save forged container** | Download Mallory's forged `.qsig` (for offline forwarding). |
| **Forward forgery to ⟨recipient⟩ →** | Sends the forged container into the victim's inbox via `/api/doc/send` (works cross-server with a `peer_url`-style flow too — on one deployed server, just the username). The victim's own verify then **REJECTS** it under their key, with the exact failed check. |

**Demo rhythm:** attack on Mallory's screen → forward → cut to Bob's
inbox → verify → ✗ REJECTED — and point at the `attack` row (red) in
Mallory's ledger and the rejected `verify` row (red) in Bob's.

---

## 11d. AuthBar — accounts (header)

| Element | What it does |
|---|---|
| **Anonymous state** | `anonymous workspace —` with username/password inputs and **log in** / **register** buttons. Anonymous calls share a `shared` workspace. |
| **register** | Creates the account (username ≤ 32 chars; letters/digits/`_`/`-`; password ≥ 6 chars → PBKDF2-SHA256, 600k rounds, 16-byte salt). Auto-logs-in on success. |
| **log in** | Verifies credentials → issues a 256-bit bearer token (kept in localStorage; the server session table is memory-only — a server restart logs you out but the account persists). 2 s backoff per username after a failed attempt. |
| **Logged-in state** | `👤 ⟨username⟩ — your keys, seals and inbox are private to this account` + **log out**. |

Everything below the header is workspace-scoped once logged in: session
keys from `/api/run`, vault seals, quorum custody/pledges, and the P2P
inbox are per-user.

---

## 12. TUI dashboard (companion, not on the web page)

`cargo run -p tui` in a second terminal: the same engine, five ratatui
panes (status + QBER sparkline, relay route, vault, audit tail, pipeline
log). Keys: `1/2/3` scenarios, `n/N` noise ±1%, `r/R` relay hops,
`s/v/t/w` vault demos (seal / verify / tamper / quorum), `Q` quit. Full
explanation: `FEATURES_V2.md` feature 6. Use it as the "second screen"
during judge demos — it proves the engine is genuinely front-end
agnostic.

---

## 13. Responsiveness matrix — what should change when

Use this to sanity-check the app before a demo. "By design" = correct
behavior that merely looks static.

| You do this | This must change | This intentionally doesn't |
|---|---|---|
| Drag **Key length**, run | sifted bits (~n/3), threshold (ε(n)), event-log provenance; sweep bars recompute | secure QBER (0% is the physics), attack QBER (~33% is the physics) |
| Drag **Base threshold**, run | dynamic threshold & verdict margins; live-chart "base %" line label+position | QBER itself (threshold doesn't touch physics) |
| Drag **Fiber noise**, run (no attack) | QBER settles ≈ noise %; verdict flips secure → ⚠ degradation warning as QBER crosses noise-floor + ε(n) | attack scenario verdict (noise doesn't excuse Eve) |
| Drag **Relay hops**, run | route strip on the cards (dots + node chain); sifted bits collapse ≈ (1/3)^(hops+1) | QBER physics (≈0 secure / ≈33% attacked either way) |
| Toggle **Custom ratio** + slider, run | cards collapse to one "Custom Intercept Ratio" card; QBER ≈ ratio/3 | — |
| **Seed**: blank vs typed | blank ⇒ fresh QBER/sifted/keys each run (log shows `random`-drawn seed); typed ⇒ identical results per identical params | — |
| Type a different **message**, run | HMAC tag (it binds the new message). The derived secret does NOT change — the key comes from the sifted bits, not the message | derived secret, QBER (message never touches the channel) |
| Click **sweep** twice (blank seed) | bar heights wiggle (fresh randomness) | theory bars (fixed f/3) |
| **① Regenerate keys** | commitment hash, all subsequent signatures, nonce counter resets | P(forgery) chip (same q×λ) |
| **② Sign** again (same message, same keys) | teleport trace (fresh Bell outcomes), nonce increments, signature hex | verdict (always 1-ACC for honest signing) |
| **② Sign** a different message | entire signature hex (message-hash bits feed every position) | — |
| Move **tamper slider**, run ③ | tampering-row mismatch count ∝ fraction (0%→0 … 100%→64) | other rows (only Eve's channel behavior changed) |
| Click **④ forgery analysis** | MC estimate re-drawn (≈0 at 20k trials) | theory bars (mathematics doesn't re-roll) |
| Click **⑤ evaluation** | nothing visible — deterministic by design (seeded); each run logged | — |
| **Seal** a file in the Vault | `.qsig` download offered; `seal` ledger entry with the file's SHA-256; commitment shown | channel state (sealing uses the captured session key) |
| **Verify** an untampered / tampered file | green verdict / red verdict naming the failed check; `verify` or `flag` ledger entry | the session key |
| Toggle **k-of-m officers**, unlock | <k shares → red rejection; ≥k → green "unlocked via quorum" + `quorum` ledger entry | — |
| **Send** a portal transfer | live log streams stages; topology strip blinks per node; hop chips + verdict on completion; 3 ledger entries | experiment parameters (portal controls are independent) |

**If something in the left column doesn't move:** hard-refresh
(Ctrl+Shift+R) — a stale cached bundle is the usual culprit — and check
the event-log provenance line to confirm the parameters actually sent.

---

## 14. The audit log (`qds_events.jsonl`)

Not on the page but behind everything in the QDS lab: every setup, sign,
verification, attack, and evaluation is appended to
`sih26141\qds_events.jsonl` with an RFC3339 timestamp, kind, label,
acceptance, and full verdict detail (e.g. `Acc1 — 0 mismatches across 64
positions — 1-ACC: valid and transferable`). Open it in Notepad during
Q&A — "every event you just saw was persisted" is a listed deliverable.

The **v2 Merkle audit ledger** (§10.3) is the cryptographically enforced
counterpart: same append-only discipline, but every entry is hash-chained
to the previous leaf and committed under a Merkle root, with per-entry
inclusion proofs and a full-chain re-verification endpoint. The JSONL log
is the *ops* trail; the Merkle ledger is the *forensic* one — that's the
two-sentence answer to "how do we know the log wasn't edited?".

---

## 15. Footer

*"Simulated six-state prepare-and-measure protocol · educational
prototype — not production cryptography."* — the honesty line. Say it
before a judge does: the framework models the quantum information
structure faithfully; it is not a hardware implementation. The full
limitations list (and what each maps to on the roadmap) is in
`PROJECT_GUIDE.md` Part 6.
