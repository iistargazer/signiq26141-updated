# Judge Round Playbook — SIH26141

**For: the main presenter. Everything you need for tomorrow, in speaking
order.** Read Parts A–D once tonight, skim the flashcards before you walk in.

**Golden rule:** you have a live product. Demo first, theory second, code
last. Judges remember what they saw working.

---

## Part A — The 60-second opener (memorize this)

> "Quantum computers will break every digital signature the internet uses
> today — RSA, ECDSA — because their security rests on math problems a
> quantum computer can solve. Attackers are already recording encrypted
> traffic to decrypt later.
>
> We built a software framework where signature security comes from **physics
> instead of computation**. It does two things: it distributes keys over a
> simulated quantum channel and **detects eavesdropping from measurement
> statistics alone**, and it **signs documents using quantum teleportation**
> so that forgery requires guessing quantum outcomes — with failure
> probability around ten to the minus thirty-nine.
>
> No machine learning, no black boxes — every decision is an explicit
> statistical threshold, which means every alarm is *explainable*. It runs
> live in front of you, and it implements the specific protocols from the
> three research papers in our problem statement."

Then: **"Let me show you it catching an attacker, live."** → start the demo.

---

## Part B — The live demo (5–7 minutes, rehearsed order)

**Setup before judges sit down:** server running, browser on
`http://127.0.0.1:8080`, scrolled to the top. Have a backup: the CLI
(`cargo run -p main_app`) if the network/browser misbehaves, and the
screenshots in this repo as last resort.

### Demo 1 — QKD: catch the eavesdropper (2 min)

1. Point at the **API online** pill: "full stack — Rust physics engine, HTTP
   API, React dashboard, one port."
2. Click **Run Secure + Attack** (defaults are fine).
3. While it streams, narrate:
   - *"Left card: clean channel. The error rate — QBER — sits at zero. We
     distill a 256-bit secret key and HMAC-sign a message. Verdict:
     AUTHENTIC."*
   - *"Right card: Eve intercepts every qubit. Watch the red line — it
     converges to exactly one-third. That's not a coincidence, it's
     physics: she picks the wrong basis two-thirds of the time, and then the
     bit is wrong half the time — one third. The detector flags it and
     destroys the key. Verdict: THREAT FLAGGED."*
4. Point at the dashed lines: *"Those thresholds are tightening as data
   accumulates — that's the Hoeffding bound, a statistics guarantee that
   works with finite samples and makes no assumptions about the attacker.
   This is the 'explainable AI' judges ask about, except it's not even AI —
   it's a formula you can write on a napkin."*

### Demo 2 — the sweep: physics you can check (1 min)

Click **Run parameter sweep**.

> "Each bar is a different eavesdropping strength. The bars track the theory
> line — QBER equals one-third of what Eve intercepts — and they cross the
> red detection threshold around sixty to seventy percent interception. We
> didn't tune the simulation to look like the theory; the theory *predicts*
> the simulation. That's what makes this a verification tool, not a toy."

### Demo 3 — QDS: sign with teleportation (3 min) ⭐ the wow section

1. Click **① Generate quantum keys**.
   - *"Trent, our trusted center, shares entangled Bell pairs with Alice.
     The public key is just a commitment hash — the actual correlations stay
     quantum and secret. Forgery probability is already displayed: ten to
     the minus thirty-nine."*
2. Click **② Sign via teleportation**.
   - *"Alice signs by teleporting qubits. This table is the actual
     teleportation log: each row is a Bell measurement — outcome zero-zero
     through one-one — and the Pauli correction Bob applies. I, X, Z, X-Z.
     Bob verified on delivery — chip is green. The nonce is single-use:
     think of it as a one-time wax seal."*
3. Click **③ Launch all 5 attacks**.
   - *"Forgery — an attacker just guesses the quantum outcomes: REJECTED.
     Impersonation — reusing a real signature on a different document:
     REJECTED, because the signature is mathematically bound to the message
     hash. Replay — re-presenting an accepted signature: REJECTED by the
     nonce ledger, that's double-spend protection. Channel tampering —
     disturbing qubits in flight — move the slider and watch the mismatch
     rate climb: REJECTED by the statistics. Unauthorized verification — a
     party with no key material tries to verify: FLAGGED as its own threat
     class. Five independent defenses, zero machine learning."*
4. Click **④ Run analysis**.
   - *"This chart is our forgery-probability guarantee: P equals
     four-to-the-minus q-times-lambda. Each extra security level λ buys
     roughly a thousandfold. The green line is 128-bit security. We exceed
     it at λ equals four."*
5. Click **⑤ Run evaluation** in the Performance panel.
   - *"Every metric the problem statement demands, measured live:
     verification accuracy above ninety-nine percent, detection rate,
     false alarms — zero — empirical versus theoretical forgery
     probability, and the actual computational cost per signature:
     tens of microseconds. The evaluation is seeded, so every number is
     reproducible for audit."*
6. If time allows, expand **Theoretical basis & references** at the bottom:
   *"Every mechanism I just showed maps to one of the three papers in our
   problem statement — Gottesman-Chuang for the verdict semantics,
   Singh-et-al for the teleportation pipeline, Weng-et-al for the six-state
   encoding and threshold rules — which we also implement as a second,
   complete QDS scheme in the six-state module."*

### Demo 4 — the product layer (3–4 min) ⭐ the v2 differentiator

*"So far you've seen the physics work. Here's it becoming a product —
we built seven features on top of those two layers."*

1. **Noise vs attack (the smart detector)** — drag **Fiber noise** to 8%,
   click Run.
   - *"Real fiber flips bits on its own. Watch: QBER climbs to eight
     percent — but the verdict is a degradation *warning*, not a breach,
     and the key is still distilled. The physics: environmental noise
     flips a polarization, it never *measures* it. Only a measurement
     collapses a state — and only collapse drives QBER to the one-third
     ceiling. Two physical processes, two signatures, one classifier."*
   - Now run the attack scenario: verdict flips red, distillation aborted.
2. **Relay routes** — drag **Relay hops** to 2, run.
   - *"Real QKD dies with distance — that's why every deployed QKD network
     uses trusted relays. Each link sifts independently: one-third per
     link, so two relays cost us one over twenty-seven of the key. That's
     the price of trusted-node networks, and the route strip shows you
     each hop — red dots where Eve sat."*
3. **Document sealing** — scroll to the **Quantum Document Vault**, drop
   any file, click **Seal → .qsig**, then **Verify**.
   - *"The session key from the QKD run now seals this document: its hash,
     an HMAC tag, and the audit root go into one portable container. Now I
     flip ONE byte of the file… re-verify: HMAC mismatch, instantly. One
     byte, caught."*
4. **Quorum unlock** — toggle **Shamir quorum seal** 3-of-5 before
   sealing; then toggle officers.
   - *"This document needs three of five officers. Two shares are
     mathematically one point short of a degree-two polynomial — zero
     information, not a policy. Two: rejected. Three: unlocked."*
5. **P2P transfer** — in the **Transfer Portal**, pick a file, 2 hops,
   **Send**.
   - *"Everything composes: seal, transmit through two relays — watch each
     hop sift and forward — unseal, verify. Live. Every stage is also an
     entry in the Merkle ledger."*
6. **Forensics** — in the Vault's **Merkle Audit Ledger**, press **proof**
   on any row.
   - *"How do you prove a signature wasn't forged three months ago? Every
     event is hash-chained under a Merkle root. Here's the inclusion proof
     for entry six — sibling hashes, recomputed root, match. If I had
     edited history, the chain verifier names the exact entry that
     broke."*

### Demo 5 (30 seconds) — the TUI second screen

Have `cargo run -p tui` already running in Windows Terminal beside the
browser. Press **2** (attack): the sparkline jumps toward one-third, the
verdict flips UNDER ATTACK. Press **s / v / t**: seal, verify, tamper-catch.

> "Same engine, second front-end — terminal over SSH, no browser. The
> framework isn't a dashboard veneer."

### Fallback demo (only if asked) — the JSONL audit log

Open `sih26141\qds_events.jsonl` in a text editor:

> "Every signature, verification, and attack was just persisted with a
> timestamp and verdict — an audit trail, which is a listed deliverable.
> The Merkle ledger is its cryptographically enforced twin."

---

## Part C — Questions judges will actually ask (with your answers)

**Q: "Is this a real quantum computer?"**
> "No — it's a faithful *classical simulation* of the quantum protocol, the
> same way flight simulators model aerodynamics. We simulate the information
> structure: entanglement correlations, measurement collapse, teleportation
> corrections. That's exactly what the problem statement asks for — a
> software framework with mathematical modelling, attack simulation, and
> security analysis. Building it on real QKD hardware is a procurement
> question, not a software question."

**Q: "How is this different from post-quantum cryptography (PQC), like the
new NIST standards?"**
> "PQC is *computational* security — new math problems we *believe* quantum
> computers can't solve. Ours is *information-theoretic* — security from
> physics, valid against adversaries with unbounded computers. They're
> complementary: NIST for the internet at large, QKD/QDS for high-assurance
> links. Our QKD layer even produces keys that could feed PQC or AES."

**Q: "Where's the AI/ML? The problem title says 'quantum-inspired cyber
threat detection'."**
> "The problem statement explicitly says *without relying on AI or machine
> learning* — detection must come from quantum principles: Pauli eigenstates,
> projective measurements, statistical thresholds. That's what we built:
> every verdict is a threshold rule on measured mismatch rates. It's more
> explainable than any ML model — I can derive each alarm from first
> principles on a whiteboard."

**Q: "What stops Eve from intercepting just a little bit?"**
> "Nothing — and that's honest physics, not a flaw. If Eve reads 10% of
> qubits she gets 10% of the key material but introduces ~3.3% QBER, which
> our threshold catches when enough samples accumulate. The defense is
> sample size: the Hoeffding margin shrinks like one over root-n, so longer
> runs tighten the net. Privacy amplification then compresses away whatever
> partial information she holds. Detection threshold versus key yield is
> *the* fundamental trade-off in QKD — our sweep chart shows it exactly."

**Q: "Why 1/3? I've heard 25% for QKD attacks."**
> "25% is BB84, which uses two bases. We implement six-state, which uses
> three — Eve guesses the right basis one-third of the time instead of one
> half, and her wrong-basis visits randomize the bit half the time:
> two-thirds times one-half is one-third. Six-state is *harder* to
> eavesdrop on; the cost is fewer sifted bits. Same trade-off the literature
> describes."

**Q: "How is your 'degradation warning' different from just a lower
threshold?"**
> "It's a physically grounded three-way classifier, not a second threshold.
> Environmental noise flips polarizations without touching bases; a
> measurement — Eve — collapses the state into her basis, which is the
> *only* mechanism that drives QBER to the one-third ceiling. So: QBER
> within noise-floor plus Hoeffding margin → secure; above that but below
> the intercept ceiling → degraded, keys still distilled, event logged;
> above the ceiling → attack, abort. The warning band moves with the
> configured noise floor, so a clean run at three percent noise stays
> secure."

**Q: "Why trusted relays instead of quantum repeaters?"**
> "Because that's what every deployed QKD network actually is — SECOQC
> Vienna, Tokyo, Beijing–Shanghai. True repeaters need quantum memory and
> entanglement swapping, still lab-stage. Our relays measure-and-forward,
> so we model the honest cost: yield falls as one-third per link. We make
> the limitation visible instead of pretending it away."

**Q: "What stops one officer from unlocking a quorum document?"**
> "Shamir secret sharing over GF(251): the seal key is the constant term
> of a random degree k-minus-one polynomial, one polynomial per key byte.
> k−1 shares are mathematically one point short — every key value is
> consistent with them, so they leak *zero* information. That's
> information-theoretic, the same grade of security as the QKD layer
> itself. k shares reconstruct by Lagrange interpolation, and each share
> carries a commitment so fabricated shares are rejected before
> reconstruction is even attempted."

**Q: "Your .qsig confidentiality — is that real encryption?"**
> "Yes — as of the current build every new seal is AES-256-GCM under the
> QKD session key, with the document metadata bound as associated data.
> The docs flag the honest history: the earliest v1 containers used a
> demo-grade XOR keystream, and that path survives only to verify old
> files. The *load-bearing* primitives were always standard: SHA-256
> binding, HMAC-SHA256 under the QKD session key, Shamir over a prime
> field, hash-chained Merkle commitments.
> for AES-256-GCM keyed by the same QKD secret — a one-function change.
> We say this before you find it."

**Q: "What exactly is teleporting here?"**
> "Quantum *states*, not matter. Alice destroys her qubit by measuring it
> jointly with her half of an entangled pair — that's the Bell measurement —
> sends two classical bits, and Bob applies one of four Pauli corrections to
> reconstruct the state. The two-bit outcome is uniformly random, so the
> correction stream itself becomes unpredictable signature material. The UI
> shows the actual trace — outcomes and corrections, row per qubit."

**Q: "Isn't SHA-256 a weakness if you claim information-theoretic security?"**
> "Sharp question. The signature verification itself — the XOR correlation
> checks — needs no computational assumption. We use SHA-256 in two auxiliary
> roles: the public-key *commitment* and message *binding*; there we treat it
> as a random oracle, the standard analysis. The privacy-amplification step
> would use a universal₂ hash family in a production system — it's on our
> roadmap, and we say so in the docs."

**Q: "Forgery probability — how is 10⁻³⁹ computed?"**
> "Each signature position publishes two bits tied to secret quantum
> correlations. A forger must guess both bits correctly at every one of 64
> positions: one quarter to the 64th power, about 2.9 times ten to the minus
> thirty-nine. We also ran a 20,000-trial Monte-Carlo on small parameters —
> it converges to exactly the theoretical one-quarter per position. Theory
> and simulation agree; that's the chart in step four."

**Q: "What happens if the channel is noisy but nobody's attacking?"**
> "In the real world, noise and attacks both raise QBER, and our threshold
> framework handles both — that's exactly what the two-threshold gray zone
> from Gottesman-Chuang is for: below c-one you accept, above c-two you
> reject, in between you get 'valid but don't forward'. In this prototype
> the channel is noiseless unless Eve acts, so the gray zone is demonstrated
> in tests. Adding a noise slider is roadmap item one."

**Q: "Who is Trent? Why do you need a trusted center?"**
> "Trent is the distribution center from the teleportation-QDS
> architecture — he prepares and routes the entangled pairs and keeps the
> nonce registry. He never learns the signed messages' content beyond hashes
> and never needs to trust Alice or Bob individually. Trust models like this
> are standard in the QDS literature — Singh-et-al's blockchain nodes and
> Weng-et-al's network center play the same role."

**Q: "What works today, end to end?"**
> "Everything you've seen is running live: key generation, QKD with live
> detection, sweeps, teleportation signing, four attack simulations,
> forgery analysis, audit logging. Seventeen automated tests all pass. The
> deliverables table — mathematical model, detection framework, signature
> module, attack module, prototype with dashboard and logging — is covered
> item by item."

---

## Part D — Deliverables checklist (map to their table, 30 seconds if asked)

| Their deliverable | Where it lives |
|---|---|
| 1. Math model of teleportation-based QDS | `docs/QDS_MATH_MODEL.md` — Bell states, teleportation derivation, correction table, verification equations, forgery theorem, complexity |
| 2. Threat-detection framework | `detection` + `qds::verify` + `qds::six_state::classify` — statistical/threshold rules, all five attack classes detected |
| 3. Signature generation & verification module | `qds` crate: `sign` / `verify` / teleportation with Pauli corrections; quantum public-key distribution via Trent; plus the six-state scheme (`six_state::sign_six_state` / `verify_six_state`) |
| 4. Attack simulation module | `qds::attacks` + QKD `attacks` — forgery, impersonation, replay, channel tampering (adjustable fraction), unauthorized verification, intercept-resend; all with tests |
| 5. Performance evaluation | `qds::metrics` + `/api/qds/metrics` + dashboard panel — verification accuracy, detection rate, false alarms, forgery probability, per-operation timings; seeded & reproducible |
| 6. Software framework / prototype | `server` + `frontend` — simulation environment, verification interface, live dashboard, persistent security-event log |

Constraints check: no AI/ML ✓ · deterministic acceptance ✓ (theorem + test) ·
low complexity ✓ (O(q·λ), microseconds — measured in the metrics panel) ·
information-theoretic security ✓ (XOR correlations, no computational
assumption in the verification path) · prototype + code + documentation ✓.

---

## Part E — Flashcards (read before walking in)

**Numbers that impress:**
- QBER under full intercept-resend: **exactly 1/3** (six-state; 1/4 for BB84)
- Partial eavesdropping: **QBER = f/3**
- Forgery probability: **4^(−qλ)**; default (16 qubits, λ=4) ⇒ **~2.9×10⁻³⁹**
- MC validation: 20,000 trials, converges to 0.25 at (1,1) — matches theory
- Hoeffding margin: **ε = √(ln(2/δ)/2n)**, δ = 0.05, shrinks like 1/√n
- Detection crossover: **~60–70% interception** at base threshold 15%
- Sifting yield: **~1/3** of qubits survive (three bases)
- Tests: **35 passing** (3 QKD unit, 3 QKD integration, 29 QDS incl. six-state scheme, noisy thresholds, metrics)
- Throughput: 20,000 qubits streamed in ~10 s (artificially paced); compute
  itself is microseconds — O(qλ)

**One-liners to deploy when cornered:**
- "Security from physics, decisions from statistics, zero black boxes."
- "We don't prevent eavesdropping; we make it *uneconomical to hide*."
- "The simulation agrees with the theory because the theory is *derivable* —
  that's the difference between a demo and a model."
- "Every alarm I raise, I can derive on a whiteboard. Can any ML product
  here say that?"
- "The nonce ledger is why double-spend dies here — the same reason the
  blockchain paper cites."

**If the demo breaks:** stay calm, say "let me show the same pipeline in the
CLI," run `cargo run -p main_app`, and keep narrating — the physics is the
same. Screenshots are the last resort; the story doesn't depend on them.

**Three things to NEVER say:**
- "It's just a simulation so it's not really secure" — say "the *protocol*
  is what's secure; the simulation demonstrates it faithfully."
- "The AI detects threats" — there is no AI. Statistics only. Say so proudly.
- "I'm not sure" without a follow-up — follow every uncertainty with
  "but here's where it's documented / here's how we'd find out."

---

## Part F — Room-readiness checklist (tonight)

- [ ] `cargo test --workspace` passes (57/57) — run it once tonight
- [ ] Server starts: `PORT=8080 cargo run -p server` from `sih26141\`
- [ ] Browser loads `http://127.0.0.1:8080`, pill says **API online**
- [ ] Full dry run of Demos 1–3 out loud, timed (target ≤ 7 min)
- [ ] Backup: CLI demo works (`cargo run -p main_app`)
- [ ] Print or bookmark: `docs/PROJECT_GUIDE.md`, `docs/QDS_MATH_MODEL.md`
- [ ] Know where `qds_events.jsonl` is for the audit-log moment
- [ ] Charge the laptop. Close Slack. Increase font size (Ctrl+= in browser).

Good luck. You built something real — show it like it is.
