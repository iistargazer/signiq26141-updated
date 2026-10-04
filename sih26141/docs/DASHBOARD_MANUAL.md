<p align="center"><img src="assets/prometheus-flame.svg" width="56" alt="Team Prometheusz flame" /></p>

# SigniQ — Dashboard Manual

**Team Prometheusz · SIH26141 · September 29, 2026**

A panel-by-panel guide to the SigniQ web dashboard. Companion documents: the [whitepaper](SIGNIQ_WHITEPAPER.md) (how it works and why), the [handbook](PROJECT_HANDBOOK.md) (APIs and configuration), and the [deliverables audit](DELIVERABLES.md).

## Contents

1. [Getting started](#1-getting-started)
2. [Reading the top bar](#2-reading-the-top-bar)
3. [Channel — the QKD experiment](#3-channel--the-qkd-experiment)
4. [Noise vs Eve — a controlled comparison](#4-noise-vs-eve--a-controlled-comparison)
5. [Diagnosis — the blind challenge](#5-diagnosis--the-blind-challenge)
6. [Vault — sealing and opening documents](#6-vault--sealing-and-opening-documents)
7. [Transfer — streaming delivery and quorum](#7-transfer--streaming-delivery-and-quorum)
8. [Peers — laptop-to-laptop transfer](#8-peers--laptop-to-laptop-transfer)
9. [Attack lab — watching forgeries fail](#9-attack-lab--watching-forgeries-fail)
10. [Signatures — the QDS Signature Lab](#10-signatures--the-qds-signature-lab)
11. [Consensus — the ring and the confidence engine](#11-consensus--the-ring-and-the-confidence-engine)
12. [Ledger — the audit trail and offline evidence](#12-ledger--the-audit-trail-and-offline-evidence)
13. [Accounts, P2P and the demo choreography](#13-accounts-p2p-and-the-demo-choreography)
14. [Parameters reference](#14-parameters-reference)
15. [Interpreting results](#15-interpreting-results)
16. [Guided run and the team dossier](#16-guided-run-and-the-team-dossier)

---

## 1. Getting started

Start the server (`cargo run -p server`) and open the printed URL — normally `http://127.0.0.1:8080`. The dashboard is a single scrolling page: a top navigation rail with ten sections (Channel · Noise vs Eve · Diagnosis · Vault · Transfer · Peers · Attack lab · Signatures · Consensus · Ledger), an editorial "folio" opener for each, and the panels beneath. On phones the rail scrolls horizontally with a hidden scrollbar; the active tab follows your scroll.

New visitors should press **Guided run** in the hero to walk the pipeline end-to-end; the **team flame** in the hero opens the six-person team dossier.

## 2. Reading the top bar

- **Status pill** — backend health (green/gray/red), polled continuously.
- **Guided run** — the tour button (hero).
- **Auth bar** — anonymous by default: you operate as the shared session user. Register/login switches you to a private workspace (private inbox, outbox, session key).

## 3. Channel — the QKD experiment

The Live Channel Monitor streams a six-state QKD simulation. Set parameters and run:

| Parameter | Meaning |
|---|---|
| Key length | Qubits prepared (10k–50k typical). More qubits → tighter statistics (Hoeffding margin ε ∝ 1/√n). |
| Threshold | Acceptance threshold on QBER, e.g. 0.15 = 15%. The *effective* line moves with sample size (dynamic threshold). |
| Eve ratio | Fraction of qubits an eavesdropper intercepts. 1.0 = full intercept-resend → QBER ≈ 33% (measured 33.60% at 20k qubits, seed 424242). |
| Noise rate | Environmental bit-flip probability (fiber model). Independent of Eve — "degraded" vs "under attack". |
| Relay hops | Number of trusted relay nodes. Each hop costs a (1/3)^hops yield factor. |
| Pace | Per-qubit delay in ms — slows the stream for narration. |
| Seed | Blank = fresh randomness each run; **typed seed reproduces the run bit-identically**. |

**Reading the run:** the status card shows the scenario verdict, **CHSH S value** (honest channels certify at S ≈ 2.83–2.85; classical bound 2), sifted count (≈ 1/3 of qubits), QBER vs the dynamic threshold, channel class (secure / degraded / under attack), and whether a key was distilled. Under attack, key distillation **aborts**. A successful secure run distills a session key the server holds; the browser never sees raw key material, only commitments.

## 4. Noise vs Eve — a controlled comparison

The controlled experiment separating environmental degradation from adversarial interception: same channel, controlled noise and intercept fractions, side-by-side QBER curves with the dynamic threshold overlaid. Read it as the visual argument for "degraded but honest" vs "statistically settled under attack".

## 5. Diagnosis — the blind challenge

A blind statistical challenge: the panel runs a hidden channel configuration and you judge honest vs attacked from statistics alone before reveal (`/api/blind-challenge/*`). Practice for the core claim — detection comes from measurement statistics, not from labels.

## 6. Vault — sealing and opening documents

The Quantum Document Vault seals files into opaque `.qsig` containers — a file goes in; the container comes out, and what's inside is ciphertext with a cryptographic binding, not a preview. Controls:

- **Seal** — choose a file; the server seals it under the session key (AES-256-GCM payload, HMAC-SHA256 tag, SHA-256 of the document in metadata). Optional **Shamir quorum seal** (k-of-m): the seal key is split across m officers; below k shares the document is cryptographically unrecoverable.
- **Verify** — re-checks a container: format, authenticity (QDS signature), integrity (HMAC + hash), key match (commitment). Each flag appears as an outcome flag with a note explaining any failure by name.
- **Open** — recovers the original bytes (quorum-gated when sealed with quorum).
- **Attack battery** — four tamper modes against any container; verification explains each rejection: AES-GCM tag mismatch (payload/metadata/key tampering), key-commitment mismatch (reseal under a different key).

Containers show an `audit_ref` — the Merkle audit coverage of their sealing events.

## 7. Transfer — streaming delivery and quorum

The transfer simulation streams a seal → send → receive → verify delivery with live SSE narration (`/api/doc/transfer`). Shamir quorum workflows (`/api/doc/quorum/*`) distribute shares, collect pledges, and unlock below-quorum-refuses / at-quorum-opens.

## 8. Peers — laptop-to-laptop transfer

Peer-to-peer delivery between two SigniQ instances (`/api/doc/send` with a peer URL): Alice's laptop delivers to Bob's laptop; Bob's inbox auto-checks and the verify endpoint explains the verdict. Same-server user-addressed delivery uses `to_user`. Inbox/outbox lists with delete; relay drop/claim workflow for offline delivery.

## 9. Attack lab — testing the document seal

The Attack Lab stages the full interception story: capture → inspect → tamper → forward → **recipient rejection** (`/api/doc/attack-theater`), each step narrated and recorded in the audit ledger. Attack modes mirror the vault battery: `tamper_bytes`, `swap_meta`, `reseal`, `truncate`.

## 10. Signatures — the QDS Signature Lab

The teleportation-based QDS lab (`/api/qds/*`):

- **Sign / Verify** — mint a signature (temporal trap: quantum-entropy timestamp, window sequence, chain link) and verify it (1-ACC / 0-ACC / REJ verdicts with named reasons).
- **Attack battery** — six attack classes, each rejected with its reason: replay (window sequence), timestamp forgery (chain check), forgery (temporal binding), impersonation (tag binding), channel tampering (mismatch ratio), unauthorized verification (no session key material).
- **Modeled forgery probability** — 4^(−qλ) with the current parameters (4⁻⁸ ≈ 1.5×10⁻⁵ at defaults; 2.9×10⁻³⁹ at (16,4)).
- **Metrics** — verification accuracy, per-class detection rates, false-accept and false-alarm rates, operation timings (`/api/qds/metrics`).

## 11. Consensus — the ring and the confidence engine

Two panels share this section:

- **Consensus ring** (`/api/qds/consensus-ring`): the signature is delivered to m receivers with independent channel noise per member (a compromised member can be injected); each verifies with full trap semantics; the ring reports unlock/transfer grades. k=3-of-5 tolerates one compromised member; k=5-of-5 does not.
- **Statistical confidence** (`/api/stats/bounds`): Chernoff–Hoeffding intervals, the N-scaling threshold curve ("vice" that narrows with sample size), REJECT-verdict p-values with bands — including **"undersized"** when the sample cannot separate honest from attack. A detector that says "cannot decide" is a feature, not a bug.

## 12. Ledger — the audit trail and offline evidence

The Merkle Audit Ledger panel polls the audit ledger (8 s cadence; newest first; click a row for detail). Every seal, verification, rejection, attack, key derivation, and delivery is appended with sequence number, timestamp, actor label, accepted flag, detail, payload hash, and chain link. `GET /api/audit/verify` re-walks the chain continuously.

**Offline evidence export:** export a self-contained bundle and verify it offline — the browser builds a standalone verifier page (`frontend/src/auditEvidence.ts`) that checks the bundle's internal hashes, root, and inclusion proofs with no server connection. Scope, stated plainly: this proves the ledger's internal consistency. It does not prove who published it; publisher authentication requires an expected root from an independent trusted channel. There is no key-revocation lifecycle.

## 13. Accounts, P2P and the demo choreography

The classic three-laptop demo: Alice (sender), Bob (recipient), Mallory (attacker) on separate browser profiles/instances, each with an account. Alice runs the seeded QKD run, seals a document, delivers to Bob (peer URL or same-server `to_user`); Mallory captures and tampers; Bob's verification rejects with named reasons; the ledger records everything. Seeded runs make the laptops agree on the same session key without transmitting it. The deployment guide's §5 covers the k-of-m account workflow.

## 14. Parameters reference

| Panel | Parameter | Range & effect |
|---|---|---|
| Channel: Key length | 10k–50k qubits | More → tighter ε(n) ∝ 1/√n statistics, slower run |
| Channel: Threshold | 0.05–0.30 | Acceptance line on QBER; effective line moves with n |
| Channel: Eve ratio | 0–1 | Intercept fraction; QBER → f/3 |
| Channel: Noise rate | 0–1 | Environmental flips; "degraded" vs "under attack" |
| Channel: Relay hops | 0–4 | (1/3)^hops yield cost |
| Channel: Pace | 0–10 ms | Narration delay per qubit |
| Seed | blank or integer | Blank = fresh randomness; typed = bit-identical reproduction |
| Vault: Shamir k-of-m | k ≤ m | Below k, recovery is cryptographically impossible |
| QDS: q (qubits), λ (repetition) | 8×1 default | Forgery P = 4^(−qλ): 1.5×10⁻⁵ → 2.9×10⁻³⁹ |

## 15. Interpreting results

- **QBER ≈ f/3** — the six-state eavesdropping signature. 0% = honest; ~33% = full interception; between = partial.
- **Dynamic threshold** — noise floor + Hoeffding margin ε(n); narrows as samples accumulate. A verdict needs the sample *settled* (`finite_key_ok`).
- **CHSH S** — S > 2 certifies non-classical correlations; ≈ 2.85 honest; ≤ 2 under intercept-resend; noise above ~14.6% erases violation even without Eve.
- **Verdict bands** — airtight / decisive / significant / undersized; "undersized" means the sample cannot decide.
- **1-ACC / 0-ACC / REJ** — unconditional / non-transferable / reject. Transferability grades forwarding.
- **Key commitment** — a digest binding the container to its sealing key; mismatch = sealed under a different key.

## 15.1 Metrics (QDS Lab)

`/api/qds/metrics?trials=120&seed=42` (also surfaced in the lab): verification accuracy 100%, detection rate 100%, false-accept rate 0.0%, per-class detection 100% across the five classes, forgery probability 4⁻⁸ ≈ 1.5×10⁻⁵, sign 41 µs / verify 18 µs (machine-specific). These are seeded simulation measurements under the implemented test distributions — not universal guarantees.

## 16. Guided run and the team dossier

**Guided run** walks the pipeline end-to-end: channel experiment → noise-vs-eve → vault → attacks → signatures → consensus → ledger, with non-technical explanations per step. The **team flame** in the hero opens the dossier: six profiles (initials avatar when no photo), roles and duties; members can add real photos (`frontend/public/team/`, `photo: '/team/name.jpg'`), links and quotes by editing the roster in `frontend/src/components/Team.tsx`.

---

*All quantum behavior is classical software simulation. The audit ledger proves internal consistency only. Educational prototype — not production cryptography.*
