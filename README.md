<p align="center">
  <img src="sih26141/docs/assets/prometheus-flame.svg" width="84" alt="Team Prometheus flame" />
</p>

<h1 align="center">SigniQ</h1>

<p align="center">
  <b>Team Prometheusz</b> · SIH26141<br/>
  Rust (edition 2021) · React 19 · TypeScript · Vite<br/>
  Quantum-inspired threat detection for digital-signature security — an honest, inspectable software simulation.
</p>

<p align="center">
  📄 <a href="sih26141/docs/pdf/SIGNIQ_WHITEPAPER.pdf"><b>Read the Whitepaper (PDF)</b></a>
  &nbsp;·&nbsp; <a href="sih26141/docs/pdf/PROJECT_HANDBOOK.pdf">Handbook</a>
  &nbsp;·&nbsp; <a href="sih26141/docs/pdf/DASHBOARD_MANUAL.pdf">Dashboard Manual</a>
  &nbsp;·&nbsp; <a href="sih26141/docs/pdf/README.pdf">Overview</a>
</p>

---

SigniQ is a classical software simulation of a quantum-secured document pipeline. It pairs a six-state quantum key distribution model with a teleportation-based quantum digital signature protocol, then layers explicit statistical threat detection on top — **no AI, no ML**: every accept/reject verdict comes from a closed-form bound or threshold applied to measurement statistics. You can seal a document, attack it four different ways, and watch each forgery get rejected for a named, explainable reason.

The problem statement asks for exactly this shape of work: *"a simulation of a teleportation-based quantum digital signature protocol with a threat-detection layer that, explicitly without any AI or ML, uses quantum principles — Pauli eigenstates, projective measurements and statistical analysis of measurement outcomes — to detect forgery, impersonation, replay attacks and quantum channel manipulation by computing forgery probabilities and verification accuracy from measurement statistics, evaluated through attack simulations that show detection rates and false-accept rates while preserving the protocol's information-theoretic security guarantees."* Every clause of that sentence is implemented and mapped to source in [`sih26141/docs/DELIVERABLES.md`](sih26141/docs/DELIVERABLES.md).

## What it is / what it is not

|  It is |  It is not |
|---|---|
| A classical **simulation** of QKD and teleportation-based QDS | Quantum hardware, a physical channel, or a real detector |
| Statistical detection: Hoeffding/Chernoff bounds, binomial tails | An AI/ML system — zero ML dependencies (grep-verifiable) |
| An educational prototype with reproducible seeded experiments | Production cryptography |
| A tamper-evident audit ledger proving **internal consistency** | Publisher authentication — an audit root alone doesn't prove *who* published |

## System architecture

SigniQ runs as one Rust service (the Axum API server also hosts the built dashboard) plus the browser client. The pipeline executes in strict causal order — every layer is a classical software model:

| Layer | Component | Crate · entry point | Description |
|---|---|---|---|
| 1 | Six-state QKD | `quantum` · `src/lib.rs` | Pauli eigenstate preparation (X/Y/Z × ±1), channel + relay hops + fiber noise, sifting, QBER |
| 2 | Threat detection | `detection` · `src/lib.rs`, `src/bounds.rs` | Hoeffding/Chernoff confidence intervals, exact binomial tails, dynamic thresholds, verdict p-values |
| 3 | Key distillation | `pa` · `src/lib.rs` | Reconciliation, Toeplitz universal₂ extraction sized by the leftover-hash lemma; HMAC-SHA256 binding in `crypto` |
| 4 | Teleportation QDS | `qds` · `src/teleport.rs`, `src/six_state.rs` | Statevector Bell measurement (Born rule), Pauli corrections, 1-ACC/0-ACC/REJ verdicts, temporal replay trap |
| 5 | Document sealing | `sealing` · `src/lib.rs` | `.qsig` containers: AES-256-GCM, key commitments, Shamir k-of-m quorum |
| 6 | Delivery & attack lab | `server` · `src/doc_api.rs` | P2P transfer, consensus rings, tamper battery, attack theater replay |
| 7 | Audit ledger | `audit` · `src/lib.rs` | Hash-chained JSONL, RFC 6962-style Merkle tree, per-event inclusion proofs, offline browser verification |

```
┌──────────────┐  3000 Pauli eigenstates (X/Y/Z × ±1)
│    Alice     │──────────────────────────────┐
└──────────────┘                              ▼
┌─────────────────────────────────────────────────────────────┐
│  channel model: fiber noise · relay hops · Eve scenarios    │
│  (intercept–resend, photon-number-splitting)                │
└─────────────────────────────────────────────────────────────┘
                              │ measurement records
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  threat detector: QBER vs dynamic threshold · Hoeffding /   │
│  Chernoff confidence intervals · exact binomial tails       │
│  (explicit statistics only — no AI, no ML)                  │
└─────────────────────────────────────────────────────────────┘
            │ authentic                     │ attack detected
            ▼                               ▼
┌───────────────────────────┐   key distillation aborted
│  privacy amplification    │   (an abort rejects this run;
│  Toeplitz extractor +     │    it is not key revocation)
│  SHA-256 → 256-bit key    │
└─────────────┬─────────────┘
              ▼
┌───────────────────────────┐      ┌────────────────────────────┐
│  HMAC-SHA256 binding ·    │      │  audit ledger: hash chain  │
│  .qsig seal (AES-256-GCM, │─────▶│  · Merkle root · inclusion │
│  key commitment, quorum)  │      │  proofs (internal consist.)│
└───────────────────────────┘      └────────────────────────────┘
```

**1 — Key generation (six-state QKD simulation).** Alice prepares qubits in one of six Pauli eigenstates (X/Y/Z × ±1). Bob measures in random bases; the sifted key's error rate (QBER) is compared against a Hoeffding-derived threshold that tightens as sample count grows. A clean channel distills a 256-bit key via privacy amplification; an intercepted channel crosses the threshold and key distillation aborts.

**2 — Signatures (teleportation-based QDS).** Signatures are built from genuine Bell-measurement outcomes of a statevector teleportation engine — CNOT + Hadamard, Born-rule collapse, Pauli corrections. Forging the whole signature means guessing every Bell outcome: **P(forgery) = 4^(−q·λ)** (≈1.5×10⁻⁵ at default parameters q=8, λ=1). Verdicts follow the protocol's 1-ACC / 0-ACC / REJ semantics with transferability, and a temporal trap (single-use nonces + sifting-window sequence) kills replays.

**3 — Threat detection (statistics, not models).** Detection rates and false-accept rates come from seeded Monte-Carlo attack batteries over a confusion matrix. Forgery, impersonation, replay, channel tampering and unauthorized verification each have a named attack routine and a named rejection reason.

**4 — Documents.** Files are sealed into `.qsig` containers (AES-256-GCM, key commitment, Shamir-split quorum optional) and delivered peer-to-peer or through k-of-m consensus rings. The recipient verifies the container cryptographically before trusting a byte of it.

## Features

- **Six-state QKD simulation** — Pauli eigenstate preparation, sifting, QBER, finite-sample classification, relay hops and fiber-noise modeling, live channel streaming with attack scenarios.
- **Teleportation-based QDS** — statevector Bell measurement, Born-rule outcomes, Pauli corrections, 1-ACC/0-ACC/REJ verdicts, transferability (second-verifier consensus), replay-state persistence across restarts.
- **Threat-detection layer** — Hoeffding/Chernoff confidence engine (`/api/stats/bounds`), dynamic rejection thresholds, per-attack-class detection rates, explicit false-accept rate.
- **Document vault** — seal/open `.qsig` containers (v2 payload AES-256-GCM; v3 envelope hides all metadata), tamper battery, attack theater replay.
- **P2P transfer + consensus rings** — laptop-to-laptop delivery, same-server user delivery, k-of-m attestation gates that stay locked below quorum.
- **Audit ledger** — persistent JSONL events, hash chain, Merkle root, inclusion proofs, portable export, offline bundle verification in the browser.
- **Evaluation** — `/api/qds/metrics` returns verification accuracy, per-class detection, false-accept/false-alarm rates, forgery probabilities (empirical + theoretical), and operation timings.
- **Dashboard + TUI** — React dashboard with live SSE monitor, guided run, team dossier; terminal UI via `cargo run -p tui`.

## Evaluation results

Measured live on this codebase (isolated scratch instance; `trials=120, seed=42` — reproducible with the command in [Verification](#verification)):

| Metric | Teleport QDS | Six-state QDS |
|---|---|---|
| Verification accuracy | 100.0% | 100.0% |
| Detection rate (TPR) | 100.0% | 100.0% |
| False-accept rate (missed attacks) | 0.0% | 0.0% |
| False-alarm rate (legitimate flagged) | 0.0% | 0.0% |
| Per-class detection (forgery / impersonation / replay / channel tampering / unauthorized) | 100% each | 100% each |
| Theoretical forgery probability | 4⁻⁸ ≈ 1.53×10⁻⁵ | — |
| Empirical forgery success | 0 / 120 | 0 / 120 |
| Timing (sign / verify) | 41 µs / 18 µs | machine-specific |

End-to-end behavior in the same run: 4/4 tamper modes rejected with named causes; consensus ring locked at k−1, opened at quorum with byte-exact document recovery; 6/6 QDS attack classes rejected; audit chain verified intact over 131 events. These are simulation measurements under seeded test distributions — not universal security guarantees (see [Limitations](#limitations)).

## The audit ledger

Every security-relevant action — seal, verify, attack, key derivation, delivery — is appended to a hash-chained JSONL ledger with a Merkle root and per-event inclusion proofs. The dashboard can export a self-contained bundle and verify it offline; `GET /api/audit/verify` re-checks the chain. **Scope, stated plainly:** this proves the ledger's internal consistency. It does not prove *who* published it — that requires an expected root from an independent trusted source. There is deliberately no key-revocation lifecycle: a QKD abort or rejected signature is not revocation.

## Quickstart

Requirements: **Rust (cargo)** and **Node.js 20+ with npm**.

```sh
# 1. Build the dashboard
cd sih26141/frontend
npm ci
npm run build
cd ../..

# 2. Run the API server (serves the built dashboard too)
cd sih26141
cargo run -p server

# 3. No-server walkthroughs
cargo run -p main_app   # seeded end-to-end demo of every engine
cargo run -p tui        # terminal UI
```

Open the printed URL — normally `http://127.0.0.1:8080`. For frontend hot reload, run `npm run dev` from `sih26141/frontend/` while the API server runs.

## Deploying

| Piece | Where | Status |
|---|---|---|
| Dashboard (frontend) | **Vercel** — this repo root's `vercel.json` builds `sih26141/frontend` | deployed |
| API + full app | **Render** — Blueprint at `sih26141/render.yaml` (Docker build, free plan, `/api/health` check) | apply the Blueprint in the Render dashboard |
| Link them | Add the Render URL as an `/api/(.*)` rewrite in the root `vercel.json`, push | after Render is live |

**What Docker is for:** the [`Dockerfile`](sih26141/Dockerfile) is the build *recipe Render runs on their servers* (Node builds the dashboard, Rust builds the API, one runtime image serves both with state under `/data`). You never need Docker installed — it is the packaging format that makes the deployment reproducible anywhere.

**24/7 note:** Render's free plan sleeps after ~15 idle minutes (30–60 s cold start) and has no persistent disk; the paid Starter plan removes both limits.

Server environment variables (PORT, HOST, FRONTEND_DIST, AUDIT_LOG, USERS_FILE, QDS_EVENT_LOG, TRENT_SEED) are documented in [`sih26141/docs/PROJECT_HANDBOOK.md`](sih26141/docs/PROJECT_HANDBOOK.md).

## Repository layout

```
├── README.md              ← this landing page
├── LICENSE
├── vercel.json            ← Vercel build config for the dashboard
└── sih26141/              ← the project workspace
    ├── quantum/           six-state QKD model: Pauli states, channel, relays, CHSH
    ├── pa/                privacy amplification: Toeplitz extractor, entropy accounting
    ├── detection/         Hoeffding/Chernoff bounds, dynamic thresholds
    ├── qds/               teleportation + six-state QDS, attacks, metrics, temporal trap
    ├── crypto/            shared primitives (HMAC-SHA256)
    ├── sealing/           .qsig containers: AES-256-GCM, commitments, Shamir quorum
    ├── audit/             hash chain, Merkle root, inclusion proofs
    ├── attacks/           QKD-channel attack scenarios
    ├── server/            Axum API + static dashboard hosting
    ├── main_app/          seeded CLI demo binary
    ├── tui/               terminal UI
    ├── tests/             cross-crate integration tests
    ├── frontend/          React 19 + TypeScript + Vite dashboard
    ├── docs/              whitepaper, handbook, manual, deliverables + pdf/ editions
    └── scripts/           PDF pipeline, isolated smoke test
```

## Documentation

| Document | Purpose |
|---|---|
| 📄 [Whitepaper (PDF)](sih26141/docs/pdf/SIGNIQ_WHITEPAPER.pdf) · [Handbook (PDF)](sih26141/docs/pdf/PROJECT_HANDBOOK.pdf) · [Manual (PDF)](sih26141/docs/pdf/DASHBOARD_MANUAL.pdf) · [Overview (PDF)](sih26141/docs/pdf/README.pdf) | Print-ready editions of all four documents |
| [`sih26141/docs/DELIVERABLES.md`](sih26141/docs/DELIVERABLES.md) | Clause-by-clause audit against the official problem statement |
| [`sih26141/docs/SIGNIQ_WHITEPAPER.md`](sih26141/docs/SIGNIQ_WHITEPAPER.md) | Full technical whitepaper: formal models, proofs, evaluation |
| [`sih26141/docs/PROJECT_HANDBOOK.md`](sih26141/docs/PROJECT_HANDBOOK.md) | Architecture, API reference, data formats, configuration |
| [`sih26141/docs/DASHBOARD_MANUAL.md`](sih26141/docs/DASHBOARD_MANUAL.md) | Panel-by-panel user manual for the web dashboard |
| [`sih26141/docs/QDS_MATH_MODEL.md`](sih26141/docs/QDS_MATH_MODEL.md) | Formal mathematical model of the teleportation QDS |
| [`sih26141/docs/PAPERS.md`](sih26141/docs/PAPERS.md) | Paper → mechanism → code → test literature map |

## Limitations

1. **All quantum behavior is classical software simulation.** No quantum hardware, physical detector, or physical channel participates anywhere.
2. **Simulation ≠ certification.** The protocol's information-theoretic arguments are preserved in the model; simulations demonstrate the statistics, they cannot certify physical devices.
3. **The audit ledger proves internal consistency only**, not publisher identity.
4. **No key-revocation lifecycle exists.**
5. **Metrics are seeded-reproducible, not universal** — detection rates describe the implemented test distributions; timings are machine-specific.
6. **Educational prototype** — review cryptographic constructions and deployment configuration before any production use.
7. **Deployment configuration ships in the repo** (Dockerfile, render.yaml — see [Deploying](#deploying)); it is not itself a security review of the hosting setup.

## Verification

```sh
cd sih26141
cargo test --workspace                              # 21 test binaries, all pass
cd frontend && npm run build && npm run lint        # dashboard build + lint

# Reproduce the evaluation numbers above against a fresh isolated instance:
cargo build -p server
PORT=8090 AUDIT_LOG=target/scratch/audit.jsonl QDS_EVENT_LOG=target/scratch/qds.jsonl \
USERS_FILE=target/scratch/users.json target/debug/server.exe &
node scripts/smoke-isolated.mjs                     # 47/47 checks
```

## License & team

Built by **Team Prometheus** for SIH26141. Team member profiles are in the dashboard's dossier (flame mark in the hero). This repository is an educational prototype; no warranty of fitness for any security purpose is given or implied.
