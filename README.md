# SIH26141 — Quantum-Secured Pipeline

Two quantum-security layers in one framework, deployed live:

- **Frontend (dashboard):** Vercel
- **Backend (Rust API server):** Render

Open the Vercel project URL for the full dashboard — the frontend proxies
`/api/*` to the Render backend, so one tab gets both layers.

(See `docs/DASHBOARD_RUN_GUIDE.md` for the full run/deploy checklist and
`docs/DASHBOARD_GUIDE.md` for what every element on the page does.)

## What it does

1. **Six-state QKD** with Hoeffding-bound eavesdropping detection, privacy
   amplification, and HMAC message authentication.
2. **Teleportation-based Quantum Digital Signatures (QDS)** — Bell-pair
   entanglement, quantum teleportation with Pauli corrections, nonce-ledger
   replay defense, and statistical (non-ML) forgery/impersonation/replay/
   channel-tampering detection with forgery-probability analysis.

Both layers are driven from a single Rust API server with an interactive React
dashboard. No AI/ML anywhere — detection is pure measurement statistics.

## Architecture

```
sih26141/
├── quantum/    Six-state prepare-and-measure QKD core
│                 • QuantumKeyGenerator  — Alice's Pauli eigenstate prep
│                 • ChannelSession       — incremental transmission (streaming)
│                 • simulate_six_state_transmission(_ratio) — batch simulation
│                 • privacy_amplification — SHA-256 key compression
├── qds/        Teleportation-based QDS (see docs/QDS_MATH_MODEL.md)
│                 • BellPair / teleport_bit / PauliOp — entanglement + corrections
│                 • Trent — notary center: key setup, nonces, ledger
│                 • sign / verify — teleportation signing + statistical verification
│                 • attacks — forgery, impersonation, replay, channel tampering,
│                            unauthorized verification (5 classes)
│                 • six_state — Weng-style six-state non-orthogonal-encoding QDS:
│                            Pauli eigenstate preparation, conclusive-bit logic,
│                            threshold-rule attack classifier
│                 • noisy — Hoeffding-bounded c1/c2 thresholds for noisy channels
│                 • metrics — repeatable evaluation: verification accuracy,
│                            detection rate, false positives/negatives, forgery
│                            probability, per-operation wall-clock timings
│                 • forgery probability — theory 4^(-qλ) + Monte-Carlo validation
├── detection/  ThreatDetector with two-sided Hoeffding bound:
│                 ε = √(ln(2/δ) / 2n), dynamic threshold = base + ε
├── attacks/    Intercept-resend eavesdropping scenario wrappers (QKD layer)
├── crypto/     HMAC-SHA256 message authentication over the derived key
├── main_app/   CLI demo binary (QKD pipeline)
├── server/     Axum REST + SSE API: /api/run, /api/simulate, /api/events,
│               /api/qds/{setup,sign,verify,attacks,forgery-analysis,events}
│               + persistent JSONL security-event log (qds_events.jsonl)
├── frontend/   React + TypeScript + Recharts dashboard (Vite): live QKD
│               monitor + QDS Signature Lab
├── tests/      Workspace integration tests (QKD pipeline)
├── docs/       PROJECT_GUIDE.md (full theory + walkthrough)
│               QDS_MATH_MODEL.md (formal model)
│               JUDGING_BOOK.md (consolidated judging-round reference)
│               JUDGE_PITCH.md (presentation playbook)
│               DASHBOARD_RUN_GUIDE.md (how to run the dashboard)
│               DASHBOARD_GUIDE.md (every dashboard element explained)
└── scripts/    run_simulations.sh — build, test, demo, serve
```

## Live deployment (no local install needed)

The dashboard is already deployed and running — use this for the judging round
and demo video unless you specifically want to run locally.

| Layer | Hosted at | What it is |
|---|---|---|
| Frontend (React dashboard) | **Vercel** — see repo Settings → Pages, or the Vercel project URL | Static build of `frontend/dist`, served globally |
| Backend (Rust API server) | **Render** — see the Render dashboard for the service URL | Axum REST + SSE API, auto-restarts on push |

The frontend on Vercel proxies `/api/*` to the Render backend, so one browser
tab gets both layers. If the backend restarts (cold start on first hit, or a
deploy), the first request may take a few extra seconds — after that it's
live.

### Local fallback (if you need to run it yourself)

Requires Rust (windows-gnu toolchain works, no MSVC needed) and Node.js ≥ 18.

```bash
# one-time: build the dashboard (only needed for local runs)
cd frontend && npm install && npm run build && cd ..

# start API + dashboard on http://127.0.0.1:8080
PORT=8080 cargo run -p server
```

Or everything at once (build + tests + CLI demo + dashboard):

```bash
./scripts/run_simulations.sh
```

Frontend development mode with hot reload (proxies /api to :8080):

```bash
cd frontend && npm run dev     # http://localhost:5173
```

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Liveness probe |
| `/api/server-info` | GET | Actual bound port (differs from the request only after a port fallback) |
| `/api/run` | POST | QKD simulation run: `key_length`, `base_threshold`, `intercept_ratio` (optional), `message`, `seed`, `pace_ms` |
| `/api/simulate` | POST | Sweep over `intercept_ratios` (up to 32 values) |
| `/api/events` | GET | SSE stream: `progress` / `result` / `done` events |
| `/api/qds/setup` | POST | Generate Trent/Alice Bell-pair key material (`qubit_count`, `lambda`) |
| `/api/qds/sign` | POST | Sign a message via teleportation; Bob verifies on delivery |
| `/api/qds/verify` | POST | Manually verify a (message, signature, nonce) triple |
| `/api/qds/attacks` | GET | Run forgery + impersonation + replay + channel tampering (tamper_fraction query param) + unauthorized verification, get verdicts |
| `/api/qds/forgery-analysis` | GET | Monte-Carlo vs theory (4^−qλ) forgery probabilities, λ-scaling |
| `/api/qds/metrics` | GET | Repeatable performance evaluation: verification accuracy, detection rates, false alarms, forgery probability, timings (trials, seed params) |
| `/api/qds/events` | GET | Recent security events (also persisted to `qds_events.jsonl`) |

```bash
# Local server example (replace with your Render URL for the deployed backend):
curl -X POST localhost:8080/api/run \
  -H 'Content-Type: application/json' \
  -d '{"key_length": 3000, "seed": 42, "pace_ms": 0}'
```

### Using the deployed stack

Point `curl` (or any HTTP client) at the Render backend URL instead of
`localhost:8080`. The Vercel frontend does this automatically — the only thing
to verify before the round is that the Render service is live (green status in
the Render dashboard) and that the Vercel deployment is the latest commit.

## Port fallback & dashboard discovery (local runs only)

If the requested port (default 8080) is held by another process or blocked by a
Windows reserved port range (os error 10013 — common with Apache/Hyper-V on
Windows), the server falls back to the next ports (up to +10) instead of
panicking, and:

1. writes `frontend/dist/server-port.json` stating the actual port, and
2. exposes it at `/api/server-info`.

The local dashboard auto-discovers this: when its same-origin health check fails it
reads the manifest, then probes adjacent ports — the "API offline" pill turns
green on its own within one poll (≤10 s). To free 8080 permanently, stop the
Apache service (`services.msc`) or run on another port: `$env:PORT=8090`.

For the Vercel + Render deployment, port handling is on the platform side —
Vercel routes `/api/*` to the Render service URL configured in the frontend
build settings, and Render assigns its own public URL. If the Render service is
down or redeploying, the dashboard will show the API-offline pill until it
comes back.

## What the simulation shows

- **Secure channel** — sifted keys match exactly; QBER 0.00%; a 256-bit key is
  distilled via SHA-256 privacy amplification and used to HMAC-authenticate a
  message.
- **Intercept-resend attack** — Eve measures and resends qubits; wrong-basis
  measurements disturb the state, driving QBER to ≈ 1/3. The Hoeffding bound
  flags the channel and key distillation is aborted.
- **Partial eavesdropping** — QBER ≈ intercept_ratio / 3 (see the sweep chart);
  detection fires once measured QBER crosses base + ε(n).

## Tests

```bash
cargo test --workspace
```

Covers the end-to-end secure pipeline, attack detection, input validation, the
partial-intercept ratio semantics (0.0 ≡ secure, 1.0 ≡ full attack, 0.3 ⇒
intermediate QBER), the six-state QDS scheme (honest acceptance, forgery /
impersonation / tampering / unauthorized-verifier rejection, click-rate ≈ 1/6),
noisy-channel thresholds, and the performance evaluation (accuracy > 0.99,
deterministic reproduction, per-class detection).

> Educational prototype — the privacy-amplification step is simplified
> (fixed SHA-256 rather than a universal₂ hash sized to estimated entropy and
> leakage), and there is no error-correction/reconciliation stage.
