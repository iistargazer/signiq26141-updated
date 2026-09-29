# SIH26141 — Quantum-Secured Pipeline

Two quantum-security layers in one framework, deployed live:

- **Frontend (dashboard):** Vercel
- **Backend (Rust API server):** Render

Open the Vercel project URL for the full dashboard — the frontend proxies
`/api/*` to the Render backend, so one tab gets both layers.

(See `docs/DASHBOARD_RUN_GUIDE.md` for the full run/deploy checklist,
`docs/DASHBOARD_GUIDE.md` for what every element on the page does,
`docs/DEPLOYMENT_GUIDE.md` for deploying to Render/Vercel and running the
three-laptop demo with accounts, and `docs/FEATURES_V2.md` for the deep-dive
on the v2 features.)

## What it does

1. **Six-state QKD** with Hoeffding-bound eavesdropping detection, privacy
   amplification, and HMAC message authentication.
2. **Teleportation-based Quantum Digital Signatures (QDS)** — Bell-pair
   entanglement, quantum teleportation with Pauli corrections, nonce-ledger
   replay defense, and statistical (non-ML) forgery/impersonation/replay/
   channel-tampering detection with forgery-probability analysis.

Both layers are driven from a single Rust API server with an interactive React
dashboard. No AI/ML anywhere — detection is pure measurement statistics.

## Seven scenario features (v2)

| # | Feature | Where |
|---|---|---|
| 1 | **Multi-hop relay nodes (quantum repeaters)** — route qubits through trusted relays, per-link sifting/noise/intercept stats | `quantum/src/relay.rs`, relay-hop slider + route view in the dashboard |
| 2 | **Noise & channel degradation filter** — environmental bit-flips (fiber/turbulence) independent of attacks; the detector gives a 3-way verdict: secure / **Channel Degradation Warning** / attack | `quantum` (noise model), `detection` (3-way classifier), fiber-noise slider |
| 3 | **Document sealing (`.qsig`)** — SHA-256 file hash + HMAC bound to the QKD session key + **AES-256-GCM** encrypted payload (metadata bound as AAD) in a versioned container, up to **5 MB** | `sealing` crate, `POST /api/doc/seal`, Quantum Document Vault |
| 4 | **P2P transfer portal** — real laptop-to-laptop transfer over HTTP + the simulated relay-route transfer, with a live per-stage log | `POST /api/doc/send` + `/api/doc/receive` + `/api/doc/inbox`, `POST /api/doc/transfer` (SSE), Peer-to-Peer panel |
| 5 | **Merkle-tree audit ledger** — hash-chained, append-only event log with Merkle root + inclusion proofs (forensics / non-repudiation) | `audit` crate, `/api/audit/*`, ledger panel |
| 6 | **Interactive TUI dashboard** — ratatui terminal UI with live QBER sparkline, relay route, vault actions, audit tail | `tui` crate — `cargo run -p tui` |
| 7 | **n-of-m threshold authorization** — Shamir secret sharing of the seal key across officers; k-of-m shares unlock | `sealing` (GF(251) Shamir), `/api/doc/quorum` + `/api/doc/quorum/unlock`, officer toggles |
| 8 | **Multi-user accounts** — register/login (PBKDF2-hashed passwords, bearer tokens); per-user session keys, seals and P2P inboxes | `server/src/auth.rs`, `/api/auth/*`, AuthBar |
| 9 | **Attack Lab (Mallory)** — tamper / swap-metadata / re-seal / truncate a captured container and watch Bob's side **cryptographically reject** it | `POST /api/doc/attack`, AttackLab panel |

All new parameters are optional with backwards-compatible defaults — existing
callers and the deployed dashboard keep working untouched.

**Deep-dive on every feature (math, code mapping, demo lines):
`docs/FEATURES_V2.md`.** What follows is the short version.

### 1 · Multi-hop relay nodes (quantum repeaters)

Real QKD dies with distance: fiber attenuation eats single photons, which is
why every deployed QKD network (SECOQC, Tokyo, Beijing–Shanghai) uses trusted
relay nodes. Set **Relay hops** (0–4) and Alice's qubits traverse
Alice → R1 → … → Bob one link at a time. Each relay measures in a random
basis (agreement probability 1/3 per link — a missed guess is line loss,
the qubit dies there) and re-prepares the measured state for the next link.
Each link applies its own environmental noise and can host its own Eve.

- Yield collapses to **(1/3)^(hops+1)** — 20k qubits → ~740 sifted bits at
  2 relays (vs ~6,650 direct). That collapse *is* the cost of trusted-node
  networks, made visible.
- Status cards render a **route strip**: one glowing dot per link (red when
  that link saw an interception), plus the node chain and key-survival %.
- Per-link `relay_stats` (in/out qubits, interceptions, QBER, from/to) come
  back on `/api/run` and render in the UI and TUI.

### 2 · Quantum noise & channel degradation filter

A detector that flags every elevated QBER as an attack is a broken detector —
real fiber flips bits on its own. **Fiber noise** (0–12%) models environmental
disturbance: a pure polarization flip in flight that **never changes the
state's basis** — the physical property that distinguishes it from
intercept-resend, where Eve's measurement collapses the state into her basis.

The detector's verdict is now three-way (`detection::ChannelClass`):

| Verdict | Condition | Consequence |
|---|---|---|
| `✓ secure` | QBER ≤ noise floor + ε(n) | keys distilled normally |
| `⚠ degradation warning` | above the noise line, below the 25% attack line | **environmental, not adversarial** — keys still distilled, event logged |
| `✗ under attack` | QBER > 25% (six-state intercept ceiling) | key distillation **aborted** |

The degraded band rides on the *configured noise floor*, so a clean run at
3% noise stays secure — the warning fires only when QBER exceeds what the
current noise can physically explain. A 1/3-ceiling QBER can only come from
basis collapse, and basis collapse can only come from a measurement.

### 3 · Secure document signing & sealing (`.qsig`)

The product layer: any file up to **5 MB** (PDF, image, contract) bound to the
QKD-derived session key. **Quantum Document Vault** in the dashboard: drop a
file, seal, download the portable `.qsig` container; verify re-checks
everything.

A `.qsig` (magic `QSIG1`, format v2) packs: file metadata + SHA-256, an
**HMAC-SHA256 tag over (metadata ‖ file bytes) under the QKD session key**,
a fresh per-seal nonce, the payload encrypted with **AES-256-GCM** (the
metadata is bound as GCM *associated data*, so a swapped document with an
intact body fails decryption), the payload serialized as base64 (a 5 MB file
stays a ~6.7 MB container instead of ballooning to ~20 MB of JSON digits), a
**key commitment** (SHA-256 of the canonical key — exposes wrong/compromised
keys without leaking them), and the **audit-ledger Merkle root at seal time**.

- Flip **one byte** anywhere — file or metadata — and verification fails
  instantly with a note naming the failed check.
- Verifying under a different session key fails the commitment:
  *"document sealed under a different session key (key possibly compromised)"*.
- Legacy v1 containers (XOR keystream payload) still verify for compatibility;
  new seals are always v2/GCM.

### 4 · Secure peer-to-peer transfer (real laptops + simulated route)

**Real laptop-to-laptop transfer** (`POST /api/doc/send`): the sender's server
seals the file and POSTs the encrypted container to the recipient's server
(`peer_url`) over HTTP, addressed by username (`to_user`); it lands in the
recipient's **inbox** (`/api/doc/inbox`) for one-click verification. Only the
AES-GCM ciphertext crosses the network — without the QKD session key the peer
sees nothing. Both accounts can also live on one server (local user-to-user
delivery) or span two laptops (`HOST=0.0.0.0` exposes the API on the LAN).

**Simulated transfer portal** (`POST /api/doc/transfer`): pick a file, set
hops + noise, **Send**. The portal runs seal → transmit over the relay route
(per-hop sifting, noise flips and Eve events streaming into a terminal-style
log with node labels) → unseal → verify on Bob's side, emitting an SSE
`transfer_log` event per stage. Every stage is also an entry in the Merkle
ledger — the demo proves the features compose.

**Attack Lab** (`POST /api/doc/attack`): Mallory captures a container and runs
tamper-bytes / swap-metadata / re-seal-under-her-key / truncate; forwarding the
forgery to Bob's verification always ends in **REJECTED** with the exact failed
check, and every attempt lands in the audit ledger as an `attack` event.

### 5 · Cryptographic Merkle-tree audit ledger (forensics)

The answer to *"how do you prove a signature wasn't forged three months
ago?"*. Every seal, verification, tamper flag, transfer, quorum unlock,
attack attempt, and QDS event is appended to a **hash-chained, append-only
ledger** (`audit` crate): each leaf hashes its own content *plus the previous
leaf* (v2 encoding: length-prefixed fields so field boundaries are
unambiguous), so retroactive editing cascades to the root. A **Merkle root**
commits to the whole history; **inclusion proofs** (sibling hashes + side
labels) let anyone verify one entry against the root without the full log —
and `.qsig` containers pin the root they were sealed under. `verify_chain`
re-derives the whole structure and names the exact entry where tampering
occurred. **The ledger persists as JSONL and reloads on startup**, so the
chain (and its non-repudiation story) survives process restarts. The
dashboard ledger panel has a per-row **proof** button that renders and
re-verifies the inclusion proof live.

### 6 · Interactive TUI dashboard

```bash
cargo run -p tui
```

A ratatui terminal dashboard running the *same* engine as the web UI —
live QBER sparkline (240-sample rolling window), progress gauge, 3-way
verdict, relay route with per-hop stats, document vault (seal / verify /
tamper / quorum demos), Merkle audit tail with chain-intact status, and a
pipeline log. Keys: `1/2/3` scenario · `n/N` noise ±1% · `r/R` relay hops ·
`s/v/t/w` vault demos · `Q` quit. Works in Windows Terminal, PowerShell and
POSIX terminals; runs over SSH with zero browser dependency.

### 7 · Multi-party threshold authorization (k-of-m signatures)

Enterprise-grade quorum authorization over the seal key: **Shamir secret
sharing** (byte-wise, GF(251), one random degree-(k−1) polynomial per key
byte). Each of m officers holds one share plus a public commitment; any k
shares reconstruct via Lagrange interpolation, and any k−1 leak **zero
information** (one point short of the polynomial — information-theoretic,
not policy).

- Enable **Shamir quorum seal** (k-of-m) in the Vault, seal, then toggle
  officers: fewer than k → *"unlock rejected — only N valid shares"*;
  k of them → *"unlocked via quorum k-of-m"*, recorded in the ledger.
- Officer commitments let the server validate presented shares without
  holding them.
- Documented subtlety: byte 31 of the key is masked into GF(251)
  (< 2 bits of entropy lost) so field arithmetic is exact.

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
│                 3-way classification: secure / degraded / under attack
├── attacks/    Intercept-resend eavesdropping scenario wrappers (QKD layer)
├── audit/      Merkle-tree append-only audit ledger: hash-chained entries,
│                 Merkle root, inclusion proofs, chain re-verification
├── sealing/    .qsig document containers: SHA-256 + QKD-key HMAC binding,
│                 masked payload, Shamir k-of-m secret sharing (GF(251))
├── crypto/     HMAC-SHA256 message authentication over the derived key
├── main_app/   CLI demo binary (QKD pipeline)
├── server/     Axum REST + SSE API: /api/run, /api/simulate, /api/events,
│               /api/qds/{setup,sign,verify,attacks,forgery-analysis,events},
│               /api/auth/{register,login,logout,me,users} (multi-user accounts),
│               /api/doc/{seal,verify,quorum,quorum/unlock,transfer,send,
│               receive,inbox,attack,session}, /api/audit/*
│               + persistent JSONL logs (qds_events.jsonl, audit_log.jsonl,
│               users.json) — audit chain reloads on startup
├── tui/        ratatui terminal dashboard: live QBER sparkline, relay route,
│               document vault, Merkle audit tail (`cargo run -p tui`)
├── frontend/   React + TypeScript + Recharts dashboard (Vite): live QKD
│               monitor + QDS Signature Lab + Doc Vault + Transfer Portal
├── tests/      Workspace integration tests (QKD pipeline)
├── docs/       FEATURES_V2.md (the seven v2 features in depth)
│               PROJECT_GUIDE.md (full theory + walkthrough)
│               QDS_MATH_MODEL.md (formal model)
│               JUDGING_BOOK.md (consolidated judging-round reference)
│               JUDGE_PITCH.md (presentation playbook)
│               DASHBOARD_RUN_GUIDE.md (how to run the dashboard)
│               DASHBOARD_GUIDE.md (every dashboard element explained)
│               VIDEO_SCRIPT.md (3-minute demo video script)
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
| `/api/auth/register` | POST | Create an account (username, password ≥ 6 chars; PBKDF2-hashed at rest) |
| `/api/auth/login` | POST | Verify credentials, get a bearer token (memory-only session table) |
| `/api/auth/logout` | POST | Drop the presented token |
| `/api/auth/me` | GET | Who am I (requires token) |
| `/api/auth/users` | GET | Registered usernames (the send-panel address book) |
| `/api/doc/session` | GET | Current user's key state: has_key, key commitment, quorum info |
| `/api/doc/seal` | POST | Seal an uploaded file (base64 `content_b64`, ≤ 5 MB) into a `.qsig` container; optional `use_quorum` + k-of-m params |
| `/api/doc/verify` | POST | Verify a `.qsig` container (`container_b64`) against the user's session keys (single flipped byte ⇒ instant failure) |
| `/api/doc/quorum` | GET | Officer share view for the quorum-unlock demo |
| `/api/doc/quorum/unlock` | POST | Present k officer shares to reconstruct the key and unlock the container |
| `/api/doc/transfer` | POST | Simulated P2P transfer over the relay route; emits per-stage SSE `transfer_log` events |
| `/api/doc/send` | POST | **Real** transfer: seal + deliver to `to_user` (local inbox) or `peer_url` (remote laptop `/api/doc/receive`) |
| `/api/doc/receive` | POST | Peer-side intake: files an inbound container into the addressed user's inbox |
| `/api/doc/inbox` | GET | List the logged-in user's inbox (`?full=false` for metadata only) |
| `/api/doc/inbox/verify` | POST | Verify one inbox item — a tampered or substituted container fails here with the exact reason |
| `/api/doc/attack` | POST | Mallory's tamper/swap_meta/reseal/truncate modes (demonstrates cryptographic rejection) |
| `/api/doc/events` | GET | SSE: live transfer-log + attack events |
| `/api/audit/events` | GET | Audit ledger entries + current Merkle root |
| `/api/audit/proof?seq=N` | GET | Merkle inclusion proof for entry N |
| `/api/audit/verify` | GET | Re-derive the whole chain; names the entry where tampering occurred |

```bash
# Local server example (replace with your Render URL for the deployed backend):
curl -X POST localhost:8080/api/run \
  -H 'Content-Type: application/json' \
  -d '{"key_length": 3000, "seed": 42, "pace_ms": 0}'
```

### Three-laptop demo (accounts + P2P + rejected attack)

The video scenario, runnable on one machine (three processes) or three real
laptops — see `.freebuff/run.md` for launchers and a scripted end-to-end:

1. **Laptop A — Alice:** register `alice`, run a QKD exchange (distills her
   session key), seal a document in the Vault.
2. **Laptop B — Bob:** register `bob`, run the QKD exchange with the **same
   seed** (identical distilled key), leave the dashboard open.
3. **Laptop A → B:** Peer-to-Peer panel → recipient `bob` + Bob's
   `http://<bob-lan-ip>:8080` → **Send to laptop**. The encrypted container
   lands in Bob's inbox; he clicks **verify** → ✓ accepted.
4. **Laptop C — Mallory:** register `mallory`, open the **Attack Lab**, load
   the captured `.qsig`, pick an attack mode, **forward to Bob** → every mode
   is **REJECTED** with the exact failed check (GCM tag, commitment, hash).
5. All of it — seals, deliveries, rejections, attacks — is on the Merkle
   audit ledgers of the respective machines, each verifiable with
   `/api/audit/verify`.

> Shared-seed keys are a demo convention (both laptops run the same scripted
> simulation); a production deployment would transport one-time pads over the
> QKD channel itself.

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
- **Channel degradation (feature 2)** — with fiber noise n% (no attack), QBER
  settles near n%: if it stays below noise-floor + ε(n) the verdict is
  *secure*; between that line and the attack line (25%) the dashboard shows a
  **Channel Degradation Warning** instead of a breach.
- **Relay routes (feature 1)** — with k relays each link sifts independently
  (~1/3 survival per link), so the sifted fraction ≈ (1/3)^(k+1); per-link
  stats and interception events render in the route view.

## TUI dashboard (feature 6)

```bash
cargo run -p tui
```

Live QBER sparkline, progress gauge, relay route with per-hop stats, document
vault (seal / verify / tamper / quorum), Merkle audit tail, and a pipeline log.
Keys: `1/2/3` scenario · `n/N` noise ±1% · `r/R` relay hops · `s/v/t/w` vault
actions · `Q` quit. Works on Windows Terminal, PowerShell, and POSIX terminals.

## Tests

```bash
cargo test --workspace
```

Covers the end-to-end secure pipeline, attack detection, input validation, the
partial-intercept ratio semantics (0.0 ≡ secure, 1.0 ≡ full attack, 0.3 ⇒
intermediate QBER), relay-route sifting factors and per-link interception
accounting, the 3-way noise/attack classifier, .qsig seal→verify round-trips
(single-byte tamper detection, wrong-key commitment rejection), Shamir
k-of-m split/reconstruct (k−1 shares fail), Merkle inclusion proofs and chain
re-verification, the six-state QDS scheme (honest acceptance, forgery /
impersonation / tampering / unauthorized-verifier rejection, click-rate ≈
1/6), noisy-channel thresholds, and the performance evaluation (accuracy >
0.99, deterministic reproduction, per-class detection).

> Educational prototype — the privacy-amplification step is simplified
> (fixed SHA-256 rather than a universal₂ hash sized to estimated entropy and
> leakage), and there is no error-correction/reconciliation stage.
