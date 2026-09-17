# FEATURES_V2 — The Scenario Features, In Depth

**What this documents:** the scenario features of the current build
(September 2026), each with the *why*, the *math*, the *exact code
mapping*, the *API surface*, and *what to say in a demo*. Features 1–7
are the v2 build; features 8–9 — **multi-user accounts with real
laptop-to-laptop P2P, the Attack Lab, and cross-account multiparty
unlock** — came in the v3 build.

**Companion docs:** `README.md` (overview + quickstart),
`PROJECT_GUIDE.md` (base theory + original two layers),
`DASHBOARD_GUIDE.md` (every UI element), `DEPLOYMENT_GUIDE.md` (Render /
Vercel + the 3-account demo), `JUDGING_BOOK.md` (demo script),
`QDS_MATH_MODEL.md` (formal QDS model).

**Verified state of this build:** `cargo test --workspace` → **66
passed, 0 failed**; frontend `tsc -b && vite build` clean; the scripted
three-laptop E2E (`scripts/e2e-test.mjs`, 9 acts), the multiparty
E2E (`scripts/e2e-multiparty.mjs`, 7 acts) and the v3 E2E
(`scripts/e2e-v3.mjs`, 40 checks) pass against the release
binary.

---

## Table of contents

- [Dependency order (why we built them in this sequence)](#dependency-order)
- [Feature 1 — Multi-hop relay nodes (quantum repeaters)](#feature-1)
- [Feature 2 — Quantum noise & channel degradation filter](#feature-2)
- [Feature 3 — Secure document sealing (.qsig)](#feature-3)
- [Feature 4 — Secure peer-to-peer transfer portal](#feature-4)
- [Feature 5 — Merkle-tree audit ledger (forensics)](#feature-5)
- [Feature 6 — Interactive TUI dashboard](#feature-6)
- [Feature 7 — Multi-party threshold authorization (k-of-m)](#feature-7)
- [Feature 8 — Multi-user accounts & laptop-to-laptop P2P](#feature-8)
- [Feature 9 — Attack Lab (Mallory vs the seal)](#feature-9)
- [API reference for the new endpoints](#api-reference)
- [One-paragraph-per-feature demo crib](#demo-crib)

---

## Dependency order

The features were implemented in this order, and the order is *load-bearing*:

```
2 (noise) ──► 1 (relays) ──► 5 (Merkle audit) ──► 3 (sealing)
                                                      │
                                    7 (Shamir quorum) ◄┘
                                          │
                              4 (transfer portal)
                                          │
                              6 (TUI visualizes everything)
```

- **Noise before relays:** every relay link adds its own environmental
  degradation, so the per-link noise model must exist first.
- **Audit before sealing:** `.qsig` containers pin the audit ledger's
  Merkle root at seal time (`audit_ref`), and every seal/verify/transfer
  event is appended to it — the ledger must exist to be pinned.
- **Quorum before transfer:** the transfer portal exercises the full
  pipeline (seal → route → unseal → verify), including quorum-sealed
  documents.
- **TUI last:** it visualizes all of the above.

---

<a name="feature-1"></a>
## Feature 1 — Multi-hop relay nodes (quantum repeaters)

### Why it matters

Real QKD is distance-limited: fiber attenuation destroys single photons
long before continental distances. The practical architecture is
**trusted relay nodes** — segment the channel into short links and have
each relay measure-and-forward. (True *quantum* repeaters need quantum
memory and entanglement swapping; every deployed "QKD network" — SECOQC
Vienna, Tokyo QKD network, the 2,000-km Beijing–Shanghai backbone — uses
trusted relays, which is exactly what we simulate.)

### The model (`quantum/src/relay.rs`)

A `RelayRoute { hop_count, noise_rate, intercept_ratio }` defines
`hop_count + 1` links: Alice → R1 → … → Rn → Bob. Each qubit traverses
links **one at a time**, and — this is the part that makes the physics
honest — **a qubit that dies at link *L* never reaches link *L+1***:

1. **Environmental noise per link** — with probability `noise_rate` the
   state's polarization flips in flight (pure bit flip, basis untouched —
   see Feature 2).
2. **Per-link Eve** — with probability `intercept_ratio` the link is
   intercepted. Eve picks a random basis: with probability 1/3 it matches
   the sender's basis and the state passes undisturbed; otherwise the
   state collapses and she resends a random eigenstate. Net flip
   probability per intercepted qubit: `2/3 × 1/2 = 1/3` — the six-state
   intercept-resend signature, reproduced per link.
3. **Relay measure-and-forward** — the receiving node measures in a
   random basis. Basis agreement has probability 1/3 per link (three
   Pauli bases); a disagreement is treated as **line loss** — the relay
   has no correlated record to forward, so the qubit dies there.
4. **Terminal link** — Bob records the sifted bit and compares against
   Alice's reference (only Bob holds one, so per-link QBER is reported
   only for the terminal link; relays report traffic and interceptions).

### The numbers to know

| Quantity | Value | Derivation |
|---|---|---|
| Sifted fraction per link | **1/3** | 3 Pauli bases, receiver guesses Alice's basis |
| End-to-end sifted fraction, k relays | **(1/3)^(k+1)** | independent links multiply |
| QBER from full interception on every link | → **1/3** | same six-state signature, accumulated |
| 20,000 qubits, 2 relays | ~740 sifted bits | 20,000 × 1/27 |

### Where it surfaces

- **API** — `relay_hops` (0–4) on `POST /api/run` and `POST /api/simulate`;
  responses carry `relay_hops` and `relay_stats[]` (`HopStats`: per-link
  in/out qubits, interceptions, QBER, from/to labels).
- **Dashboard** — "Relay hops" slider (0–4) in Experiment Parameters; each
  status card draws a **route strip** (glowing hop dots, red when that link
  saw an interception) plus the node chain `Alice → Relay 1 → … → Bob` and
  a key-survival percentage.
- **Transfer portal** — its own hops slider runs the sealed-file transfer
  over the same route model with a live topology view.
- **TUI** — `r`/`R` adjusts hops; the relay pane renders the node chain
  with per-link stats.
- **Tests** — `quantum/src/relay.rs` `#[cfg(test)]`: sifting factor ≈
  (1/3)^links, per-link interception accounting (only qubits that *arrive*
  at a link can be intercepted there), deterministic-seed reproducibility.

**Demo line:** *"Each relay re-sifts locally, so yield falls as one-third
per link — one-third cubed with two relays. That's the real cost of
trusted-node QKD networks, and you're watching it live."*

---

<a name="feature-2"></a>
## Feature 2 — Quantum noise & channel degradation filter

### Why it matters

A detector that screams "ATTACK!" at any elevated QBER is a broken detector
— real fiber flips bits all by itself. The interesting engineering problem
is telling **malicious disturbance** (intercept-resend, basis collapse)
apart from **environmental disturbance** (thermal noise, turbulence,
impurities). They are physically different processes:

| | Environmental noise | Intercept-resend Eve |
|---|---|---|
| Mechanism | photon lost/impurity → polarization flip in flight | Eve *measures* in a random basis → state collapses |
| Changes basis? | **No** — pure bit flip | **Yes** — collapses to Eve's basis |
| QBER signature | ≈ `noise_rate` | ≈ `intercept_ratio / 3` |
| Bounded by statistics? | deterministic-ish floor | 1/3 ceiling at full interception |

### The model

- **`quantum/src/lib.rs` — `ChannelSession::with_noise(p)`**: with
  probability `p` the qubit's state flips (Positive ↔ Negative) in flight.
  Crucially the *basis is untouched* — nature disturbs, Eve measures.
  Noise applies **independently of and in addition to** `intercept_ratio`.
- **`detection/src/lib.rs` — `ThreatDetector::evaluate_channel(qber, n,
  noise_floor, measured_noise)`** — the 3-way classifier:

```
secure_line  = noise_floor + ε(n)         ε(n) = √(ln(2/δ)/2n)
attack_line  = 0.25                        (six-state intercept ceiling)

QBER ≤ secure_line            → ChannelClass::Secure
secure_line < QBER ≤ 0.25     → ChannelClass::Degraded   ("Channel Degradation Warning")
QBER > 0.25                   → ChannelClass::UnderAttack (abort key distillation)
```

The **degraded band rides on the noise floor, not the legacy base
threshold** — so a clean run at 3% noise classifies *secure* (3% ≤
3% + ε), not warning. The warning fires only when QBER exceeds what the
configured noise can explain. `is_authentic` keeps its legacy meaning
(QBER ≤ base + ε) so the original pipeline is unchanged.

### What "Channel Degradation Warning" means operationally

Environmental, not adversarial: **keys are still distilled** (the channel
is usable) but the dashboard flags caution, and the event is recorded in
the audit ledger as a `flag` entry. Only `UnderAttack` aborts
distillation — matching the physics: a 1/3-ceiling QBER can only come
from basis collapse, and basis collapse can only come from a measurement.

### Where it surfaces

- **API** — `noise_rate` (0–0.12) on `/api/run`, `/api/simulate`; every
  scenario result now carries `channel_class` (`secure | degraded |
  under_attack`), `noise_rate`, and the familiar `is_authentic`.
- **Dashboard** — "Fiber noise" slider (chip: *degradation filter*);
  status cards show a 3-way verdict chip (`✓ secure` / `⚠ degradation
  warning` / `✗ under attack`), amber top-bar + warning band on degraded,
  and the degraded warning explains itself: *"QBER above the noise floor
  but below the attack line — environmental, not adversarial."*
- **TUI** — `n`/`N` adjusts noise ±1%; verdict line shows SECURE /
  DEGRADED / UNDER ATTACK.
- **Tests** — `detection` crate: noise-only runs classify Secure;
  noise above tolerance classifies Degraded; attacks still classify
  UnderAttack; secure-line vs attack-line boundaries.

**Demo line:** *"I've turned fiber noise to 8% with no attacker. The QBER
climbs — but the verdict is a degradation *warning*, not a breach. Now I
launch an intercept-resend attack: QBER converges to one-third and the
verdict flips to UNDER ATTACK, aborting the key. The detector didn't
just threshold — it distinguished two different physical processes."*

---

<a name="feature-3"></a>
## Feature 3 — Secure document sealing (.qsig)

### Why it matters

QKD and QDS prove the *plumbing* works. Sealing turns the distilled
session key into a **product**: any file — PDF, image, contract — bound
cryptographically to the quantum-derived key, such that tampering with a
single byte is detectable and key compromise is provable.

### The container (`sealing/src/lib.rs`)

**v3 opaque envelope — what a sealed file actually looks like on disk.** The
whole container below is itself serialized to JSON and sealed under
AES-256-GCM with the session key. The `.qsig` file on disk is:

```
QSIG3 3 <nonce> <key_commitment>\n<AES-256-GCM ciphertext — binary noise>
```

Open it in any editor: no file name, no hash, no readable metadata, no
plaintext — the "locked document" is literal. The one-line header exposes
only the format version, the GCM nonce and the key commitment (which proves
*which* key family sealed it without revealing the key). `parse_container`
returns the envelope as a placeholder with `sealed_envelope: true`; every
consumer (verify, open, inbox meta, relay claim, wire-proof, quorum unlock)
unseals with the workspace's candidate keys first — `unseal_envelope`
fails closed with a precise commitment-mismatch reason on a wrong key.
Legacy v1/v2 clear-JSON containers (below) still verify for compatibility.

The JSON **inside** the envelope (`QSIG1\n` + JSON, as in v2):

```jsonc
{
  "magic": "QSIG1",
  "meta":    { "name", "size", "mime", "sha256", "sealed_at" },
  "audit_ref": { "first_seq", "last_seq", "root" },   // Merkle ledger coverage at seal time
  "scheme":  "aes-256-gcm+sha256-hmac/qkd",
  "v":       2,                            // 1 = legacy XOR payload (still verifies)
  "key_commitment": "<sha256(canonical key)>",  // binds container ⇄ key, leaks nothing
  "nonce":   812394...,                    // fresh per seal → GCM IV / legacy keystream
  "tag":     "<hex hmac>",                 // HMAC-SHA256 over (meta ‖ 0x00 ‖ file)
  "quorum":  { "threshold", "shares", "officer_commitments" },  // Feature 7
  "ciphertext": "<base64>"                 // AES-256-GCM(meta as AAD); b64 keeps a 5 MB
                                           // file a ~6.7 MB container, not ~20 MB of digits
}
```

Security properties, each mapped to a mechanism:

| Property | Mechanism |
|---|---|
| Tamper-evidence (1 byte) | AES-256-GCM authenticated decryption (v2) + HMAC-SHA256 over `(serialized meta ‖ 0x00 ‖ file_bytes)` — metadata is bound *both* as GCM associated data and inside the tag, so swapping documents with intact bodies fails before the HMAC is even reached |
| Key-compromise evidence | `key_commitment = SHA-256(canonical key)` — verify with the wrong session key → `key_match: false` → *"document sealed under a different session key (key possibly compromised)"* |
| Confidentiality | **AES-256-GCM** under the canonical session key (v2 payload, v3 envelope); the legacy XOR keystream remains only for verifying v1 containers |
| Size honesty | ciphertext serialized as base64: a 5 MB file seals to a ~6.7 MB container (unit-tested to stay under 1.5×) |
| Forensic anchoring | `audit_ref` pins the ledger's `first_seq / last_seq / root` at seal time — the ledger root *proves what the log looked like when the document was sealed* |
| Replay-fresh sealing | fresh 64-bit nonce per seal → identical file sealed twice yields different containers |

Verification (`verify_document`) recomputes the HMAC and returns a
four-flag `VerificationOutcome`: `format_ok`, `key_match`, `authentic`,
`integrity` — with a precise `note` naming *which* check failed
(format / key commitment / HMAC tag / payload hash). One flipped byte
anywhere fails instantly.

**Honest scope note** (say it before a judge does): the legacy v1
payload used a demo-grade XOR keystream; since the v3 build every new
seal is **AES-256-GCM** — real authenticated encryption. The current
build additionally seals the container itself (the **opaque envelope**
above), so the metadata is hidden too. The docs keep the v1 path only
for verifying old containers.

### Where it surfaces

- **API** — `POST /api/doc/seal` (base64 file + optional quorum spec),
  `POST /api/doc/verify` (base64 container + which key to verify under).
  Responses carry the outcome flags, metadata, and the audit seq.
- **Dashboard — Quantum Document Vault** — drop a file, see its size +
  SHA-256, seal (download the `.qsig`), verify against the session key,
  and watch the seal/verify events land in the Merkle ledger below.
- **TUI** — `s` seal / `v` verify / `t` tamper-and-catch on a demo
  document.
- **Tests** — `sealing` crate (9 tests): round-trip seal→parse→verify,
  single-byte tamper detection (both payload and metadata), wrong-key
  rejection via commitment, container-magic corruption, quorum-split and
  reconstruction, k−1 shares *fail* to reconstruct.

**Demo line:** *"I seal this PDF: its hash, the audit root at seal time,
and an HMAC under the QKD session key all go into one portable container.
Watch — I flip one byte of the file, re-verify: HMAC mismatch, instantly.
And if you seal under a compromised key, the key commitment exposes it."*

---

<a name="feature-4"></a>
## Feature 4 — Secure peer-to-peer transfer portal

### Why it matters

The judge-pleasing scene: data *moving* through quantum machinery. The
portal runs the entire pipeline end-to-end on one file and narrates every
stage as it happens.

### The pipeline (`POST /api/doc/transfer`, SSE)

```
A: hash file ──► derive key (QKD session) ──► seal .qsig
                    │
                    ▼  transmit over RelayRoute (hops slider, noise slider)
   per-hop sifting, noise flips, per-link Eve events  ── live log lines
                    │
                    ▼
B: unseal (reconstruct key if quorum) ──► verify HMAC + hash ──► verdict
```

Every stage emits an SSE `transfer_log` event (`stage`, `node`, `level`,
`detail`) that the dashboard renders in a terminal-style log with node
labels and stage icons; the topology strip (Alice → relays → Bob) blinks
live as qubits move. Per-hop stats render as chips after the transfer.

The transfer **reuses** the same crates — relay route, sealing, audit —
so the demo proves composition: the same primitives from features 1/3/5
assembled into a working flow.

### Where it surfaces

- **API** — `POST /api/doc/transfer` → SSE stream + final
  `TransferResponse` (hops, key_derived, seal_ok, delivered, verdict,
  per-hop stats, audit seq, one-line summary).
- **Dashboard — P2P Transfer Portal** — file drop, hops + noise sliders,
  quorum toggle, live log, topology strip, hop-stat chips, verdict box.
- **Audit** — the whole transfer lands as `seal` + `transfer` + `verify`
  entries in the Merkle ledger.

**Demo line:** *"Alice seals the file, transmits it over a two-relay
route — watch each hop sift and forward — and Bob unseals and verifies on
arrival. Every stage you see in the log is also an entry in the Merkle
audit ledger."*

---

<a name="feature-5"></a>
## Feature 5 — Merkle-tree audit ledger (forensics)

### Why it matters

The judge question this answers: *"How do we prove to an auditor that a
signature wasn't forged three months ago?"* An append-only log that
anyone could edit is worthless; the ledger is **hash-chained** (each leaf
commits to the previous leaf) and **Merkle-rooted** (one hash commits to
the entire history), so any retroactive edit breaks the chain and any
individual entry can be proven present with an inclusion proof.

### The structure (`audit/src/lib.rs`)

- **Leaf hash** — `SHA-256(seq ‖ ts ‖ kind ‖ label ‖ accepted ‖ detail ‖
  payload_hash ‖ previous_leaf)`. The chain link is *inside* each leaf
  hash: rewriting entry *k* changes its leaf, which breaks leaf *k+1*'s
  hash input, cascading to the root.
- **Merkle root** — binary tree over leaf hashes; odd trailing nodes are
  promoted Bitcoin-style (`H(a‖a)`).
- **Inclusion proof** — the sibling hashes bottom-up with side labels
  (`L:`/`R:`); `verify_inclusion` recomputes the root from the leaf +
  siblings and compares. Anyone with just the root (e.g. pinned inside a
  `.qsig`'s `audit_ref`) can verify one entry without the whole log.
- **`verify_chain`** — full re-derivation from entry 1: returns
  `ChainVerdict { ok, broken_at, root, detail }` naming the exact seq
  where tampering occurred.
- **Events recorded** — `seal`, `verify`, `flag` (threat/tamper),
  `transfer`, `quorum`, plus system events. Each carries the payload hash
  of the artifact it concerns (e.g. the document's SHA-256), binding the
  log to the artifacts.

### Where it surfaces

- **API** — `GET /api/audit` (entries + root + chain verdict) and
  `GET /api/audit/proof?seq=N` (inclusion proof).
- **Dashboard — Merkle Audit Ledger** (inside the Doc Vault panel) —
  live table: seq / kind / accepted glyph / detail / truncated leaf hash,
  a `chain ✓` badge, the root as a hover tooltip, and a **proof** button
  per row that renders the sibling hashes and re-verification inline.
- **TUI** — audit pane with root + `chain ✓ intact` in the title, tail of
  entries, ✓/✗ glyphs.
- **Tests** — `audit` crate (5 tests): append + root stability,
  inclusion proof verifies, tampered detail breaks the proof, tampered
  entry breaks the chain at the right seq, chain verdict on intact log.

**Demo line:** *"Every seal, verify, tamper flag, and transfer is
hash-chained into a Merkle tree. Here's the inclusion proof for entry 6 —
recompute the root from these siblings, match. If I edited history, the
chain verdict names the exact entry where it broke."*

---

<a name="feature-6"></a>
## Feature 6 — Interactive TUI dashboard

### Why it matters

A terminal dashboard is the perfect second screen: it shows the *same
engine* driving a completely different front-end (proof the architecture
is genuinely layered), it runs over SSH on a projector with zero browser
dependency, and it looks phenomenal next to the web UI.

### The implementation (`tui/` crate, ratatui + crossterm)

Run: `cargo run -p tui`. Five panes:

```
┌────────────────────────┬──────────────────────────────┐
│ scenario · noise · hops│  progress gauge               │
│ qber / threshold       │  QBER sparkline (per-mille,   │
│ sifted / processed     │  240-sample rolling window)   │
│ verdict + vault status │                               │
├────────────────────────┴──────────────────────────────┤
│ relay route — ●Alice ── R1 ── R2 ── ●Bob  (+per-link) │
├───────────────────────────────────────────────────────┤
│ document vault — seal / verify / tamper / quorum      │
├───────────────────────────────────────────────────────┤
│ merkle audit ledger — root…, chain ✓ intact           │
├───────────────────────────────────────────────────────┤
│ pipeline log                                          │
└───────────────────────────────────────────────────────┘
```

Keys: `1/2/3` scenario (secure / attack / mixed 30%) · `Tab` cycle ·
`n`/`N` noise ±1% · `r`/`R` relay hops · `s` seal · `v` verify ·
`t` tamper · `w` quorum demo · `Q`/`Esc` quit.

Engineering details worth citing: the engine reuses the *same* crates
(`quantum::ChannelSession`, `quantum::relay`, `detection::ThreatDetector`,
`sealing`, `audit`) — the TUI is a thin rendering layer, not a second
implementation. Per-tick batches of 400 qubits stream through the session;
the relay path merges per-batch `HopStats` into running totals. Key events
filter on `KeyEventKind::Press` (Windows sends press *and* release —
without the filter every keystroke fires twice). Terminal state is
faithfully restored on exit (raw mode off, alternate screen left, cursor
back) even after a panic-free `?` error path.

**Demo line:** *"Same engine, second front-end — this is the terminal
dashboard. I'll intercept the channel live (press 2), watch the sparkline
jump to one-third and the verdict flip to UNDER ATTACK, then seal, tamper
and catch a document modification, all logged to the Merkle ledger."*

---

<a name="feature-7"></a>
## Feature 7 — Multi-party threshold authorization (k-of-m)

### Why it matters

A single key is a single point of failure — and a single point of
coercion. Enterprise workflows (government, defense, board approvals)
need **quorum authorization**: no one officer can unseal a sensitive
document alone. This is Shamir secret sharing, applied to the
QKD-derived seal key.

### The math (byte-wise Shamir over GF(251))

`split_secret(secret_hex, k, m)` treats the 32-byte key as 32 independent
values in GF(251). For **each key byte** one random polynomial of degree
k−1 is drawn *once*:

```
f_b(x) = key_b + c₁x + c₂x² + … + c_{k−1}x^{k−1}   (mod 251)
```

Officer *i* receives share `x=i, y_b = f_b(i)` for all 32 bytes — plus a
`commitment = SHA-256(x ‖ y)` so the server can validate a presented
share without storing it. Reconstruction is Lagrange interpolation at 0:

```
key_b = Σ_i  y_b(i) · Π_{j≠i}  x_j / (x_j − x_i)   (mod 251)
```

with modular inverses via Fermat little theorem (`a^(p−2) mod p`).

Two subtle correctness points (both unit-tested):

1. **One polynomial per key byte, not per share.** The original bug —
   redrawing coefficients per share — produces shares that don't
   interpolate. The fix draws the coefficient matrix once and evaluates
   it at each x.
2. **Byte 31 is masked into GF(251)** (`key[31] %= 251`, losing < 2 bits
   of entropy) so field arithmetic is exact for every byte — documented
   in code, flagged in the limitations list.

Security property: any k−1 shares leak **zero information** about the
key (Shamir's theorem — k−1 points on a degree k−1 polynomial are
exactly one point short), so the threshold is information-theoretic, not
a policy.

### Where it surfaces

- **API** — `POST /api/doc/quorum` (split into m shares, threshold k;
  returns officer commitments only), `POST /api/doc/unlock` (present
  shares → server validates commitments → reconstructs → verifies the
  container → **`unlocked_via: "quorum k-of-m"`** in the outcome).
  Seals created with a quorum spec record it in the container's
  `quorum` field with per-officer commitments.
- **Dashboard — Doc Vault** — "Shamir quorum seal" toggle with k/m
  selects; after sealing, the verify column renders **officer toggle
  pills** — flip fewer than k and unlock is rejected with the count of
  valid shares; flip k and the document unlocks, named as quorum-unlocked.
- **TUI** — `w` runs the quorum demo: split k-of-5, reconstruct from k
  shares, *prove* k−1 fails.
- **Tests** — split/reconstruct round-trip, k−1 rejection, commitment
  validation, threshold boundary validation (2 ≤ k ≤ m ≤ 15).

**Demo line:** *"This contract is sealed 3-of-5. One officer — even
coerced — cannot open it: two shares are mathematically one point short.
Watch me present two: rejected. Three: unlocked, and the outcome says
'unlocked via quorum 3-of-5' — that's in the audit ledger too."*

---

<a name="feature-8"></a>
## Feature 8 — Multi-user accounts & laptop-to-laptop P2P

### Why it matters

The v2 vault was a single shared workspace — a great demo of *crypto*, but
not a demo of a *system*. Real deployments have many users on one website
exchanging documents between machines, with an attacker trying to poison
the channel. The v3 build adds:

1. **Accounts** (`server/src/auth.rs`) — register / login / logout /
   `me` / address-book. Passwords are stored as PBKDF2-HMAC-SHA256
   digests (600,000 rounds, 16-byte random salts — OWASP-calibrated);
   sessions are random 256-bit bearer tokens held **in memory only**
   (never persisted). Failed logins trigger a per-username 2 s backoff.
   Accounts live in `users.json` (path overridable via `USERS_FILE`) and
   survive restarts.
2. **Per-user workspaces** — session keys, seals, quorum splits, and the
   P2P inbox are scoped to the logged-in user (`Arc<AppState> →
   DocStateHolder.workspaces`); anonymous calls share a `shared`
   workspace so the classic demo still works. The QKD run handler
   (`/api/run`) routes the distilled secret to the *calling* user's
   workspace, and API responses never contain the raw key — only its
   commitment.
3. **Real P2P transfer** — `POST /api/doc/send` delivers a sealed
   container **addressed by username** (`to_user`) either into another
   account's inbox on the same server, or over HTTP to another machine's
   `/api/doc/receive` (`peer_url`; the server binds `HOST=0.0.0.0` for
   LAN reachability). Only the AES-GCM ciphertext crosses the wire. The
   recipient's **Inbox** panel lists inbound items with one-click verify;
   verification checks the container against *their* session keys.

### The key-sharing convention (be honest about it)

Two laptops end up with the same session key because **both derived it
with the same six-state QDS seed** (the seeded generation is
deterministic). The dashboards show this: seed 424242 on both machines →
both distill the identical 256-bit key → each can verify the other's
seals. A production system would transport a one-time pad over the
quantum channel itself; the convention here keeps the demo
two-laptop-friendly. Cross-server QDS signature verification additionally
requires every server to share `TRENT_SEED` (same notary tables).

### Where it surfaces

- **API** — `/api/auth/*`, `GET /api/doc/session` (has_key, commitment,
  quorum state), `POST /api/doc/send` / `receive`, `GET /api/doc/inbox`,
  `GET /api/doc/outbox` (sent items, kept separate from received),
  `POST /api/doc/inbox/verify`, `DELETE /api/doc/inbox/{id}`,
  `POST /api/doc/open` (unlock & download the original file),
  `GET /api/doc/wire-proof` (what crossed the network: ciphertext sample,
  entropy, hashes), `POST /api/doc/relay/deposit` + `claim` +
  `GET /api/doc/relay/inbox` (cross-LAN transfer via claim codes).
- **Dashboard** — **AuthBar** in the header (register / login / logout,
  `👤 alice` chip when logged in); the **Peer-to-Peer Transfer** panel's
  two send modes (user vs laptop); the **Inbox** list with verify /
  dismiss per row.
- **Tests** — `server/src/auth.rs` (PBKDF2 known vector, register /
  login / reload round-trip, duplicate + short-password rejection);
  scripted E2E `scripts/e2e-v3.mjs` (three accounts, cross-laptop QDS
  handshake, delivery, unlock/download, outbox separation, wire proof,
  relay claim-code round-trip, attack theater rejection) and
  `scripts/e2e-test.mjs` acts 1–3 & 7.

**Demo line:** *"Two laptops, two accounts, one website. Alice seals on
her machine, sends to bob's account over the network — only ciphertext
travels — and bob's inbox verifies it against the key both machines
distilled from the same quantum channel. Nobody sees anybody else's
keys."*

---

<a name="feature-9"></a>
## Feature 9 — Attack Lab (Mallory vs the seal)

### Why it matters

The claim "tampering is detected" deserves an on-camera adversary.
The Attack Lab is that adversary: Mallory captures a `.qsig` container
(public ciphertext) and mangles it with one of four attacks, then
forwards the forgery to the victim — whose verification **rejects it**
with the exact failed check. Every attempt is appended to the Merkle
ledger as an `attack` event.

### The four attack modes (`POST /api/doc/attack`)

| Mode | What Mallory does | Why it fails |
|---|---|---|
| `tamper_bytes` | flips 8 random ciphertext bytes | AES-GCM authentication tag no longer matches |
| `swap_meta` | renames the document inside the container | metadata is GCM associated data — decryption fails before the HMAC check |
| `reseal` | replaces commitment + tag with her own key's | key commitment mismatch — *"sealed under a different session key"* |
| `truncate` | halves the payload, edits `meta.size` | GCM tag + payload SHA-256 both fail |

On a shared deployed server Mallory holds **no session key by design**,
so "forward" goes through the recipient's inbox (`to_user`) — the
rejection then happens under the *victim's* key on the victim's screen,
exactly like the real-world attack path.

### Real-time Attack Theater (`POST /api/doc/attack-theater`)

For the demo video, the theater stages the whole kill chain in one call
and returns a narrated step log rendered live in the UI: **capture**
(what Mallory holds) → **inspect the wire** (ciphertext sample + entropy
+ hashes, proving she sees only ciphertext) → **tamper** (the mangled
bytes) → **forward** (delivered into the victim's inbox as a real item)
→ **victim's rejection** (the exact failed check, computed under the
victim's key; the inbox item is pre-flagged `verified: false` with the
reason). Each theater run is a ledger event.

### Where it surfaces

- **API** — `POST /api/doc/attack` (returns the mangled `container_b64`
  + `description` + `expected_outcome`), audit `attack` events, live SSE
  `attack` stage entries on `/api/doc/events`.
- **Dashboard — ⚔ Attack Lab** — capture field, mode selector with
  per-mode hints, attacker label, *save forged container*, and
  *forward to <recipient> →*.
- **Tests** — scripted E2E act 4: all four modes executed from Mallory's
  own server process, forwarded to Bob's laptop, each REJECTED with the
  named check; Bob's ledger records the rejections.

**Demo line:** *"Mallory — third laptop, her own account — captures the
container, flips bytes, renames the document, even re-seals it with her
own key. Every forgery lands in bob's inbox and every one is rejected:
GCM tag, commitment, hash. The attack itself is on the permanent
ledger."*

### Cross-account multiparty unlock (feature 7 × feature 8)

Feature 7's quorum now spans **user accounts**: after a quorum seal, the
sealant calls `POST /api/doc/quorum/distribute` with m usernames — share
*i* is placed into account *i*'s server-side custody (the holder never
sees the bytes; only the commitment is public). Each officer's dashboard
shows a custody card and they **pledge** (`POST /api/doc/quorum/pledge`)
from their own login. The sealant unlocks with
`POST /api/doc/quorum/unlock` and `shares: []` — the server validates
pledged shares against the officer commitments and reconstructs.
Below k pledges the unlock is rejected; a successful unlock consumes the
pledges. Distribute / each pledge / unlock / rejections all land in the
ledger (E2E: `scripts/e2e-multiparty.mjs`).

---

<a name="api-reference"></a>
## API reference for the new endpoints

All endpoints are additive; every new request parameter has a
backwards-compatible default.

### Modified endpoints

| Endpoint | New params | New response fields |
|---|---|---|
| `POST /api/run` | `noise_rate` (0–0.12), `relay_hops` (0–4) | per-scenario `channel_class`, `noise_rate`, `relay_hops`, `relay_stats[]`; the distilled secret is routed to the authenticated caller's workspace and is **not** serialized |
| `POST /api/simulate` | `noise_rate`, `relay_hops` | same per-point fields |

### New endpoints

| Endpoint | Method | Request | Response (abridged) |
|---|---|---|---|
| `/api/auth/register` | POST | `{ username, password }` | `{ ok, username }` |
| `/api/auth/login` | POST | `{ username, password }` | `{ ok, token, username }` |
| `/api/auth/logout` | POST | Bearer token | `{ ok }` |
| `/api/auth/me` | GET | Bearer token | `{ username }` |
| `/api/auth/users` | GET | — | `{ users[] }` (address book) |
| `/api/doc/session` | GET | — | `{ has_key, key_commitment?, quorum? }` |
| `/api/doc/seal` | POST | `{ name, content_b64, mime?, use_quorum?, quorum_threshold?, quorum_shares? }` (≤ 5 MB) | `{ container_b64, key_commitment, quorum?, officer_commitments[], audit_seq }` |
| `/api/doc/verify` | POST | `{ container_b64 }` | `{ outcome: { authentic, integrity, format_ok, key_match, unlocked_via, note, payloadScheme }, meta?, audit_seq }` |
| `/api/doc/quorum` | GET | — | sealant: `{ threshold, officers[], pledges_received }`; officer: `{ held_share: { x, from } }` |
| `/api/doc/quorum/distribute` | POST | `{ users[m] }` | `{ assignments[[user, x]], threshold, shares_total }` |
| `/api/doc/quorum/pledge` | POST | (caller's custody) | `{ pledged, officer_x, pledges_received, threshold, quorum_met }` |
| `/api/doc/quorum/unlock` | POST | `{ container_b64, shares[] }` — **empty `shares` = pledged unlock** | `{ shares_presented, threshold, enough_shares, outcome?, recognized_officers[] }` |
| `/api/doc/transfer` | POST | `{ name, content_b64, hops?, noise_rate?, eve_mode?, seed? }` | SSE `transfer_log` events → final `{ transfer_id, delivered, verdict, relay_stats[], qber, summary }` |
| `/api/doc/send` | POST | `{ container_b64? \| name+content_b64, to_user? , peer_url?, from_label? }` | `{ delivered, destination, peer_item_id, summary }` |
| `/api/doc/receive` | POST | `{ container_b64, from_label?, to_user? }` | `{ accepted, item_id, can_verify_now, note }` |
| `/api/doc/inbox` | GET | `?full=false` | `{ items[], total }` |
| `/api/doc/inbox/verify` | POST | `{ id }` | `{ outcome, meta?, audit_seq }` |
| `/api/doc/attack` | POST | `{ container_b64, mode: tamper_bytes\|swap_meta\|reseal\|truncate, from_label? }` | `{ description, container_b64, expected_outcome, audit_seq }` |
| `/api/doc/events` | GET | — | SSE: `transfer_log` / `transfer_done` (incl. `attack` stage) |
| `/api/audit/events` | GET | `?limit=N` | `{ entries[], root, total }` |
| `/api/audit/proof` | GET | `?seq=N` | `{ seq, leaf_hash, siblings["L:…"/"R:…"], root }` |
| `/api/audit/verify` | GET | — | `{ ok, broken_at?, root?, detail }` |

The session key used for sealing is the **256-bit SHA-256 privacy-
amplified secret distilled by the calling user's most recent secure QKD
run** — sealing without a prior run returns a clear error. This is
deliberate: it makes the product layer *depend on* the quantum layer in
front of judges, and the raw key never leaves the server.

---

<a name="demo-crib"></a>
## One-paragraph-per-feature demo crib

1. **Relays** — set Relay hops to 2, run: route strip renders
   Alice → R1 → R2 → Bob, sifted fraction collapses to ~1/27, red dots
   if Eve sat on a link.
2. **Noise** — set Fiber noise to 8% (no attack): verdict chip says
   *degradation warning*, keys still distilled. Then run the attack
   scenario: verdict flips to *under attack*, distillation aborted.
3. **Sealing** — drop any file in the Quantum Document Vault, Seal →
   download `.qsig`; tamper the file, Verify → HMAC mismatch, instantly;
   event lands in the ledger below.
4. **Transfer** — Portal: pick a file, 2 hops, Send: per-stage log
   streams sifting/noise/unseal/verify; verdict box lands green.
5. **Audit** — Ledger: press *proof* on any row: sibling hashes +
   recomputed root shown; the chain badge certifies the whole history.
6. **TUI** — second terminal: `cargo run -p tui`, press 2 (attack),
   watch the sparkline jump to 1/3, then s / v / t for the vault demo.
7. **Quorum** — Vault: enable quorum seal 3-of-5 → seal → toggle only 2
   officers → unlock rejected; toggle 3 → unlocked via quorum. Or go
   **cross-account**: distribute to carol/dave/eve, they pledge from
   their logins, unlock with the pledged shares.
8. **Accounts + P2P** — register on two laptops, same seed, seal on A,
   send to B's inbox, verify green on B.
9. **Attack Lab** — Mallory (third laptop/account) captures the
   container, runs any of the four attacks, forwards to bob — rejected
   every time, and the attempt is on the ledger.
