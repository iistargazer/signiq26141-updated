# Deployment & Multi-Laptop Guide — SIH26141

This guide covers: deploying the stack to **Render** (backend + dashboard),
optionally fronting it with **Vercel**, running the **three-laptop demo with
three accounts** (2 users + 1 attacker), and the **cross-account multiparty
threshold** (k-of-m officer unlock with separate user accounts).

---

## 1. What runs where — pick one of three modes

| Mode | What you get | Best for |
|---|---|---|
| **A. One Render service** | ONE URL: API + dashboard in a single Rust process | simplest; works on all laptops with zero config — **recommended** |
| **B. Vercel (frontend) + Render (API)** | Separate URLs; Vercel proxies `/api/*` to Render | matches the README's "Vercel + Render" story |
| **C. Local LAN (3 processes)** | `http://<laptop-ip>:8080` on your Wi-Fi, no cloud at all | offline demos, no deploy needed (see `.freebuff/run.md`) |

In every mode the flow is identical: each laptop opens the URL, registers its
own account, and the server keeps per-user keys/seals/inboxes isolated.

---

## 2. Mode A — deploy everything to Render (recommended)

The repo ships a **Dockerfile** (multi-stage: Node builds the dashboard, Rust
builds the API, one runtime image serves both) and a **render.yaml** blueprint.

### Steps

1. **Push the repo to GitHub** (Render deploys from a git repo or a Docker
   image registry).
2. In the Render dashboard: **New → Blueprint**, select the repo, review the
   plan (the blueprint defaults to `starter`; use `free` for a zero-cost demo —
   cold starts and no persistent disk), then **Apply**.
   - Render builds the Docker image and starts one web service.
   - First build takes ~5–10 minutes (full Rust release build).
3. Note the service URL: `https://<your-service>.onrender.com`.
4. **Health check:** open `https://<your-service>/api/health` — it must say
   `ok`.

### Persistence (optional but nice)

The blueprint attaches a 1 GB disk at `/data`. The Docker image sets
`AUDIT_LOG=/data/audit_log.jsonl`, `USERS_FILE=/data/users.json`,
`QDS_EVENT_LOG=/data/qds_events.jsonl`, so **accounts and the Merkle audit
ledger survive restarts and deploys**. On the free plan (no disk) they reset
when the service restarts — just re-register the accounts; nothing else
changes.

### Notes

- The service binds `0.0.0.0:8080` inside the container; Render's proxy
  terminates TLS and forwards to it — the server never needs a cert.
- Request bodies up to the server's 12 MB cap pass through Render's proxy
  unchanged, so the 5 MB document demo works as-is.
- Auto-deploys: every push to the connected branch rebuilds the image.

---

## 3. Mode B — Vercel frontend + Render API (split)

1. Deploy the backend on Render **exactly as in Mode A** (the Dockerfile runs
   the same service; the dashboard it embeds is simply unused by Vercel).
2. In `frontend/vercel.json`, replace
   `https://REPLACE-WITH-YOUR-RENDER-URL.onrender.com` with your real Render
   URL (keep the `/api/$1` suffix).
3. In Vercel: **Add New → Project**, import the repo, set:
   - **Root Directory:** `frontend`
   - Framework preset: Vite (build `npm run build`, output `dist`)
4. Deploy. The Vercel URL now proxies `/api/*` to Render, so the dashboard
   code (which talks same-origin) works unchanged.

> CORS is already permissive server-side (`CorsLayer::permissive()`), so even
> without the proxy the Vercel frontend could talk to the Render API directly.

---

## 4. Three laptops, three accounts (the video scenario)

Works identically on a deployed URL or a LAN URL. Each laptop uses its own
browser profile (or incognito) so the localStorage tokens stay separate.

**One-time (Laptop A, any account):** nothing to configure — accounts are
created from the UI.

| Laptop | Browser profile | Account | Role |
|---|---|---|---|
| A | normal | `alice` | sender |
| B | normal | `bob` | recipient |
| C | normal | `mallory` | attacker |

### Script (shot list)

1. **Laptop A — register alice.** AuthBar → username `alice`, password →
   **register** → **log in**. The header shows `👤 alice`.
2. **Laptop B — register bob.** Same steps on the other laptop. Then press
   **Derive QDS key** in the Vault (Seed = 424242) — six-state QDS key
generation distills bob's session key.
3. **Laptop A — alice does the same** (Seed = 424242). Both laptops now
   hold the SAME QDS-derived session key (see the shared-seed note in the
   README).

> **Self-hosting requirement:** every server that will verify another
> server's containers must run with the same `TRENT_SEED` env var (any
> fixed value, e.g. `424242`) — the teleport-QDS notary tables are seeded
> from it, so signatures made on laptop A verify on laptop B. The Render
> blueprint sets it; set it manually when launching `server.exe` yourself.
4. **Laptop A — seal a document.** Quantum Document Vault → drop a file →
   **Seal → .qsig** (auto-downloads).
5. **Laptop A → B — real P2P transfer.** Peer-to-Peer Transfer panel →
   drop the same file → **Recipient username:** `bob` → **…or remote laptop
   API base URL:** the Render URL (or `http://<bob-lan-ip>:8080` on a LAN) →
   **Send to laptop →**. Verdict: `✓ delivered — container accepted into the
   inbox`.
6. **Laptop B — verify.** Bob's Inbox panel shows the inbound item →
   **verify** → `✓ document verified: AES-GCM payload, HMAC tag and payload
   hash all match the QKD session key`.
7. **Laptop C — mallory attacks.** Register/log in as `mallory`. She captured
   the container (it's public ciphertext — e.g. the downloaded `.qsig`). In
   the **Attack Lab**: load it, pick an attack mode (tamper bytes / swap
   metadata / re-seal (forge) / truncate), **Run attack →**, then
   **forward to bob →** (recipient field).
8. **Laptop B — the rejection.** Mallory's forgery lands in bob's inbox →
   **verify** → `✗ REJECTED` with the exact failed check (GCM tag mismatch /
   key commitment mismatch / hash mismatch). The attack is also on the audit
   ledger as an `attack` event.
9. **Closing shot — the ledger.** Any laptop: Merkle Audit Ledger panel →
   `✓ chain intact`, per-row **proof** buttons render Merkle inclusion proofs.

---

## 5. Cross-account multiparty threshold (k-of-m with user accounts)

This is feature 7 extended to real accounts: **the officer shares live in
other users' accounts, and each officer pledges from their own login.**

Server-side primitives (all authenticated, all audit-logged):

| Endpoint | Who calls | What it does |
|---|---|---|
| `POST /api/doc/quorum/distribute` | sealant | hands share *i* to the *i*-th named user account (server-side custody; the holder never sees the bytes) |
| `POST /api/doc/quorum/pledge` | officer | the logged-in holder commits their share toward the sealant's unlock |
| `POST /api/doc/quorum/unlock` | sealant | with empty `shares: []`, unlocks using the **pledged** shares (validated against officer commitments) |

UI flow (4 accounts: `alice` + 3 officers, k=2, m=3):

1. **alice** — Vault → enable **Shamir quorum seal**, set k=2, m=3, seal.
   The result card shows the **Multiparty** box: three `OFF-xx → account`
   inputs (pre-filled with registered usernames) → **Distribute shares →**.
2. **carol** (another account/laptop) — her Vault shows
   `🔑 You hold officer OFF-1 (distributed by alice)` → **Pledge my share →**
   → `1/2 pledges`.
3. **dave** — same → `2/2 — QUORUM MET`.
4. **alice** — the Multiparty box shows the pledge count →
   **Unlock with 2 pledged shares →** → `✓ unlocked via quorum 2-of-3`.
   Pledges are consumed by the unlock.
5. Try to unlock after only one pledge → `✗ unlock rejected` (and it's in the
   ledger). `eve`, the third officer, still holds OFF-3 in custody — pledge it
   too and the count updates.

Everything (distribute / each pledge / unlock / rejections) is appended to the
Merkle audit ledger — the non-repudiation story applies to the multiparty
protocol itself.

> For the video: carol and dave can be different browser profiles on the same
> laptop, different laptops, or different phones — the accounts are what
> matter, not the machines.

---

## 6. Deployment verification checklist

After deploying (any mode):

```bash
BASE=https://<your-service>.onrender.com   # or http://<lan-ip>:8080

curl -s $BASE/api/health                          # -> ok
curl -s -X POST $BASE/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"demo-pass-1"}'
TOKEN=$(curl -s -X POST $BASE/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"demo-pass-1"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
curl -s $BASE/api/auth/me -H "Authorization: Bearer $TOKEN"   # -> {"username":"alice"}
curl -s $BASE/api/audit/verify                    # -> {"ok":true,...}
```

Then run the scripted E2E against the deployed URL by editing the `A`/`B`/`C`
constants at the top of `scripts/e2e-test.mjs` and
`scripts/e2e-multiparty.mjs` (for one deployed URL, point all three at it —
accounts give you the isolation).

---

## 7. Known demo conventions & limits

- **Shared-seed keys:** two laptops hold the same session key because both
  derived it from the same six-state QDS seed. A real deployment would
  transport a one-time pad over the QKD link itself.
- **`TRENT_SEED` must match across servers** for cross-laptop QDS
  verification (the embedded teleport-QDS signature is made by the sealing
  server's notary; same seed = same notary tables). On Render it is set in
  the blueprint; locally the `.freebuff/launch*.ps1` scripts set it.
- **Sessions are memory-only:** a server restart logs everyone out (accounts
  persist; tokens do not). On Render free tier, restarts happen — re-login and
  continue.
- **5 MB cap** (`MAX_FILE_BYTES` = 5 × 1024 × 1024) enforced server-side;
  bodies above 12 MB are rejected.
- **Passwords ≥ 6 chars**, PBKDF2-SHA256 600k rounds, 16-byte salts. Rate
  limit: 2s backoff per username after a failed login.
- **Attack Lab on a shared server:** Mallory's "forward" goes through the
  recipient's inbox (`to_user`) because she holds no session key by design —
  the rejection happens under the recipient's key.
