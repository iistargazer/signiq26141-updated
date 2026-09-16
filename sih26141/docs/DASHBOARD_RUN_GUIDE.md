# How to Run the Dashboard — Judging Round Guide

**For: any team member who has never started the app before.**
Follow this top to bottom. Time needed the first time: ~10 minutes
(mostly downloads). Time on judging day: ~1 minute.

Everything happens inside one folder:

```
C:\Users\rohan\Downloads\S-Vageesh SigniQ vageesh sih26141-project-qds-updated\sih26141
```

---

## 0. What you're starting (30-second orientation)

One Rust program (the API + physics engine) serves the pre-built React
dashboard on **one port: 8080**. You open the dashboard in a browser;
the browser talks to the same program. There is no separate frontend
server to start for the demo.

```
cargo run -p server  →  http://127.0.0.1:8080  →  browser shows the dashboard
```

---

## 1. One-time setup (do this tonight, not at the venue)

### 1.1 Check the tools are installed

Open **PowerShell** (Start → type "powershell") and run:

```powershell
cargo --version    # expect: cargo 1.x — any 1.8x is fine
node --version     # expect: v24.x (anything ≥ 18 works)
npm --version      # expect: 11.x
```

If `cargo` is not recognized: install Rust from https://rustup.rs
(default options are fine; MSVC toolchain not required — windows-gnu
works). If `node` is not recognized: install Node LTS from
https://nodejs.org.

### 1.2 Build the Rust workspace + run the test suite

```powershell
cd "C:\Users\rohan\Downloads\S-Vageesh SigniQ vageesh sih26141-project-qds-updated\sih26141"
cargo test --workspace
```

Expected: a stream of test names ending with `test result: ok.` lines —
**66 tests total, 0 failed**. This is also great evidence if a judge
asks whether the project is tested.

### 1.3 Build the dashboard (only needed if `frontend\dist` is missing)

The dashboard ships pre-built in `frontend\dist\`. If that folder exists,
**skip this step**. Otherwise (or after any frontend code change):

```powershell
cd frontend
npm install        # first time only, ~1–2 min
npm run build      # ~10 s, must end with "✓ built"
cd ..
```

> The `tui` crate has no build step — it compiles with the workspace.
> If it's missing from `cargo run -p tui`, run `cargo fetch` once to pull
> `ratatui`/`crossterm` (needs network, first time only).

---

## 2. Starting the dashboard (the part you do on judging day)

In PowerShell, from the `sih26141` folder:

```powershell
cargo run -p server
```

That's it. Port 8080 is the default; you don't need to set anything.

Expected console output (takes a few seconds the first time while it
compiles):

```
SIH26141 API server listening on http://127.0.0.1:8080
Frontend: ...\sih26141\frontend\dist
```

> Leave this window open — closing it stops the app. If the terminal
> shows `Compiling`/`Blocking` for a while on first run, that's normal
> one-time compilation.

**Then open a browser** (Chrome/Edge) at:

```
http://127.0.0.1:8080
```

### 2.1 What you should see

- Dark quantum-themed dashboard titled **"Quantum-Secured Pipeline ⚛"**
- Top-right pill: **● API online** (green)
- Panels in order: Experiment Parameters (with **Fiber noise** and
  **Relay hops** sliders) → status cards → Live Channel Monitor → QBER
  vs. Eavesdropping Intensity → **⚛ Quantum Document Vault** (seal /
  verify / Merkle ledger) → **P2P Transfer Portal** → **⚛ QDS Signature
  Lab** (with the ①–⑤ numbered buttons) → footer.

### 2.2 The 8-click smoke test (3 minutes, do it before judges arrive)

| Click | Where | Expected result |
|---|---|---|
| **Run Secure + Attack** | top-right button | Left card ends green "AUTHENTIC", right card red "THREAT FLAGGED", chart shows red line converging to ~33% |
| Set **Fiber noise** to 8%, **Run** again | parameters | Left card ends amber "⚠ degradation warning" (keys still distilled) |
| Set **Relay hops** to 2, **Run** | parameters | Cards show a route strip Alice → R1 → R2 → Bob; sifted bits drop to ~1/27 of raw |
| **Seal → .qsig** (after picking a file) | Quantum Document Vault | `.qsig` download offered; a `seal` entry appears in the Merkle ledger below |
| **Verify** | Document Vault | Green verdict "HMAC tag and payload hash match" |
| **Send securely** (pick a file, 2 hops) | P2P Transfer Portal | Live log streams stages; green verdict box; new `transfer` ledger entries |
| **1 · Generate quantum keys** | QDS Lab | Green chip "P(forgery) < 10^-39" appears |
| **2 · Sign** then **3 · Launch all 5 attacks** | QDS Lab | "✓ Bob verified · 1-ACC" chip; all 5 attack rows show "✓ rejected" |

If all eight behave, you're demo-ready. (Forgery analysis and
performance evaluation also work; each takes ~1–3 s. To test tamper
detection: after sealing, edit one character of the original file,
re-upload, Verify → red verdict.)

### 2.3 The TUI second screen (optional but impressive)

In a **second** terminal window:

```powershell
cargo run -p tui
```

A live terminal dashboard appears: QBER sparkline, relay route, document
vault, Merkle audit tail, pipeline log. Keys: `1/2/3` scenarios,
`n`/`N` noise ±1%, `r`/`R` relay hops, `s` seal / `v` verify / `t`
tamper / `w` quorum, `Q` quit. It runs the same engine as the web UI —
use it as a second screen during the demo.

---

## 3. Other ways to start it (reference)

**Command Prompt (cmd.exe) instead of PowerShell:**

```cmd
cd /d "C:\Users\rohan\Downloads\S-Vageesh SigniQ vageesh sih26141-project-qds-updated\sih26141"
cargo run -p server
```

**Git Bash:**

```bash
cd "/c/Users/rohan/Downloads/S-Vageesh SigniQ vageesh sih26141-project-qds-updated/sih26141"
cargo run -p server
```

**On a different port** (only if 8080 is taken — see troubleshooting):

```powershell
$env:PORT = 8090
cargo run -p server
# then open http://127.0.0.1:8090
```

**One command for everything** (build + tests + CLI demo + dashboard;
Git Bash / WSL):

```bash
./scripts/run_simulations.sh
```

**Frontend hot-reload dev mode** (only for editing the UI, not for the
demo — runs a second server on 5173 that proxies /api to 8080):

```powershell
cd frontend
npm run dev        # http://localhost:5173
```

---

## 4. Troubleshooting

**Pill says "● API offline"**
- The dashboard auto-probes for the API every 10 s and after a port
  fallback — give it ≤ 10 s before worrying.
- Check the server console window is still open and shows
  "listening on http://127.0.0.1:8080". If it shows a fallback line
  ("falling back to 127.0.0.1:8081"), just browse to that port instead.
- Still offline? Restart the server, then hard-refresh the browser
  (Ctrl+Shift+R).

**Console error: port 8080 held / os error 10013**
- Another program (often Apache, Hyper-V, or a stale server) holds
  8080. The server **auto-falls back** to 8081–8090 and prints the
  actual URL — use what it prints. To see who holds 8080:
  `netstat -ano | findstr :8080`
- Or just pick another port: `$env:PORT = 8090; cargo run -p server`

**Console says "no frontend build at ... — API-only mode"**
- `frontend\dist` is missing. Run section 1.3, then restart the server.

**Browser shows an old/broken page**
- Hard refresh: Ctrl+Shift+R. The pre-built bundle is cached
  aggressively.

**Runs look identical every time / charts don't change**
- Check the **Seed** box. Blank = fresh randomness every run. If a number
  is typed there, every run with the same parameters reproduces the exact
  same results *by design* (that's the reproducibility feature — the event
  log proves it: each run prints `seed <n> · <qubits> qubits · threshold <x>%`).
  Clear the box for a new random draw each run.
- The event log line also echoes the parameters actually used — if the
  qubits/threshold values there don't match the sliders, the page is stale:
  hard-refresh (Ctrl+Shift+R).

**Windows Firewall popup on first run**
- Click **Allow** (the server binds 127.0.0.1 only, but the popup can
  still appear once).

**`cargo run` says "already running" / file lock**
- A previous server is still alive: close its terminal window, or
  `taskkill /f /im server.exe` in PowerShell, then start again.

**Last-resort fallback for the demo**
- The CLI demo shows the same physics without any browser:
  `cargo run -p main_app`
- And `docs/JUDGE_PITCH.md` has the full narration script if you have
  to present from the terminal.

**Folder size (why ~1.6 GB)**
- That's almost entirely `target/` (Rust build cache, ~1.5 GB) and
  `frontend/node_modules` (npm deps, ~121 MB) — both regenerable and
  both *required to be present* for a fast demo start. Do not clean
  before the round. Afterwards, `bash scripts/clean_build_artifacts.sh`
  reclaims the space; the next `cargo build` / `npm install` restores
  whatever is needed. The actual source code is only ~1 MB.

---

## 5. Pre-flight checklist (night before / morning of)

- [ ] `cargo test --workspace` → 66 passed, 0 failed
- [ ] `cargo run -p server` → prints "listening on http://127.0.0.1:8080"
- [ ] Browser at http://127.0.0.1:8080 → pill green, 5-click smoke test passes
- [ ] Server stays open; laptop plugged in; browser zoom comfortable (Ctrl+=)
- [ ] Backup known: CLI demo (`cargo run -p main_app`) works
- [ ] Audit-log file exists at `sih26141\qds_events.jsonl` (opens in Notepad)

Good luck — you're one command away: **`cargo run -p server`**.
