# Demo Video Script (3:00) — SIH26141 Quantum-Secured Pipeline

**Target length:** 3:00 sharp. **Format:** 1080p screen recording +
voiceover (record narration separately, sync in editing; ~140 wpm).

**Golden rules:** record each scene as a separate clip; every scene
resets cleanly so retakes are cheap. **Every number in the narration is
verified behavior of this build** — if the screen disagrees, the tab is
stale: hard-refresh (Ctrl+Shift+R) before retaking.

---

## 1. Pre-recording checklist (15 minutes, once)

- [ ] `cargo test --workspace` → 66 passed (confidence floor)
- [ ] Server running: `cargo run -p server` → `http://127.0.0.1:8080`
- [ ] TUI running in a second terminal: `cargo run -p tui` (only if
      recording the optional Scene 6)
- [ ] **Hard-refresh the tab** (picks up the fixed bundle)
- [ ] Browser zoom **110–125%** (Ctrl + +); fullscreen (F11)
- [ ] Notifications off (Win + A → Do not disturb); bookmarks bar hidden
      (Ctrl+Shift+B)
- [ ] **Warm every panel once** (run, sweep, keys, sign, attacks, ④, ⑤)
      so nothing compiles on camera
- [ ] Parameters for Scene 2: key length **20,000**, threshold **15%**,
      **pace 0–2 ms** (the stream must finish in ≤15 s), seed box
      **BLANK** (a typed seed would falsify the "fresh randomness"
      narration), message default
- [ ] Quiet room; mic at fixed mouth distance

## 2. Recording setup

- OBS Studio (or Win+G), 1920×1080, 30 fps, capture the browser window
  only. Cursor highlight on — clicks are the visual anchors.
- Voiceover separately (Audacity/phone), sync later. The narration below
  totals ~410 words ≈ 2:55 at a calm pace — do not rush it; trim pauses
  in editing instead.
- Per clip: click → result lands → one silent beat → stop. Editors need
  the padding.

---

## 3. The 3:00 script

### SCENE 1 — Hook (0:00–0:10)
**On screen:** title card:
> **SIH26141 — Quantum-Secured Pipeline**
> Six-State QKD · Teleportation-Based QDS · physics, not computation

**Narration:**
> "Quantum computers will break every signature the internet uses.
> This is SIH26141 — security from physics, not computation. Let me
> show you it working, live."

---

### SCENE 2 — QKD: catching the eavesdropper (0:10–1:00) ★ core scene
**Actions:** dashboard top → **click "Run Secure + Attack"** at 0:10.
Cursor follows: pills/cards while streaming → the red line → dashed
thresholds → verdict chips as they land.

**Narration:**
> "One Rust engine, one API, one dashboard — everything in this tab is
> live. I'm sending twenty thousand qubits through two channels: a clean
> one, and one where an eavesdropper intercepts every single qubit.
>
> Left card — the secure channel: error rate exactly zero, and we've
> distilled a 256-bit key that HMAC-signs a message. Right card — watch
> the red line converge… to exactly one third. That's not tuning, that's
> physics: Eve picks the wrong measurement basis two-thirds of the time,
> and then the bit is wrong half the time.
>
> The dashed thresholds tighten as data accumulates — the Hoeffding
> bound, statistics with no machine learning anywhere. And the verdicts:
> the secure channel authenticates; the attack is flagged and its key
> material destroyed. No key ever existed to steal."

**Overlays:** `QBER → 1/3 — six-state physics` (on the red line) ·
`threshold(n) = base + √(ln(2/δ)/2n)` (near the dashed lines)

---

### SCENE 3 — Sweep: theory predicts simulation (1:00–1:20)
**Action:** scroll to **QBER VS. EAVESDROPPING INTENSITY** → click
**Run parameter sweep** (~3 s).

**Narration:**
> "Eleven experiments in one chart: every bar is a different
> eavesdropping strength. Blue is measured, dark is theory — QBER equals
> one third of what Eve intercepts — and they track each other without
> tuning. Detection fires around fifty-five percent; below that Eve
> hides under the statistical margin — the honest trade-off of QKD."

**Overlay:** `QBER(f) = f/3 · crossover ≈ 50–55%`

---

### SCENE 4 — QDS: keys & teleportation signing (1:20–1:55) ★ wow scene
**Actions:** scroll to **⚛ QDS SIGNATURE LAB** → **click "1 · Generate
quantum keys"** → then **"2 · Sign via teleportation"** (default
message). Cursor on the commitment hash, the P(forgery) chip, then the
trace table.

**Narration:**
> "Now signatures. Trent, our notary center, shares entangled Bell
> pairs with Alice; the public key is only a commitment hash, and the
> forgery bound is already on screen: below ten to the minus
> thirty-eight. Alice signs by teleporting qubits — this table is the
> actual teleportation log: Bell outcome, Pauli correction, raw and
> corrected bits. Bob verified on delivery — one-ACC, transferable — and
> the nonce is single-use. Change one character of the message and this
> entire signature changes."

**Overlay:** `P(forgery) = (1/4)^64 = 4^−64 ≈ 2.9×10⁻³⁹`

---

### SCENE 5 — Five attacks, five rejections (1:55–2:30)
**Actions:** move the **tamper fraction** slider while speaking its
sentence, then **click "3 · Launch all 5 attacks"**. Cursor walks the
five rows top to bottom as each is named.

**Narration:**
> "Five attacks, straight from the problem statement. Forgery — guessing
> every quantum outcome: rejected, three-quarters of positions mismatch.
> Impersonation — a real signature on a different message: rejected, the
> message binding fails. Replay — blocked by the nonce ledger *before
> statistics even run*: that's double-spend protection. Channel
> tampering — slide Eve's fraction and the mismatches climb with it; at
> zero, no false alarm. Unauthorized verification — flagged as its own
> class. Five attacks, five rejections, zero machine learning."

**Overlay:** `5 attack classes → 5 rejections · 0 false alarms`

---

### SCENE 6 — Guarantees & evaluation (2:30–2:50)
**Actions:** **click "4 · Run analysis"** (~2 s) → scroll to evaluation →
**click "5 · Run evaluation"** (~1 s). Cursor on the bar chart, then the
two metric cards.

**Narration:**
> "The forgery cost is a law: four to the minus q-times-lambda — every
> security level multiplies the attacker's work a thousandfold, and we
> cross 128-bit security at lambda four. The evaluation measures it all:
> accuracy above ninety-nine point nine percent, zero false alarms,
> microsecond signatures — seeded, so auditors can reproduce every
> number."

**Overlay:** `seeded evaluation → reproducible for audit`

---

### SCENE 7 — Outro (2:50–3:00)
**On screen:** end card:
> **Security from physics. Decisions from statistics. Zero black boxes.**
> 66 automated tests · Gottesman–Chuang 2001 · Singh et al. 2023 ·
> Weng et al. 2021 · Merkle-audit-logged

**Narration:**
> "Security from physics. Decisions from statistics. Zero black boxes —
> 66 automated tests, every event hash-chained into a Merkle audit ledger.
> SIH26141. Thank you."

---

## 4. Overlays to build (6 lower-thirds, 3–4 s each)

1. `QBER → 1/3 — six-state physics` (Scene 2)
2. `threshold(n) = base + √(ln(2/δ)/2n)` (Scene 2)
3. `QBER(f) = f/3 · crossover ≈ 50–55%` (Scene 3)
4. `P(forgery) = 4^(−qλ) ≈ 2.9×10⁻³⁹ @ (16, λ=4)` (Scene 4)
5. `5 attack classes → 5 rejections · 0 false alarms` (Scene 5)
6. `seeded evaluation → reproducible for audit` (Scene 6)

## 5. Timing discipline (what makes 3:00 work)

- **Pace slider at 0–2 ms** — the Scene 2 stream must finish in ~12 s so
  verdicts land by 0:55. At pace 6 the scene overruns; at 20 it dies.
- Narration is ~410 words. Rehearse Scene 2 twice aloud — it's the only
  scene where talking and streaming must overlap cleanly.
- Don't pause the stream mid-take; keep talking over it and cut dead air
  later. Silence is harder to edit than wobble.
- If a scene runs long, cut from Scene 3 (the sweep survives with just
  "the bars track theory — detection at fifty-five percent").

## 6. Retake-cheat sheet

| Scene resets by | Notes |
|---|---|
| 2 | params panel unchanged; just click Run again |
| 3 | sweep is stateless — re-click |
| 4 | **① Regenerate keys** re-rolls the commitment on camera (itself a nice beat: "fresh quantum randomness every time") |
| 5 | needs any signature on file: re-click ② then ③ |
| 6 | stateless — re-click |

## 7. If the portal allows more time (extend 3:00 → 5:00)

Add these beats back, in this order of value:

1. **+45 s — The v2 product layer (after Scene 6):** fiber noise to 8% →
   run → amber "degradation warning" ("noise flips bits; only a
   measurement collapses states"); relay hops to 2 → run → route strip +
   collapsing yield; Doc Vault: seal a file, flip one byte, verify →
   instant red; quorum 3-of-5 → two officers rejected, three unlocked;
   Transfer Portal send with the live log streaming. Overlay:
   `1 byte ⇒ instant fail · k−1 shares ⇒ zero info · (1/3)^(hops+1)`.
2. **+60 s — Three laptops: real transfer, rejected attack (after Scene
   6):** follow `docs/DEPLOYMENT_GUIDE.md` §4 — laptop A (alice) seals and
   **Send to laptop** → laptop B (bob) verifies green in his inbox;
   laptop C (mallory) captures the container, runs **tamper bytes** in
   the Attack Lab, forwards to bob → his screen shows ✗ REJECTED and her
   ledger shows the red `attack` row. Overlay: `2 laptops · 3 accounts ·
   4 attack modes → 4 rejections`.
3. **+40 s — Audit trail & reproducibility (after Scene 6):** open
   `qds_events.jsonl` in Notepad beside the browser ("every event you
   just saw was persisted with a timestamp and verdict"), press
   **proof** on a row in the Merkle ledger ("one entry proven against
   the root — without revealing the log"), then type seed
   **777**, run twice at pace 0, point at the identical results + `seed
   777` log lines ("bit-for-bit reproducible — auditors can check,
   attackers can't argue").
3. **+20 s — Key material close-up (after Scene 2):** the derived
   256-bit secret, the verified HMAC tag, and the attack side: "first
   divergent bit at index two — no shared secret produced."
4. **+15 s — Threshold-goes-wrong demo (after Scene 3):** set base
   threshold to 40%, run — the full attack now passes as AUTHENTIC.
   "Set the bar above the physics and Eve walks through — thresholds
   are policy, not formality." (Verify once before recording; reset to
   15% after.)
5. **+25 s — Slow teleportation narration (Scene 4):** walk the trace
   table row by row and re-sign a tampered message on camera ("Transfer
   999 QCO…" → completely different hex).
6. **+15 s — TUI second screen (optional):** `cargo run -p tui` beside
   the browser; press 2 — sparkline jumps toward one-third, verdict
   flips UNDER ATTACK. "Same engine, terminal front-end."

## 8. Export

H.264, 1080p, ~8 Mbps, AAC 192 kbps → `SIH26141_QuantumSecuredPipeline_Demo.mp4`.
Keep the editing project **outside** `sih26141/` (folder-size hygiene —
see `DASHBOARD_RUN_GUIDE.md`).
