// Live three-laptop end-to-end: Alice → Bob delivery, Mallory attack, rejection.
// Laptops: A=http://127.0.0.1:8080 (Alice) · B=http://127.0.0.1:8081 (Bob)
//          C=http://127.0.0.1:8083 (Mallory) — isolated data dirs.
const A = 'http://127.0.0.1:8080'
const B = 'http://127.0.0.1:8081'
const C = 'http://127.0.0.1:8083'
const B_PEER = 'http://127.0.0.1:8081' // what Alice dials (LAN base in real life)

let step = 0
function head(s) { step++; console.log(`\n——— ${s} ———`) }
function ok(s) { console.log(`  ✓ ${s}`) }
function bad(s) { console.log(`  ✗ ${s}`) }

async function call(base, path, { method = 'POST', token, body } = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { /* non-JSON */ }
  return { status: res.status, json, text }
}

// VerificationOutcome serializes as four flags (passed() is a Rust method).
const passedOf = (o) => !!o && o.format_ok && o.authentic && o.integrity && o.key_match

// Deterministic "laptop fingerprints": same seed everywhere → same key.
const SEED = 424242

async function main() {
  // ---- Act 1: accounts -----------------------------------------------------
  head('Act 1 · Accounts on Laptop A')
  for (const [name, pw] of [['alice', 'wonderland9'], ['mallory', 'evil-laptop1']]) {
    const reg = await call(A, '/api/auth/register', { body: { username: name, password: pw } })
    if (reg.status === 200) ok(`registered '${name}'`)
    else if (reg.json?.error?.includes('taken')) ok(`'${name}' already registered (re-run)`)
    else bad(`register '${name}': ${JSON.stringify(reg.json)}`)
  }
  const bobReg = await call(B, '/api/auth/register', { body: { username: 'bob', password: 'bobcat-99' } })
  if (bobReg.status === 200) ok(`registered 'bob' on Laptop B`)
  else if (bobReg.json?.error?.includes('taken')) ok(`'bob' already registered on Laptop B`)
  else bad(`register bob: ${JSON.stringify(bobReg.json)}`)

  const alice = (await call(A, '/api/auth/login', { body: { username: 'alice', password: 'wonderland9' } })).json.token
  const mallory = (await call(A, '/api/auth/login', { body: { username: 'mallory', password: 'evil-laptop1' } })).json.token
  const bob = (await call(B, '/api/auth/login', { body: { username: 'bob', password: 'bobcat-99' } })).json.token
  if (alice && bob && mallory) ok('alice + mallory (A), bob (B) logged in with bearer tokens')
  else bad(`tokens: alice=${!!alice} bob=${!!bob} mallory=${!!mallory}`)

  // Bob runs the QKD sim under the SAME seed → same distilled session key.
  // (derived_secret is deliberately NOT in the API response — its presence
  // is proven by the successful seal/verify that follow.)
  head('Act 1b · Key derivation (shared seed on both laptops)')
  for (const [base, tk, who] of [[A, alice, 'Alice'], [B, bob, 'Bob']]) {
    const run = await call(base, '/api/run', { token: tk, body: { key_length: 3000, seed: SEED, pace_ms: 0 } })
    const secure = run.json?.results?.find(r => r.scenario === 'secure')
    const got = !!run.json?.results?.some(r => r.is_authentic && r.channel_class === 'secure')
    got ? ok(`${who} distilled a session key (QBER ${(secure?.qber * 100).toFixed(2)}%)`)
        : bad(`${who} has no session key: ${JSON.stringify(run.json).slice(0, 200)}`)
  }

  // ---- Act 2: Alice seals a document ---------------------------------------
  head('Act 2 · Alice seals a document')
  const docText = 'CONFIDENTIAL — Project Phoenix budget review. Transfer approved: $4.2M.'
  const b64 = s => Buffer.from(s, 'utf8').toString('base64')
  const seal = await call(A, '/api/doc/seal', {
    token: alice,
    body: { name: 'phoenix-budget.txt', content_b64: b64(docText), mime: 'text/plain' },
  })
  if (seal.json?.container_b64) {
    ok(`sealed '${seal.json.name}' (${seal.json.size} B, sha ${seal.json.sha256.slice(0, 12)}…)`)
  } else bad(`seal failed: ${JSON.stringify(seal.json)}`)
  const containerB64 = seal.json.container_b64

  // ---- Act 3: real laptop-to-laptop P2P send -------------------------------
  head('Act 3 · Alice → Bob over the network (laptop A → laptop B)')
  const send = await call(A, '/api/doc/send', {
    token: alice,
    body: { container_b64: containerB64, peer_url: B_PEER, to_user: 'bob', from_label: 'alice' },
  })
  if (send.json?.delivered) {
    ok(`delivered to Laptop B — ${send.json.summary}`)
  } else bad(`send failed: ${JSON.stringify(send.json)}`)

  head('Act 3b · Bob verifies the inbound container')
  const inbox = await call(B, '/api/doc/inbox', { token: bob, method: 'GET' })
  const item = inbox.json?.items?.at(-1)
  if (!item) { bad(`inbox: HTTP ${inbox.status} ${inbox.text.slice(0, 120)}`); return }
  ok(`inbox has ${inbox.json.total} item(s): '${item.meta.name}' from ${item.from_peer}`)
  const bobVerify = await call(B, '/api/doc/inbox/verify', { token: bob, body: { id: item.id } })
  if (passedOf(bobVerify.json?.outcome)) {
    ok(`BOB ACCEPTED: ${bobVerify.json.outcome.note}`)
  } else bad(`bob verify: ${JSON.stringify(bobVerify.json?.outcome ?? bobVerify.json)}`)

  // ---- Act 4: Mallory attacks from HER OWN laptop (C) -----------------------
  head('Act 4 · Mallory (Laptop C) intercepts and tampers')
  // Mallory captured the container off the wire (it is public ciphertext) and
  // operates entirely from her laptop: attack on C, forward C → B.
  const malloryC = (await call(C, '/api/auth/register', { body: { username: 'mallory', password: 'evil-laptop1' } }))
  if (malloryC.status === 200) ok('mallory registered on Laptop C')
  else if (malloryC.json?.error?.includes('taken')) ok('mallory already registered on Laptop C')
  else bad(`register on C: ${JSON.stringify(malloryC.json)}`)
  const mallTokC = (await call(C, '/api/auth/login', { body: { username: 'mallory', password: 'evil-laptop1' } })).json.token
  if (!mallTokC) { bad('mallory login on C failed'); return }
  for (const mode of ['tamper_bytes', 'swap_meta', 'reseal', 'truncate']) {
    const atk = await call(C, '/api/doc/attack', {
      token: mallTokC,
      body: { container_b64: containerB64, mode, from_label: 'mallory' },
    })
    if (!atk.json?.container_b64) { bad(`attack ${mode}: ${JSON.stringify(atk.json)}`); continue }
    // Mallory forwards her forgery from C to Bob's laptop...
    const fwd = await call(C, '/api/doc/send', {
      token: mallTokC,
      body: { container_b64: atk.json.container_b64, peer_url: B_PEER, to_user: 'bob', from_label: 'mallory' },
    })
    // ...Bob's inbox auto-checks; verify explicitly for the verdict line.
    const inbox2 = await call(B, '/api/doc/inbox', { token: bob, method: 'GET' })
    const item2 = inbox2.json?.items?.at(-1)
    if (!item2) { bad(`attack ${mode}: nothing arrived in Bob's inbox`); continue }
    const v = await call(B, '/api/doc/inbox/verify', { token: bob, body: { id: item2.id } })
    const out = v.json?.outcome
    if (out && !passedOf(out)) {
      ok(`attack ${mode} → REJECTED: ${out.note}`)
    } else if (out) {
      bad(`attack ${mode} was ACCEPTED — SECURITY FAILURE: ${JSON.stringify(out)}`)
    } else {
      bad(`attack ${mode}: verify errored: ${v.text.slice(0, 160)}`)
    }
    // clean mallory's rejected item from bob's inbox for the next iteration
    await call(B, `/api/doc/inbox/${item2.id}`, { token: bob, method: 'DELETE' })
  }  // ---- Act 5: audit trail ----------------------------------------------------
  head('Act 5 · Audit ledger records everything')
  const events = await call(A, '/api/audit/events?limit=50', { method: 'GET' })
  const kinds = {}
  for (const e of events.json?.entries ?? []) kinds[e.kind] = (kinds[e.kind] ?? 0) + 1
  ok(`ledger on A: ${JSON.stringify(kinds)} (root ${events.json.root?.slice(0, 12)}…)`)
  const eventsC = await call(C, '/api/audit/events?limit=50', { method: 'GET' })
  const attacksC = (eventsC.json?.entries ?? []).filter(e => e.kind === 'attack')
  if (attacksC.length >= 4) ok(`Mallory's ${attacksC.length} attack attempts are on Laptop C's permanent record`)
  else bad(`expected >= 4 attack events on C, saw ${attacksC.length}`)
  const rejectsB = await call(B, '/api/audit/events?limit=50', { method: 'GET' })
  const rejected = (rejectsB.json?.entries ?? []).filter(e => e.kind === 'verify' && !e.accepted)
  if (rejected.length >= 4) ok(`Bob's ledger recorded ${rejected.length} REJECTED verifications`)
  else bad(`expected >= 4 rejections on B, saw ${rejected.length}`)
  const chainA = await call(A, '/api/audit/verify', { method: 'GET' })
  chainA.json?.ok ? ok(`A chain intact: ${chainA.json.detail}`) : bad(`A chain BROKEN: ${chainA.json.detail}`)
  const chainB = await call(B, '/api/audit/verify', { method: 'GET' })
  chainB.json?.ok ? ok(`B chain intact: ${chainB.json.detail}`) : bad(`B chain BROKEN: ${chainB.json.detail}`)

  // ---- Act 6: 5 MB document ---------------------------------------------------
  head('Act 6 · 5 MB document round-trip (Alice → Bob)')
  const big = Buffer.alloc(5 * 1024 * 1024, 0x5A) // 5 MB of 'Z'
  const bigSeal = await call(A, '/api/doc/seal', {
    token: alice,
    body: { name: 'big-report.bin', content_b64: big.toString('base64'), mime: 'application/octet-stream' },
  })
  if (bigSeal.json?.container_b64) ok(`sealed 5 MB (${(bigSeal.json.size / 1048576).toFixed(2)} MB)`)
  else { bad(`5MB seal failed: ${JSON.stringify(bigSeal.json)}`); return }
  const bigSend = await call(A, '/api/doc/send', {
    token: alice,
    body: { container_b64: bigSeal.json.container_b64, peer_url: B_PEER, to_user: 'bob', from_label: 'alice' },
  })
  if (bigSend.json?.delivered) ok('5 MB container delivered laptop-to-laptop')
  else bad(`5MB send: ${JSON.stringify(bigSend.json)}`)
  const bigInbox = await call(B, '/api/doc/inbox', { token: bob, method: 'GET' })
  const bigItem = bigInbox.json?.items?.at(-1)
  if (!bigItem) { bad(`inbox: HTTP ${bigInbox.status} ${bigInbox.text.slice(0, 120)}`); return }
  const bigVerify = await call(B, '/api/doc/inbox/verify', { token: bob, body: { id: bigItem.id } })
  passedOf(bigVerify.json?.outcome)
    ? ok(`5 MB verified on Bob's laptop: ${bigVerify.json.outcome.payloadScheme}`)
    : bad(`5 MB verify: ${JSON.stringify(bigVerify.json?.outcome ?? bigVerify.json)}`)

  // ---- Act 7: user-to-user on one server --------------------------------------
  head('Act 7 · alice → bob… wait, bob lives on B. alice → mallory (same-server delivery)')
  const mallRegB = await call(B, '/api/auth/register', { body: { username: 'malloryB', password: 'evil-again7' } })
  const mallB = (await call(B, '/api/auth/login', { body: { username: 'malloryB', password: 'evil-again7' } })).json.token
  if (!mallB) { bad('malloryB login failed'); return }
  const localSend = await call(B, '/api/doc/send', {
    token: mallB,
    body: { container_b64: containerB64, to_user: 'bob', from_label: 'malloryB' },
  })
  localSend.json?.delivered
    ? ok(`user-addressed delivery works: ${localSend.json.summary}`)
    : bad(`to_user delivery failed: ${JSON.stringify(localSend.json)}`)

  console.log(`\n——— E2E complete: ${step} acts ———`)
}

main().catch((e) => { console.error('E2E crashed:', e); process.exit(1) })
