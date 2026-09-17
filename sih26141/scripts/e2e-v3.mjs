// Live end-to-end verification of the v3 feature set across three "laptops":
//   A = http://127.0.0.1:8080 (Alice)  B = http://127.0.0.1:8081 (Bob)
//   C = http://127.0.0.1:8083 (Mallory)
// Covers: QDS key derivation, QDS-signed seal, unlock/download, outbox
// separation, inbox delete, wire proof, attack theater, cross-LAN relay,
// and the dev-token audit clear (disabled without the env token).

const A = 'http://127.0.0.1:8080'
const B = 'http://127.0.0.1:8081'
const C = 'http://127.0.0.1:8083'

let pass = 0, fail = 0
function check(ok, label, extra = '') {
  if (ok) { pass++; console.log(`  ✓ ${label}${extra ? ' — ' + extra : ''}`) }
  else { fail++; console.log(`  ✗ ${label}${extra ? ' — ' + extra : ''}`) }
}
async function call(base, path, method, token, body) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { /* non-JSON */ }
  return { status: res.status, json, text }
}
const post = (base, path, token, body) => call(base, path, 'POST', token, body)
const get = (base, path, token) => call(base, path, 'GET', token)

const stamp = Date.now().toString(36)
const u = (n) => `${n}_${stamp}`

async function register(base, name) {
  const pw = 'demo-passphrase-1'
  await post(base, '/api/auth/register', null, { username: name, password: pw })
  const login = await post(base, '/api/auth/login', null, { username: name, password: pw })
  if (login.status !== 200 || !login.json?.token) throw new Error(`login ${name}: ${login.text}`)
  return login.json.token
}

function makeFileB64(kb, fill) {
  const bytes = new Uint8Array(kb * 1024)
  for (let i = 0; i < bytes.length; i++) bytes[i] = (fill + i) & 0xff
  return Buffer.from(bytes).toString('base64')
}

console.log('——— ACT 0 · accounts')
const alice = await register(A, u('alice'))
const bob = await register(B, u('bob'))
const mallory = await register(C, u('mallory'))
check(!!alice && !!bob && !!mallory, 'three accounts registered on three laptops')

console.log('——— ACT 1 · QDS key derivation (six-state QDS session, shared seed)')
const keyResp = await post(A, '/api/doc/qds/key', alice, { seed: 424242 })
check(keyResp.status === 200, 'POST /api/doc/qds/key', `status ${keyResp.status}`)
check((keyResp.json?.conclusive_bits ?? 0) > 50, 'session produced conclusive bits',
  `${keyResp.json?.conclusive_bits} bits / ${keyResp.json?.n_pulses} qubits`)
check((keyResp.json?.provenance ?? '').includes('six-state QDS'), 'provenance names the QDS session')
// Bob's laptop derives the SAME key from the same seed — the cross-laptop handshake.
const keyBob = await post(B, '/api/doc/qds/key', bob, { seed: 424242 })
check(keyBob.json?.key_commitment === keyResp.json?.key_commitment,
  'Bob (laptop B) derived the SAME key from the shared seed — cross-laptop handshake ✓')

console.log('——— ACT 2 · QDS-signed seal')
const DOC = makeFileB64(64, 7)
const seal = await post(A, '/api/doc/seal', alice, { name: 'treaty.pdf', content_b64: DOC, mime: 'application/pdf' })
check(seal.status === 200, 'seal succeeded', `${seal.json?.size} bytes`)
check(seal.json?.qds_signature === true, 'teleport-QDS signature attached to the container')
check(seal.json?.key_source === 'qds', 'sealing key provenance = six-state QDS')
const containerB64 = seal.json?.container_b64

console.log('——— ACT 3 · unlock & download the ORIGINAL (two-factor)')
const open = await post(A, '/api/doc/open', alice, { container_b64: containerB64 })
check(open.status === 200, 'POST /api/doc/open', open.json ? '' : open.text.slice(0, 120))
check(open.json?.content_b64 === DOC, 'recovered bytes == original bytes (the doc is OPENABLE)')
check(open.json?.qds_check?.accepted === true, 'embedded QDS signature re-verified via Trent',
  open.json?.qds_check?.verdict)
check((open.json?.unlocked_via ?? '').includes('teleport-QDS'), 'unlocked_via names both factors')
// a genuinely wrong key must NOT open (mallory derives a DIFFERENT seed)
await post(C, '/api/doc/qds/key', mallory, { seed: 777777 })
const openMallory = await post(C, '/api/doc/open', mallory, { container_b64: containerB64 })
check(openMallory.status !== 200, 'wrong-key user cannot open the document', `status ${openMallory.status}`)
// Bob shares the seeded session key by design (the handshake), so he CAN open:
const openBobOk = await post(B, '/api/doc/open', bob, { container_b64: containerB64 })
check(openBobOk.status === 200 && openBobOk.json?.content_b64 === DOC,
  'key-sharing peer (Bob, same seed) opens it too — the handshake works both ways')

console.log('——— ACT 4 · real P2P: Alice (A) → Bob (B) laptop-to-laptop')
const send = await post(A, '/api/doc/send', alice, {
  container_b64: containerB64, to_user: u('bob'), peer_url: B, from_label: u('alice'),
})
check(send.status === 200 && send.json?.delivered === true, 'cross-laptop delivery accepted',
  send.json?.destination)
const outboxId = send.json?.outbox_id
check(Number.isInteger(outboxId), 'sender got an OUTBOX record', `outbox #${outboxId}`)
const inboxBob = await get(B, '/api/doc/inbox?full=false', bob)
const item = inboxBob.json?.items?.at(-1)
check(!!item, 'container arrived in Bob’s INBOX (not the sender’s)')

console.log('——— ACT 5 · outbox vs inbox separation')
const outboxAlice = await get(A, '/api/doc/outbox', alice)
check(outboxAlice.json?.total >= 1, 'Alice’s outbox lists the sent document')
const inboxAlice = await get(A, '/api/doc/inbox?full=false', alice)
check((inboxAlice.json?.total ?? 0) === 0, 'Alice’s inbox is EMPTY (sender copies never pollute the inbox)')

console.log('——— ACT 6 · Bob downloads the received document')
const openInbox = await post(B, '/api/doc/open', bob, { inbox_id: item.id })
check(openInbox.status === 200, 'Bob opened the received container')
check(openInbox.json?.content_b64 === DOC, 'Bob recovered the ORIGINAL file bytes over P2P')
check(openInbox.json?.qds_check?.accepted === true, 'QDS signature verified on Bob’s side too')

console.log('——— ACT 7 · wire proof (what crossed the network)')
const proof = await get(B, `/api/doc/wire-proof?inbox_id=${item.id}`, bob)
check(proof.status === 200, 'GET /api/doc/wire-proof')
check(proof.json?.ciphertext_entropy > 7.5, 'wire entropy ≈ random (≈8.0)',
  `${proof.json?.ciphertext_entropy} bits/byte`)
check((proof.json?.verdict ?? '').startsWith('PROTECTED'), 'wire verdict: PROTECTED',
  proof.json?.verdict?.slice(0, 60))

console.log('——— ACT 8 · inbox delete')
const del = await call(B, `/api/doc/inbox/${item.id}`, 'DELETE', bob)
check(del.status === 200 && del.json?.deleted === item.id, 'DELETE /api/doc/inbox/{id} works')
const inboxAfter = await get(B, '/api/doc/inbox?full=false', bob)
check(!inboxAfter.json?.items?.some((i) => i.id === item.id), 'item gone from the inbox')

console.log('——— ACT 9 · attack theater (live staged rejection)')
// Fresh seal for Mallory to capture.
const seal2 = await post(A, '/api/doc/seal', alice, { name: 'budget.xlsx', content_b64: makeFileB64(32, 3) })
// The theater victim lives on the same server (local workspace) but holds
// the same seeded key, so the rejection is CRYPTOGRAPHIC, not just "no key".
const BOB_LOCAL = u('boblocal')
const bobLocal = await register(A, BOB_LOCAL)
await post(A, '/api/doc/qds/key', bobLocal, { seed: 424242 })
const theater = await post(A, '/api/doc/attack-theater', mallory, {
  container_b64: seal2.json?.container_b64, mode: 'tamper_bytes', victim: u('boblocal'), attacker: u('mallory'),
})
check(theater.status === 200, 'POST /api/doc/attack-theater', theater.json ? '' : theater.text.slice(0, 120))
check(theater.json?.steps?.length === 6, 'six staged steps', theater.json?.steps?.map((s) => s.title).join(' | '))
check(theater.json?.rejected === true, 'victim REJECTED the tampered container', theater.json?.victim_verdict?.note?.slice(0, 60))
check((theater.json?.victim_verdict?.note ?? '').includes('GCM') || (theater.json?.victim_verdict?.note ?? '').includes('HMAC') || (theater.json?.victim_verdict?.note ?? '').includes('commitment'),
  'rejection names the cryptographic check that failed')
const evi = theater.json?.steps?.find((s) => s.title === 'Interception')?.evidence
check((evi?.ciphertext_entropy ?? 0) > 7.5, 'theater shows the unreadable wire (entropy)',
  `${evi?.ciphertext_entropy}`)
const victimInbox = await get(A, '/api/doc/inbox?full=false', bobLocal)
const bad = victimInbox.json?.items?.at(-1)
check(bad?.verified === false, 'the forwarded forgery sits in the victim’s inbox flagged ✗')

console.log('——— ACT 10 · cross-LAN relay (claim-code, different networks)')
const dep = await post(A, '/api/doc/relay/deposit', alice, {
  container_b64: seal2.json?.container_b64, to_user: BOB_LOCAL, from_label: u('alice'),
})
check(dep.status === 200 && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(dep.json?.claim_code ?? ''),
  'deposit parked with a claim code', dep.json?.claim_code)
// Mallory tries to claim it — must be refused (addressed to boblocal).
const wrongClaim = await post(A, '/api/doc/relay/claim', mallory, { claim_code: dep.json.claim_code, expected_user: BOB_LOCAL })
check(wrongClaim.status !== 200, 'a different user cannot consume the code')
const claim = await post(A, '/api/doc/relay/claim', bobLocal, { claim_code: dep.json.claim_code, expected_user: BOB_LOCAL })
check(claim.status === 200 && claim.json?.accepted === true, 'recipient claimed the deposit from the relay',
  claim.json?.note?.slice(0, 60))
const relayInbox = await get(A, '/api/doc/inbox?full=false', bobLocal)
check(relayInbox.json?.items?.some((i) => i.from_peer?.includes('relay')), 'claimed document landed in the inbox')

console.log('——— ACT 11 · dev-token audit clear (gated)')
const clearNoToken = await post(A, '/api/audit/clear', null, { developer_token: '', confirm: 'CLEAR' })
check(clearNoToken.status === 400, 'clearing WITHOUT a token is refused (no DEVELOPER_TOKEN env)',
  clearNoToken.json?.error?.slice(0, 50))
const clearBad = await post(A, '/api/audit/clear', null, { developer_token: 'wrong-token', confirm: 'CLEAR' })
check(clearBad.status === 400, 'a wrong token is refused', clearBad.json?.error?.slice(0, 50))

console.log('——— ACT 12 · outbox delete')
const delOut = await call(A, `/api/doc/outbox/${outboxId}`, 'DELETE', alice)
check(delOut.status === 200, 'DELETE /api/doc/outbox/{id} works')

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`)
process.exit(fail > 0 ? 1 : 0)
