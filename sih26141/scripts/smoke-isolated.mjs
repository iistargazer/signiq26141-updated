// Isolated smoke test — Team Prometheus verification pass, Sept 29, 2026.
// Run ONLY against a scratch server instance (isolated data files via env vars).
// Usage: SMOKE_BASE=http://127.0.0.1:8090 node scripts/smoke-isolated.mjs
const BASE = process.env.SMOKE_BASE || 'http://127.0.0.1:8090'
const SEED = 424242

let pass = 0, fail = 0
const failures = []
function ok(s) { pass++; console.log(`  ✓ ${s}`) }
function bad(s) { fail++; failures.push(s); console.log(`  ✗ ${s}`) }
function head(s) { console.log(`\n——— ${s} ———`) }

async function call(path, { method = 'POST', token, body } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { /* non-JSON */ }
  return { status: res.status, json, text }
}

const passedOf = (o) => !!o && o.format_ok && o.authentic && o.integrity && o.key_match

async function main() {
  head('1 · Health')
  const h = await call('/api/health', { method: 'GET' })
  h.status === 200 ? ok(`health: ${JSON.stringify(h.json ?? h.text).slice(0, 60)}`) : bad(`health HTTP ${h.status}`)

  head('2 · Accounts (scratch instance — fresh users)')
  const tokens = {}
  for (const [name, pw] of [['alice', 'smoke-alice1'], ['bob', 'smoke-bob22'], ['mallory', 'smoke-mall3']]) {
    const r = await call('/api/auth/register', { body: { username: name, password: pw } })
    ;(r.status === 200 || r.json?.error?.includes('taken'))
      ? ok(`registered '${name}'`)
      : bad(`register '${name}': ${JSON.stringify(r.json).slice(0, 100)}`)
    const l = await call('/api/auth/login', { body: { username: name, password: pw } })
    tokens[name] = l.json?.token
    tokens[name] ? ok(`login '${name}' → bearer token`) : bad(`login '${name}' failed`)
  }

  head('3 · Seeded QKD key distillation (same seed → same session key)')
  for (const name of ['alice', 'bob']) {
    const run = await call('/api/run', { token: tokens[name], body: { key_length: 3000, seed: SEED, pace_ms: 0 } })
    const secure = run.json?.results?.find(r => r.scenario === 'secure')
    const got = run.json?.results?.some(r => r.is_authentic && r.channel_class === 'secure')
    got ? ok(`${name} distilled a session key (QBER ${((secure?.qber ?? 0) * 100).toFixed(2)}%)`)
        : bad(`${name} no session key: ${JSON.stringify(run.json).slice(0, 160)}`)
  }

  head('4 · Seal + same-server delivery + verify')
  const docText = 'SMOKE TEST — Team Prometheus isolated verification document.'
  const b64 = s => Buffer.from(s, 'utf8').toString('base64')
  const seal = await call('/api/doc/seal', { token: tokens.alice, body: { name: 'smoke-doc.txt', content_b64: b64(docText), mime: 'text/plain' } })
  const containerB64 = seal.json?.container_b64
  containerB64 ? ok(`sealed 'smoke-doc.txt' (${seal.json.size} B, sha ${seal.json.sha256?.slice(0, 12)}…)`): bad(`seal failed: ${JSON.stringify(seal.json).slice(0, 140)}`)

  const send = await call('/api/doc/send', { token: tokens.alice, body: { container_b64: containerB64, to_user: 'bob', from_label: 'alice' } })
  send.json?.delivered ? ok(`delivered alice → bob: ${send.json.summary}`) : bad(`send failed: ${JSON.stringify(send.json).slice(0, 140)}`)

  const inbox = await call('/api/doc/inbox', { token: tokens.bob, method: 'GET' })
  const item = inbox.json?.items?.at(-1)
  item ? ok(`bob's inbox: ${inbox.json.total} item(s), latest '${item.meta?.name}' from ${item.from_peer}`) : bad('bob inbox empty')

  const bobVerify = await call('/api/doc/inbox/verify', { token: tokens.bob, body: { id: item.id } })
  passedOf(bobVerify.json?.outcome) ? ok(`BOB ACCEPTED genuine: ${bobVerify.json.outcome.note}`) : bad(`genuine verify failed: ${JSON.stringify(bobVerify.json?.outcome ?? bobVerify.json).slice(0, 160)}`)

  head('5 · Tamper battery — every forgery must be REJECTED')
  for (const mode of ['tamper_bytes', 'swap_meta', 'reseal', 'truncate']) {
    const atk = await call('/api/doc/attack', { token: tokens.mallory, body: { container_b64: containerB64, mode, from_label: 'mallory' } })
    if (!atk.json?.container_b64) { bad(`attack ${mode} could not build container: ${JSON.stringify(atk.json).slice(0, 100)}`); continue }
    const fwd = await call('/api/doc/send', { token: tokens.mallory, body: { container_b64: atk.json.container_b64, to_user: 'bob', from_label: 'mallory' } })
    if (!fwd.json?.delivered) { bad(`attack ${mode} forward failed: ${JSON.stringify(fwd.json).slice(0, 100)}`); continue }
    const ib = await call('/api/doc/inbox', { token: tokens.bob, method: 'GET' })
    const it = ib.json?.items?.at(-1)
    const v = await call('/api/doc/inbox/verify', { token: tokens.bob, body: { id: it.id } })
    const out = v.json?.outcome
    out && !passedOf(out) ? ok(`${mode} → REJECTED: ${out.note}`) : bad(`${mode} ACCEPTED — SECURITY FAILURE: ${JSON.stringify(out).slice(0, 120)}`)
    await call(`/api/doc/inbox/${it.id}`, { token: tokens.bob, method: 'DELETE' })
  }

  head('6 · Consensus ring — k−1 locked, k-of-m opens')
  const tag = String(Date.now() % 100000)
  const RING = ['charlie', 'dave', 'erin'].map(n => `${n}-${tag}`)
  const ringTok = {}
  for (const name of RING) {
    await call('/api/auth/register', { body: { username: name, password: 'ring-smoke1' } })
    ringTok[name] = (await call('/api/auth/login', { body: { username: name, password: 'ring-smoke1' } })).json?.token
    const run = await call('/api/run', { token: ringTok[name], body: { key_length: 3000, seed: SEED, pace_ms: 0 } })
    run.json?.results?.some(r => r.is_authentic) ? ok(`${name} distilled the shared key`) : bad(`${name} key distillation failed`)
  }
  const ringSend = await call('/api/doc/ring/send', { token: tokens.alice, body: { container_b64: containerB64, members: RING, k: 2 } })
  ringSend.json?.accepted?.length === 3 ? ok(`ring delivered: ${ringSend.json.note}`) : bad(`ring send: ${JSON.stringify(ringSend.json).slice(0, 140)}`)

  const cName = RING[0]
  const cItem = (await call('/api/doc/inbox', { token: ringTok[cName], method: 'GET' })).json?.items?.find(x => x.ring)
  if (!cItem) { bad('charlie has no ring item'); return }
  cItem.ring ? ok(`ring spec present (k=${cItem.ring.k} of ${cItem.ring.members?.length ?? 'm'})`) : bad("charlie's item carries no ring spec")
  const early = await call('/api/doc/open', { token: ringTok[cName], body: { inbox_id: cItem.id } })
  early.status !== 200 && /CONSENSUS GATE/i.test(early.text)
    ? ok(`gate LOCKED before quorum: ${(early.json?.error ?? early.text).slice(0, 90)}`)
    : bad(`early open should be refused: HTTP ${early.status} ${early.text.slice(0, 110)}`)
  for (const member of RING.slice(0, 2)) {
    const at = await call('/api/doc/ring/attest', { token: ringTok[member], body: { member, inbox_id: cItem.id } })
    at.json?.attested ? ok(`${member} attested — tally ${at.json.attested_count}/${at.json.k}${at.json.quorum_ok ? ' → QUORUM' : ''}`) : bad(`${member} attest: ${JSON.stringify(at.json).slice(0, 100)}`)
  }
  const late = await call('/api/doc/open', { token: ringTok[cName], body: { inbox_id: cItem.id } })
  const round = late.json?.content_b64 ? Buffer.from(late.json.content_b64, 'base64').toString('utf8') : null
  late.status === 200 && round === docText ? ok('gate OPEN after quorum — original bytes recovered') : bad(`post-quorum open: HTTP ${late.status} ${late.text.slice(0, 120)}`)

  head('7 · QDS battery — six attack classes, all rejected')
  const preSign = await call('/api/qds/sign', { body: { message: 'smoke battery source' } })
  preSign.json?.signature_hex ? ok(`genuine signature minted (window #${preSign.json.temporal?.window})`) : bad(`sign failed: ${JSON.stringify(preSign.json).slice(0, 120)}`)
  const battery = await call('/api/qds/attacks', { method: 'GET' })
  const byKind = {}
  for (const o of battery.json ?? []) byKind[o.kind] = o
  for (const kind of ['replay', 'timestamp_forgery', 'forgery', 'impersonation', 'channel_tampering', 'unauthorized_verification']) {
    const o = byKind[kind]
    if (!o) { bad(`battery missing '${kind}'`); continue }
    !o.report?.accepted ? ok(`${kind} → REJECTED: ${(o.report?.reason ?? '').slice(0, 80)}`) : bad(`${kind} ACCEPTED — SECURITY FAILURE`)
  }
  const s1 = await call('/api/qds/sign', { body: { message: 'persistence one' } })
  const s2 = await call('/api/qds/sign', { body: { message: 'persistence two' } })
  const w1 = s1.json?.temporal?.window, w2 = s2.json?.temporal?.window
  w2 > w1 ? ok(`notary clock monotone: ${w1} → ${w2}`) : bad(`window did not advance: ${w1} → ${w2}`)

  head('8 · QDS metrics — detection rates + false-accept rates (PS clause 6)')
  const m = await call('/api/qds/metrics?trials=120&seed=42', { method: 'GET' })
  const tp = m.json?.teleport, ss = m.json?.six_state
  if (!tp?.confusion || !ss?.confusion) { bad(`metrics shape unexpected: ${JSON.stringify(m.json).slice(0, 200)}`); return }
  // API returns raw confusion counts; rates are derived (same formulas as qds/src/metrics.rs).
  const rates = (c) => {
    const total = c.true_negatives + c.true_positives + c.false_positives + c.false_negatives
    const attacks = c.true_positives + c.false_negatives
    const legit = c.true_negatives + c.false_positives
    const acc = total ? (c.true_negatives + c.true_positives) / total : 0
    const tpr = attacks ? c.true_positives / attacks : 0
    const far = attacks ? c.false_negatives / attacks : 0   // false-ACCEPT rate = missed attacks
    const fpr = legit ? c.false_positives / legit : 0       // false-alarm rate over legitimate events
    return `acc ${(acc * 100).toFixed(1)}% · TPR ${(tpr * 100).toFixed(1)}% · FAR-accept ${(far * 100).toFixed(1)}% · FPR ${(fpr * 100).toFixed(1)}%`
  }
  ok(`teleport: ${rates(tp.confusion)} · forgery 4^-(qλ)=${tp.theoretical_forgery_probability?.toExponential(2)} empirical=${tp.empirical_forgery_probability}`)
  ok(`six-state: ${rates(ss.confusion)}`)
  ok(`per-class detection: ${Object.entries(ss.detection_by_class ?? {}).map(([k, v]) => `${k}=${((v.detected / Math.max(1, v.detected + v.missed)) * 100).toFixed(0)}%`).join(' · ')}`)
  const accOf = (c) => (c.true_negatives + c.true_positives) / Math.max(1, c.true_negatives + c.true_positives + c.false_positives + c.false_negatives)
  accOf(tp.confusion) > 0.99 && accOf(ss.confusion) > 0.99 ? ok('accuracy > 0.99 for both schemes (matches unit-test assertions)') : bad(`accuracy below 0.99: tp=${accOf(tp.confusion).toFixed(4)} ss=${accOf(ss.confusion).toFixed(4)}`)
  tp.confusion.false_negatives === 0 && ss.confusion.false_negatives === 0 ? ok('false-accept rate = 0 over the seeded battery (no missed attacks)') : bad(`missed attacks: tp FN=${tp.confusion.false_negatives} ss FN=${ss.confusion.false_negatives}`)
  ok(`timings: sign ${tp.timing?.mean_sign_us?.toFixed(0)}µs · verify ${tp.timing?.mean_verify_us?.toFixed(0)}µs (machine-specific)`)

  head('9 · Bounds engine + audit ledger')
  const b = await call('/api/stats/bounds', { method: 'GET' })
  b.status === 200 ? ok(`stats/bounds OK: ${JSON.stringify(b.json).slice(0, 80)}`) : bad(`stats/bounds HTTP ${b.status}`)
  const key = await call('/api/doc/qds/key', { token: tokens.alice, body: {} })
  key.json?.key_commitment ? ok(`six-state QDS key derived (commitment ${key.json.key_commitment.slice(0, 12)}…)`) : bad(`qds/key: ${JSON.stringify(key.json).slice(0, 120)}`)
  const ev = await call('/api/audit/events?limit=50', { method: 'GET' })
  const kinds = {}
  for (const e of ev.json?.entries ?? []) kinds[e.kind] = (kinds[e.kind] ?? 0) + 1
  ok(`ledger: ${ev.json?.total ?? '?'} events, kinds ${JSON.stringify(kinds)}, root ${ev.json?.root?.slice(0, 12)}…`)
  const chain = await call('/api/audit/verify', { method: 'GET' })
  chain.json?.ok ? ok(`chain intact: ${chain.json.detail}`) : bad(`chain BROKEN: ${chain.json.detail}`)
  const seq2 = (ev.json?.entries ?? []).at(-1)?.seq ?? 2
  const proof = await call(`/api/audit/proof?seq=${seq2}`, { method: 'GET' })
  proof.json?.proof || proof.json?.siblings || proof.json?.hashes
    ? ok(`inclusion proof for seq ${seq2}: ${JSON.stringify(proof.json).slice(0, 90)}…`)
    : bad(`proof: HTTP ${proof.status} ${proof.text.slice(0, 110)}`)
  const exp = await call('/api/audit/export', { method: 'GET' })
  exp.status === 200 ? ok(`audit export: ${exp.text.length} bytes`) : bad(`export HTTP ${exp.status}`)

  head('10 · Attack theater (staged capture → tamper → forward → rejection)')
  const th = await call('/api/doc/attack-theater', { body: { container_b64: containerB64, attacker: 'mallory', victim: 'bob', mode: 'tamper_bytes' } })
  th.status === 200 ? ok(`theater staged: ${Object.keys(th.json ?? {}).slice(0, 8).join(', ')}`) : bad(`theater HTTP ${th.status} ${th.text.slice(0, 120)}`)

  console.log(`\n——— SMOKE COMPLETE: ${pass} passed, ${fail} failed ———`)
  if (fail) { console.log('FAILURES:\n' + failures.map(f => `  - ${f}`).join('\n')); process.exit(1) }
}

main().catch((e) => { console.error('SMOKE crashed:', e); process.exit(1) })
