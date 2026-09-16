// Cross-account multiparty threshold E2E:
// alice seals 2-of-3 → distributes shares to carol/dave/eve accounts →
// carol pledges (1/2, unlock REJECTED) → dave pledges (2/2) → unlock ✓.
const A = 'http://127.0.0.1:8080'
let step = 0
const head = (s) => { step++; console.log(`\n——— ${s} ———`) }
const ok = (s) => console.log(`  ✓ ${s}`)
const bad = (s) => console.log(`  ✗ ${s}`)

async function call(path, { method = 'POST', token, body } = {}) {
  const res = await fetch(`${A}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { /* ignore */ }
  return { status: res.status, json, text }
}

const passedOf = (o) => !!o && o.format_ok && o.authentic && o.integrity && o.key_match

async function main() {
  head('Act 1 · Four accounts')
  const creds = [
    ['alice', 'wonderland9'],
    ['carol', 'carol-pass-1'],
    ['dave', 'dave-pass-01'],
    ['eve', 'eve-listens-9'],
  ]
  const tokens = {}
  for (const [u, p] of creds) {
    const reg = await call('/api/auth/register', { body: { username: u, password: p } })
    if (reg.status === 200 || reg.json?.error?.includes('taken')) ok(`'${u}' registered`)
    else bad(`register ${u}: ${reg.text.slice(0, 120)}`)
    tokens[u] = (await call('/api/auth/login', { body: { username: u, password: p } })).json.token
    if (!tokens[u]) bad(`login ${u} failed`)
  }

  head('Act 2 · Alice derives a key and seals 2-of-3')
  await call('/api/run', { token: tokens.alice, body: { key_length: 3000, seed: 777, pace_ms: 0 } })
  const seal = await call('/api/doc/seal', {
    token: tokens.alice,
    body: {
      name: 'board-resolution.txt',
      content_b64: Buffer.from('Board resolution #2026-114: approved unanimously.', 'utf8').toString('base64'),
      use_quorum: true,
      quorum_threshold: 2,
      quorum_shares: 3,
    },
  })
  if (!seal.json?.container_b64) { bad(`seal: ${seal.text.slice(0, 150)}`); return }
  ok(`sealed '${seal.json.name}' with quorum ${seal.json.quorum[0]}-of-${seal.json.quorum[1]}`)

  head('Act 3 · Distribute shares to carol / dave / eve accounts')
  const dist = await call('/api/doc/quorum/distribute', {
    token: tokens.alice,
    body: { users: ['carol', 'dave', 'eve'] },
  })
  if (dist.status !== 200) { bad(`distribute: ${dist.text.slice(0, 150)}`); return }
  ok(`assignments: ${dist.json.assignments.map(([u, x]) => `${u}←OFF-${x}`).join(', ')}`)

  head('Act 4 · carol pledges (1 of 2) — unlock must REJECT')
  const p1 = await call('/api/doc/quorum/pledge', { token: tokens.carol })
  if (p1.status !== 200) { bad(`pledge carol: ${p1.text.slice(0, 150)}`); return }
  ok(`carol pledged OFF-${p1.json.officer_x} → ${p1.json.pledges_received}/${p1.json.threshold}`)
  const early = await call('/api/doc/quorum/unlock', { token: tokens.alice, body: { container_b64: seal.json.container_b64, shares: [] } })
  if (early.json?.outcome === null && early.json?.enough_shares === false) {
    ok(`early unlock REJECTED: ${early.json.recognized_officers.length} pledge(s) < ${early.json.threshold}`)
  } else bad(`early unlock should have been rejected: ${early.text.slice(0, 150)}`)

  head('Act 5 · dave pledges (2 of 2) — unlock must SUCCEED')
  const p2 = await call('/api/doc/quorum/pledge', { token: tokens.dave })
  ok(`dave pledged OFF-${p2.json.officer_x} → ${p2.json.pledges_received}/${p2.json.threshold}${p2.json.quorum_met ? ' — QUORUM MET' : ''}`)
  const unlock = await call('/api/doc/quorum/unlock', { token: tokens.alice, body: { container_b64: seal.json.container_b64, shares: [] } })
  if (passedOf(unlock.json?.outcome)) {
    ok(`CROSS-ACCOUNT UNLOCK ✓ — ${unlock.json.outcome.unlocked_via}: ${unlock.json.outcome.note}`)
  } else bad(`pledged unlock failed: ${unlock.text.slice(0, 200)}`)

  head('Act 6 · eve checks her custody card')
  const eveQ = await call('/api/doc/quorum', { token: tokens.eve, method: 'GET' })
  if (eveQ.json?.held_share) ok(`eve holds OFF-${eveQ.json.held_share.x} from ${eveQ.json.held_share.from} (never sees the bytes)`)
  else bad(`eve custody missing: ${eveQ.text.slice(0, 120)}`)

  head('Act 7 · Audit ledger')
  const ev = await call('/api/audit/events?limit=30', { method: 'GET' })
  const kinds = {}
  for (const e of ev.json?.entries ?? []) if (e.kind === 'quorum') kinds[e.label] = (kinds[e.label] ?? 0) + 1
  ok(`quorum events: ${JSON.stringify(kinds)}`)
  const cross = (ev.json?.entries ?? []).some((e) => e.detail.includes('CROSS-ACCOUNT'))
  cross ? ok('CROSS-ACCOUNT unlock recorded in the ledger') : bad('cross-account unlock missing from ledger')

  console.log(`\n——— Multiparty E2E complete: ${step} acts ———`)
}

main().catch((e) => { console.error('crashed:', e); process.exit(1) })
