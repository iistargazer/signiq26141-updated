import type { AuditEntry, AuditExportResponse, InclusionProof } from './api'

export interface AuditVerificationCheck {
  label: string
  valid: boolean
  detail: string
}

export interface AuditVerificationReport {
  valid: boolean
  entryCount: number
  root: string | null
  validProofs: number
  checks: AuditVerificationCheck[]
}

type PortableBundle = Partial<AuditExportResponse> & {
  entries?: AuditEntry[]
  proofs?: InclusionProof[]
}

type Bytes = Uint8Array<ArrayBuffer>
const encoder = new TextEncoder()

function bytes(value: string): Bytes {
  return encoder.encode(value)
}

function concat(parts: Bytes[]): Bytes {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.byteLength
  }
  return out
}

function hexBytes(value: string): Bytes | null {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) return null
  const out = new Uint8Array(value.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
  return out
}

function hex(value: ArrayBuffer): string {
  return Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function sha256(value: Bytes): Promise<string> {
  const copy = new Uint8Array(value.byteLength)
  copy.set(value)
  return hex(await crypto.subtle.digest('SHA-256', copy))
}

function u64(value: number, littleEndian: boolean): Bytes {
  const out = new Uint8Array(new ArrayBuffer(8))
  new DataView(out.buffer).setBigUint64(0, BigInt(value), littleEndian)
  return out
}

function frame(value: Bytes): Bytes {
  return concat([u64(value.byteLength, false), value])
}

async function entryHash(entry: AuditEntry, previous: string): Promise<string> {
  const fields: Bytes[] = [
    u64(entry.seq, true),
    bytes(entry.ts),
    bytes(entry.kind),
    bytes(entry.label),
    new Uint8Array([entry.accepted ? 1 : 0]),
    bytes(entry.detail),
    bytes(entry.payload_hash),
    bytes(previous),
  ]
  const version = entry.hash_v ?? 1
  return sha256(concat(version >= 2 ? [bytes('AUD1'), ...fields.map(frame)] : fields))
}

async function treeRoot(leaves: string[]): Promise<string | null> {
  if (!leaves.length) return null
  let level = leaves
  while (level.length > 1) {
    const parents: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      parents.push(await sha256(concat([new Uint8Array([1]), bytes(level[i]), bytes(level[i + 1] ?? level[i])])))
    }
    level = parents
  }
  return level[0]
}

async function proofMatches(proof: InclusionProof, expectedRoot: string): Promise<boolean> {
  if (!proof || typeof proof.leaf_hash !== 'string' || proof.root !== expectedRoot || !hexBytes(proof.leaf_hash)) return false
  let current = proof.leaf_hash
  for (const sibling of proof.siblings ?? []) {
    const split = sibling.indexOf(':')
    if (split < 0) return false
    const side = sibling.slice(0, split)
    const siblingHash = sibling.slice(split + 1)
    if ((side !== 'L' && side !== 'R') || !hexBytes(siblingHash) || !hexBytes(current)) return false
    current = await sha256(concat([
      new Uint8Array([1]),
      bytes(side === 'L' ? siblingHash : current),
      bytes(side === 'L' ? current : siblingHash),
    ]))
  }
  return current === expectedRoot
}

function isAuditEntry(value: unknown): value is AuditEntry {
  if (!value || typeof value !== 'object') return false
  const entry = value as Partial<AuditEntry>
  return Number.isSafeInteger(entry.seq) && typeof entry.ts === 'string' &&
    typeof entry.kind === 'string' && typeof entry.label === 'string' &&
    typeof entry.accepted === 'boolean' && typeof entry.detail === 'string' &&
    typeof entry.payload_hash === 'string' && typeof entry.leaf_hash === 'string'
}

/** Recompute the complete entry hash chain, Merkle root, and every inclusion proof locally. */
export async function verifyAuditBundle(input: unknown): Promise<AuditVerificationReport> {
  const bundle = (input && typeof input === 'object' ? input : {}) as PortableBundle
  const rawEntries: unknown[] = Array.isArray(bundle.entries) ? bundle.entries : []
  const entries = rawEntries.filter(isAuditEntry)
  const rawProofs: unknown[] = Array.isArray(bundle.proofs) ? bundle.proofs : []
  const proofs = rawProofs.filter((proof): proof is InclusionProof => {
    if (!proof || typeof proof !== 'object') return false
    const candidate = proof as Partial<InclusionProof>
    return Number.isSafeInteger(candidate.seq) && typeof candidate.leaf_hash === 'string' &&
      typeof candidate.root === 'string' && Array.isArray(candidate.siblings) &&
      candidate.siblings.every((sibling) => typeof sibling === 'string')
  })
  const root = typeof bundle.root === 'string' ? bundle.root : null
  const checks: AuditVerificationCheck[] = []
  const add = (label: string, valid: boolean, detail: string) => checks.push({ label, valid, detail })
  const entryShapeOk = entries.length === rawEntries.length
  const proofShapeOk = proofs.length === rawProofs.length
  const complete = bundle.format_version === 1 && Number.isSafeInteger(bundle.total) &&
    bundle.total === rawEntries.length && entryShapeOk && proofShapeOk && proofs.length === entries.length

  add(
    'Complete portable snapshot',
    complete,
    complete ? `${entries.length.toLocaleString()} entries and proofs are present.`
      : 'Unsupported format, missing entries/proofs, invalid fields, or count mismatch.',
  )

  if (!globalThis.crypto?.subtle) {
    add('Local cryptographic verification', false, 'Web Crypto SHA-256 is unavailable in this browser context.')
    return { valid: false, entryCount: rawEntries.length, root, validProofs: 0, checks }
  }
  if (!entryShapeOk) {
    add('Hash-chain integrity', false, 'One or more entries have invalid fields.')
    add('Merkle root', false, 'Cannot rebuild a Merkle tree from malformed entries.')
    add('Per-entry inclusion proofs', false, 'Cannot validate proofs for malformed entries.')
    add('Server verdict matches local check', false, 'Cannot compare verdicts with malformed entries.')
    return { valid: false, entryCount: rawEntries.length, root, validProofs: 0, checks }
  }

  let previous = ''
  let chainValid = true
  let chainDetail = 'Every sequence number and leaf hash recomputes from the exported fields.'
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!
    if (entry.seq !== i + 1) {
      chainValid = false
      chainDetail = `Sequence gap at position ${i + 1}: found #${entry.seq}.`
      break
    }
    const expected = await entryHash(entry, previous)
    if (expected !== entry.leaf_hash.toLowerCase()) {
      chainValid = false
      chainDetail = `Leaf hash mismatch at sequence #${entry.seq}; its fields or predecessor were altered.`
      break
    }
    previous = entry.leaf_hash
  }
  add('Hash-chain integrity', chainValid, chainDetail)

  const computedRoot = await treeRoot(entries.map((entry) => entry.leaf_hash.toLowerCase()))
  const serverVerdict = bundle.chain
  const rootValid = computedRoot === root && serverVerdict != null && serverVerdict.root === computedRoot
  add(
    'Merkle root',
    rootValid && complete,
    rootValid ? `Rebuilt root ${computedRoot ?? '(empty ledger)'}.`
      : `Rebuilt ${computedRoot ?? '(empty ledger)'}, but the bundle declares ${root ?? '(no root)'}.`,
  )

  const entriesBySeq = new Map(entries.map((entry) => [entry.seq, entry]))
  const proofSeqs = new Set<number>()
  let validProofs = 0
  let proofError = ''
  for (const proof of proofs) {
    if (proofSeqs.has(proof.seq)) {
      proofError = 'A proof has a duplicate sequence number.'
      continue
    }
    proofSeqs.add(proof.seq)
    const entry = entriesBySeq.get(proof.seq)
    if (!entry || proof.leaf_hash.toLowerCase() !== entry.leaf_hash.toLowerCase() ||
      !root || !(await proofMatches(proof, root))) {
      proofError ||= `Inclusion proof for sequence #${proof.seq} does not match the exported root.`
      continue
    }
    validProofs++
  }
  const proofsValid = proofShapeOk && validProofs === entries.length && proofs.length === entries.length && complete
  add(
    'Per-entry inclusion proofs',
    proofsValid,
    proofsValid ? `All ${validProofs.toLocaleString()} proofs independently reconstruct the same root.`
      : proofError || `${validProofs} of ${entries.length} entry proofs verified.`,
  )
  const serverChainOk = serverVerdict?.ok === chainValid && serverVerdict?.root === computedRoot && complete
  add(
    'Server verdict matches local check',
    serverChainOk,
    serverChainOk ? `The exported server verdict (${serverVerdict?.ok ? 'intact' : 'broken'}) agrees with the local recomputation.`
      : `The exported server verdict (${serverVerdict?.ok === true ? 'intact' : 'broken or missing'}) disagrees with the local recomputation.`,
  )

  return { valid: checks.every((check) => check.valid), entryCount: rawEntries.length, root, validProofs, checks }
}

export const OFFLINE_AUDIT_VERIFIER_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SigniQ · Offline Audit Verifier</title>
<style>
:root{color-scheme:dark;--bg:#070a12;--panel:#16203a;--inset:#10192e;--text:#ece5d4;--dim:#a89d81;--faint:#8fb0c9;--gold:#c9a45c;--green:#86bf9c;--red:#d67f72;--border:rgba(232,222,196,.2)}
*{box-sizing:border-box}body{margin:0;padding:32px 18px;background:var(--bg);color:var(--text);font:16px Georgia,serif;line-height:1.55}.plate{max-width:820px;margin:auto;background:var(--panel);border:1px solid var(--border);border-top:2px solid var(--gold);padding:26px 30px;box-shadow:0 20px 55px #02040a99}h1{font-weight:500;margin:0;color:var(--text)}.kicker{font:10px monospace;letter-spacing:2px;color:var(--gold);text-transform:uppercase}p{color:var(--dim)}.upload{display:inline-flex;margin:12px 0;padding:10px 16px;border:1px solid var(--gold);border-radius:3px;color:var(--text);font:12px monospace;letter-spacing:1px;text-transform:uppercase;cursor:pointer}.upload input{position:absolute;width:1px;height:1px;opacity:0}.status{margin:16px 0;padding:12px 14px;border:1px solid var(--border);background:var(--inset);font:12px monospace}.status.ok{color:var(--green);border-color:#86bf9c66}.status.bad{color:var(--red);border-color:#d67f7266}code{display:block;padding:10px;background:var(--inset);color:var(--faint);font:11px monospace;overflow-wrap:anywhere}ul{list-style:none;padding:0}li{display:flex;gap:8px;padding:8px 0;border-bottom:1px dotted var(--border);font-size:14px}li b{font:10px monospace;letter-spacing:1px;white-space:nowrap}.ok{color:var(--green)}.bad{color:var(--red)}.fine{font-size:12px;color:var(--dim)}
</style>
</head>
<body><main class="plate">
<div class="kicker">SigniQ · local verifier · no network access</div>
<h1>Portable audit evidence</h1>
<p>Choose a <code style="display:inline;padding:2px 5px">.json</code> evidence bundle. This page recomputes the hash chain, the Merkle root and each entry’s inclusion proof in your browser. No file is uploaded.</p>
<label class="upload">Choose evidence bundle<input id="bundle" type="file" accept=".json,application/json"></label>
<div id="summary" class="status" aria-live="polite">Waiting for a JSON evidence bundle.</div>
<div class="kicker">Published root</div><code id="root">—</code>
<ul id="checks" aria-live="polite"></ul>
<p class="fine">A valid export proves internal consistency against the root included in the bundle. To prove who published that root, compare it with a root obtained through a trusted independent channel. The QKD/QDS protocol itself is a classical software simulation.</p>
</main>
<script>
'use strict';
const input = document.getElementById('bundle');
const summary = document.getElementById('summary');
const checksList = document.getElementById('checks');
const rootOutput = document.getElementById('root');
const encoder = new TextEncoder();
const bytes = value => encoder.encode(value);
const concat = parts => {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const hexBytes = value => {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/i.test(value)) return null;
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const hex = buffer => Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
const sha = value => crypto.subtle.digest('SHA-256', value);
const u64 = (value, little) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), little);
  return out;
};
const frame = value => concat([u64(value.length, false), value]);
async function entryHash(entry, previous) {
  const fields = [u64(entry.seq, true), bytes(entry.ts), bytes(entry.kind), bytes(entry.label), new Uint8Array([entry.accepted ? 1 : 0]), bytes(entry.detail), bytes(entry.payload_hash), bytes(previous)];
  const version = entry.hash_v == null ? 1 : Number(entry.hash_v);
  return hex(await sha(concat(version >= 2 ? [bytes('AUD1'), ...fields.map(frame)] : fields)));
}
async function treeRoot(leaves) {
  if (!leaves.length) return null;
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(hex(await sha(concat([new Uint8Array([1]), bytes(level[i]), bytes(level[i + 1] || level[i])]))));
    level = next;
  }
  return level[0];
}
async function proofValid(proof, root) {
  if (!proof || proof.root !== root || !hexBytes(proof.leaf_hash)) return false;
  let current = proof.leaf_hash;
  for (const item of proof.siblings || []) {
    if (typeof item !== 'string') return false;
    const split = item.indexOf(':');
    if (split < 0) return false;
    const side = item.slice(0, split);
    const sibling = item.slice(split + 1);
    if ((side !== 'L' && side !== 'R') || !hexBytes(sibling) || !hexBytes(current)) return false;
    current = hex(await sha(concat([new Uint8Array([1]), bytes(side === 'L' ? sibling : current), bytes(side === 'L' ? current : sibling)])));
  }
  return current === root;
}
function showCheck(label, valid, detail) {
  const li = document.createElement('li');
  li.className = valid ? 'ok' : 'bad';
  const mark = document.createElement('b');
  mark.textContent = valid ? 'PASS  ' : 'FAIL  ';
  const text = document.createElement('span');
  text.textContent = label + ': ' + detail;
  li.append(mark, text);
  checksList.append(li);
  return valid;
}
async function verify(file) {
  checksList.replaceChildren();
  rootOutput.textContent = '—';
  summary.className = 'status';
  summary.textContent = 'Verifying locally…';
  try {
    const bundle = JSON.parse(await file.text());
    const entries = Array.isArray(bundle.entries) ? bundle.entries : [];
    const proofs = Array.isArray(bundle.proofs) ? bundle.proofs : [];
    const shapeOk = entries.every(e => e && Number.isSafeInteger(e.seq) && typeof e.ts === 'string' && typeof e.kind === 'string' && typeof e.label === 'string' && typeof e.accepted === 'boolean' && typeof e.detail === 'string' && typeof e.payload_hash === 'string' && typeof e.leaf_hash === 'string');
    const proofShapeOk = proofs.every(proof => proof && Number.isSafeInteger(proof.seq) && typeof proof.leaf_hash === 'string' && typeof proof.root === 'string' && Array.isArray(proof.siblings) && proof.siblings.every(item => typeof item === 'string'));
    const complete = bundle.format_version === 1 && Number.isSafeInteger(bundle.total) && bundle.total === entries.length && proofs.length === entries.length && shapeOk && proofShapeOk;
    const results = [showCheck('Complete portable snapshot', complete, complete ? entries.length + ' entries and proofs are present.' : 'Unsupported format, malformed fields, missing proofs, or count mismatch.')];
    if (!shapeOk) {
      results.push(showCheck('Hash-chain integrity', false, 'One or more exported entries have malformed fields.'));
      results.push(showCheck('Merkle root', false, 'Cannot rebuild the tree from malformed entries.'));
      results.push(showCheck('Per-entry inclusion proofs', false, 'Cannot validate proofs for malformed entries.'));
      results.push(showCheck('Server verdict agrees', false, 'Cannot compare the server verdict with malformed entries.'));
      summary.className = 'status bad';
      summary.textContent = 'NOT VERIFIED — inspect the failed checks before relying on this export.';
      return;
    }
    if (!globalThis.crypto || !crypto.subtle) throw new Error('Web Crypto SHA-256 is unavailable in this browser context.');
    let previous = '';
    let chain = true;
    let chainDetail = 'Every sequence and leaf hash recomputes from the exported fields.';
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (entry.seq !== i + 1) { chain = false; chainDetail = 'Sequence gap at position ' + (i + 1) + '.'; break; }
      if (await entryHash(entry, previous) !== entry.leaf_hash.toLowerCase()) { chain = false; chainDetail = 'Leaf hash mismatch at sequence #' + entry.seq + '; fields or predecessor were altered.'; break; }
      previous = entry.leaf_hash;
    }
    results.push(showCheck('Hash-chain integrity', chain, chainDetail));
    const computedRoot = await treeRoot(entries.map(e => e.leaf_hash.toLowerCase()));
    const rootOk = computedRoot === (bundle.root == null ? null : bundle.root) && bundle.chain != null && bundle.chain.root === computedRoot;
    results.push(showCheck('Merkle root', rootOk, rootOk ? 'Rebuilt root ' + (computedRoot || '(empty ledger)') + '.' : 'Rebuilt ' + (computedRoot || '(empty ledger)') + ', declared ' + (bundle.root || '(no root)') + '.'));
    const bySeq = new Map(entries.map(e => [e.seq, e]));
    const seen = new Set();
    let proofCount = 0;
    let proofDetail = '';
    for (const proof of proofs) {
      if (!proofShapeOk || !Number.isSafeInteger(proof.seq) || seen.has(proof.seq)) { proofDetail = 'Invalid or duplicate proof sequence.'; continue; }
      seen.add(proof.seq);
      const entry = bySeq.get(proof.seq);
      if (!entry || proof.leaf_hash.toLowerCase() !== entry.leaf_hash.toLowerCase() || !bundle.root || !(await proofValid(proof, bundle.root))) { proofDetail = 'Proof for sequence #' + proof.seq + ' does not match the exported root.'; continue; }
      proofCount++;
    }
    const allProofs = complete && proofShapeOk && proofCount === entries.length && proofs.length === entries.length;
    results.push(showCheck('Per-entry inclusion proofs', allProofs, allProofs ? 'All ' + proofCount + ' proofs reconstruct the same root.' : proofDetail || proofCount + ' of ' + entries.length + ' proofs verified.'));
    const serverOk = complete && bundle.chain != null && bundle.chain.ok === chain && bundle.chain.root === computedRoot;
    results.push(showCheck('Server verdict agrees', serverOk, serverOk ? 'The reported chain verdict agrees with local recomputation.' : 'The reported server verdict is missing or disagrees with local recomputation.'));
    rootOutput.textContent = bundle.root || '(empty ledger)';
    const valid = results.every(Boolean);
    summary.className = 'status ' + (valid ? 'ok' : 'bad');
    summary.textContent = valid ? 'VERIFIED — chain, root and every inclusion proof are valid.' : 'NOT VERIFIED — inspect the failed checks before relying on this export.';
  } catch (error) {
    summary.className = 'status bad';
    summary.textContent = 'Could not verify: ' + (error instanceof Error ? error.message : String(error));
  }
}
input.addEventListener('change', () => { if (input.files && input.files[0]) verify(input.files[0]); });
if (!globalThis.crypto || !crypto.subtle) summary.textContent = 'This browser does not expose Web Crypto here. Open the verifier in a modern browser that supports local SHA-256.';
</script>
</main></body></html>`
