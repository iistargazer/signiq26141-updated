// Convert the four professional docs to branded, print-ready PDFs.
//
// Path: Markdown -> HTML (marked, GFM tables) -> Chrome headless print-to-PDF.
// Repeatable:  cd frontend && npm install && node ../scripts/build-docs-pdf.mjs
// Output:      docs/pdf/<name>.pdf  (committed to the repository)
//
// Chrome is located via CHROME env var or the usual Windows/macOS/Linux spots.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { createRequire } from 'node:module'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(path.join(root, 'frontend', 'package.json'))
const { marked } = require('marked')

const OUT_DIR = path.join(root, 'docs', 'pdf')
const FLAME = path.join(root, 'docs', 'assets', 'prometheus-flame.svg')
const CHROME_CANDIDATES = [
  process.env.CHROME,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean)

const DOCS = [
  { md: 'README.md', kicker: 'OVERVIEW & QUICKSTART', title: 'SigniQ', desc: 'System overview, pipeline architecture, measured evaluation results and quickstart.' },
  { md: 'docs/SIGNIQ_WHITEPAPER.md', kicker: 'TECHNICAL WHITEPAPER', title: 'SigniQ', desc: 'Formal models of the six-state QKD layer, the teleportation-based QDS protocol, the statistical threat-detection engine, and the seeded evaluation.' },
  { md: 'docs/PROJECT_HANDBOOK.md', kicker: 'PROJECT HANDBOOK', title: 'SigniQ', desc: 'Engineering reference: workspace architecture, configuration, the complete API surface, data formats, testing strategy and operator notes.' },
  { md: 'docs/DASHBOARD_MANUAL.md', kicker: 'DASHBOARD MANUAL', title: 'SigniQ', desc: 'Panel-by-panel guide to the web dashboard: runs, signatures, the document vault, attack lab and the audit ledger.' },
]

function findChrome() {
  for (const c of CHROME_CANDIDATES) if (existsSync(c)) return c
  throw new Error('Chrome/Edge not found; set CHROME env var')
}

const CSS = `
:root { --ink:#1c1a17; --dim:#5d574c; --gold:#8a6d2f; --gold-deep:#6d541f; --line:#d8d2c4; --panel:#f7f4ec; }
@page { size: A4; margin: 20mm 16mm 24mm 16mm; }
* { box-sizing: border-box; }
body { font-family: Georgia, 'Times New Roman', serif; color: var(--ink); font-size: 10.5pt; line-height: 1.55; margin: 0; }
h1, h2, h3, h4 { font-family: 'Segoe UI', Arial, sans-serif; color: var(--ink); line-height: 1.25; }
h1 { font-size: 20pt; margin: 0 0 10pt; }
h2 { font-size: 14.5pt; margin: 24pt 0 8pt; padding-bottom: 5pt; border-bottom: 1.6px solid var(--gold); }
h2, h3 { break-after: avoid; }
h3 { font-size: 11.5pt; margin: 16pt 0 6pt; color: var(--gold-deep); }
h4 { font-size: 10.5pt; margin: 12pt 0 4pt; }
p { margin: 6pt 0; }
a { color: var(--gold-deep); text-decoration: none; }
strong { color: #14120f; }
code, pre { font-family: Consolas, 'Courier New', monospace; }
code { font-size: 8.8pt; background: var(--panel); padding: 1pt 3pt; border-radius: 3px; }
pre { background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--gold); border-radius: 6px; padding: 9pt 11pt; font-size: 7.6pt; line-height: 1.35; white-space: pre-wrap; overflow-wrap: break-word; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: inherit; }
blockquote { border-left: 3px solid var(--gold); background: var(--panel); margin: 10pt 0; padding: 7pt 12pt; color: var(--dim); break-inside: avoid; border-radius: 0 6px 6px 0; }
table { border-collapse: collapse; width: 100%; font-size: 8.9pt; margin: 8pt 0; break-inside: auto; }
th, td { border: 1px solid var(--line); padding: 4pt 6pt; text-align: left; vertical-align: top; overflow-wrap: break-word; }
th { background: #efe8d6; font-family: 'Segoe UI', Arial, sans-serif; font-size: 8.4pt; color: #3d3628; border-bottom: 1.6px solid var(--gold); }
tr { break-inside: avoid; }
thead { display: table-header-group; }
hr { border: none; border-top: 1px solid var(--line); margin: 14pt 0; }
ul, ol { margin: 6pt 0; padding-left: 18pt; }
li { margin: 2.5pt 0; }
img { max-width: 100%; }
/* ---- Cover page ---- */
.cover-page { height: 247mm; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; page-break-after: always; }
.cover-page .flame { width: 92px; height: 92px; margin-bottom: 10pt; }
.cover-page .k { font-family: 'Segoe UI', Arial, sans-serif; font-size: 9pt; letter-spacing: 3.4pt; color: var(--gold); text-transform: uppercase; margin: 0 0 6pt; }
.cover-page .t { font-family: 'Segoe UI', Arial, sans-serif; font-size: 30pt; font-weight: 600; letter-spacing: 1pt; margin: 0; }
.cover-page .rule { width: 40mm; border: none; border-top: 2px solid var(--gold); margin: 14pt auto; }
.cover-page .d { color: var(--dim); font-size: 10.5pt; max-width: 122mm; line-height: 1.6; margin: 0; }
.cover-page .meta { margin-top: 26pt; font-family: 'Segoe UI', Arial, sans-serif; font-size: 9.5pt; color: var(--ink); letter-spacing: 0.6pt; }
.cover-page .meta .sub { color: var(--dim); font-size: 8.5pt; margin-top: 3pt; }
/* ---- Per-page footer (Chrome repeats position:fixed elements on every page;
        it is parked inside the 24mm bottom @page margin so nothing overlaps) ---- */
.page-footer { position: fixed; bottom: -17mm; left: 0; right: 0; text-align: center;
  font-family: 'Segoe UI', Arial, sans-serif; font-size: 7.8pt; color: var(--dim); }
.page-footer b { color: var(--gold-deep); font-weight: 600; }
`

function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c])
}

function toHtml(mdPath, meta) {
  const raw = readFileSync(path.join(root, mdPath), 'utf8')
  // The branded cover replaces the document's markdown header block:
  // flame banner, H1, subtitle/byline, and everything up to the first
  // horizontal rule when one closes the header block.
  let md = raw
    .replace(/^<p align="center"><img[^>]*prometheus-flame[^>]*><\/p>\s*/i, '')
    .replace(/^<h1 align="center">[\s\S]*?<\/h1>\s*/, '')
    .replace(/^# .*$/m, '')
    .replace(/\*\*Team Prometheus · SIH26141 · \*\*September\s*\d{1,2},\s*2026\*\*/g, '')
    .replace(/\*\*Team Prometheus · SIH26141 · September\s*\d{1,2},\s*2026\*\*/g, '')
  const hrPos = md.indexOf('\n---\n')
  if (hrPos !== -1 && hrPos < 2200) md = md.slice(hrPos + 5)
  md = md.replace(/\]\(#([^)]+)\)/g, '](#$1)')
  const body = marked.parse(md, { gfm: true })
  // Inline the flame SVG so the intermediate HTML is portable (no file:// refs).
  const flameSvg = readFileSync(FLAME, 'utf8')
    .replace(/width="96" height="96"/, 'class="flame"')
  const today = new Date().toISOString().slice(0, 10)
  return `<!doctype html><html><head><meta charset="utf-8"><style>${CSS}</style></head>
<body>
  <div class="cover-page">
    ${flameSvg}
    <div class="k">${escapeHtml(meta.kicker)}</div>
    <div class="t">${escapeHtml(meta.title)}</div>
    <hr class="rule">
    <p class="d">${escapeHtml(meta.desc)}</p>
    <div class="meta">TEAM PROMETHEUS · SIH26141<div class="sub">Quantum-secured document signatures · classical software simulation · ${today}</div></div>
  </div>
${body}
  <div class="page-footer"><b>SigniQ</b> · Team Prometheus · SIH26141 · classical software simulation — no quantum hardware</div>
</body></html>`
}

function convert() {
  mkdirSync(OUT_DIR, { recursive: true })
  const chrome = findChrome()
  const results = []
  for (const doc of DOCS) {
    const htmlPath = path.join(OUT_DIR, path.basename(doc.md).replace(/\.md$/, '.html'))
    const pdfPath = htmlPath.replace(/\.html$/, '.pdf')
    writeFileSync(htmlPath, toHtml(doc.md, doc))
    execFileSync(chrome, [
      '--headless=new',
      '--disable-gpu',
      '--no-pdf-header-footer',
      '--print-to-pdf=' + pdfPath,
      '--virtual-time-budget=10000',
      'file:///' + htmlPath.replace(/\\/g, '/'),
    ], { stdio: 'pipe' })
    const size = existsSync(pdfPath)
    if (!size) throw new Error(`PDF not created for ${doc.md}`)
    results.push({ doc: doc.md, pdf: pdfPath, bytes: readFileSync(pdfPath).length })
  }
  for (const r of results) console.log(`✓ ${r.doc} → ${path.basename(r.pdf)} (${(r.bytes / 1024).toFixed(0)} KB)`)
}

convert()
