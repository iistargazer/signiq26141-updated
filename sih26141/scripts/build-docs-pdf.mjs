// Convert the four professional docs to branded, print-ready PDFs.
//
// Path: Markdown -> HTML (marked, GFM tables) -> Chrome headless print-to-PDF.
// Repeatable:  cd frontend && npm install && node ../scripts/build-docs-pdf.mjs
// Output:      target/docs-pdf/<name>.pdf  (target/ is gitignored)
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

const OUT_DIR = path.join(root, 'target', 'docs-pdf')
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
  { md: 'README.md', title: 'SigniQ — Overview & Quickstart', subtitle: 'Team Prometheus · SIH26141' },
  { md: 'docs/SIGNIQ_WHITEPAPER.md', title: 'SigniQ — Technical Whitepaper', subtitle: 'Team Prometheus · SIH26141' },
  { md: 'docs/PROJECT_HANDBOOK.md', title: 'SigniQ — Project Handbook', subtitle: 'Team Prometheus · SIH26141' },
  { md: 'docs/DASHBOARD_MANUAL.md', title: 'SigniQ — Dashboard Manual', subtitle: 'Team Prometheus · SIH26141' },
]

function findChrome() {
  for (const c of CHROME_CANDIDATES) if (existsSync(c)) return c
  throw new Error('Chrome/Edge not found; set CHROME env var')
}

const CSS = `
:root { --ink:#1c1a17; --dim:#5d574c; --gold:#8a6d2f; --line:#d8d2c4; --panel:#f7f4ec; }
@page { size: A4; margin: 18mm 16mm 20mm 16mm; }
* { box-sizing: border-box; }
body { font-family: Georgia, 'Times New Roman', serif; color: var(--ink); font-size: 10.5pt; line-height: 1.55; margin: 0; }
h1, h2, h3, h4 { font-family: 'Segoe UI', Arial, sans-serif; color: var(--ink); line-height: 1.25; }
h1 { font-size: 21pt; margin: 0 0 6pt; border-bottom: 2px solid var(--gold); padding-bottom: 8pt; }
h2 { font-size: 14.5pt; margin: 22pt 0 8pt; border-bottom: 1px solid var(--line); padding-bottom: 4pt; }
h3 { font-size: 11.5pt; margin: 16pt 0 6pt; }
p { margin: 6pt 0; }
a { color: var(--gold); text-decoration: none; }
code, pre { font-family: Consolas, 'Courier New', monospace; }
code { font-size: 8.8pt; background: var(--panel); padding: 1pt 3pt; border-radius: 3px; }
pre { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 9pt 11pt; font-size: 7.6pt; line-height: 1.35; white-space: pre-wrap; overflow-wrap: break-word; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: inherit; }
blockquote { border-left: 3px solid var(--gold); background: var(--panel); margin: 10pt 0; padding: 7pt 12pt; color: var(--dim); break-inside: avoid; }
table { border-collapse: collapse; width: 100%; font-size: 8.9pt; margin: 8pt 0; }
th, td { border: 1px solid var(--line); padding: 4pt 6pt; text-align: left; vertical-align: top; overflow-wrap: break-word; }
th { background: #efe9db; font-family: 'Segoe UI', Arial, sans-serif; font-size: 8.4pt; }
tr { break-inside: avoid; }
thead { display: table-header-group; }
hr { border: none; border-top: 1px solid var(--line); margin: 14pt 0; }
ul, ol { margin: 6pt 0; padding-left: 18pt; }
li { margin: 2.5pt 0; }
img { max-width: 100%; }
/* Print behavior */
h2, h3 { break-after: avoid; }
table, blockquote, pre, li { break-inside: avoid; }
.cover { text-align: center; margin: 0 0 18pt; padding: 14pt 0 16pt; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); break-inside: avoid; }
.cover svg { width: 58px; height: 58px; }
.cover .t { font-family: 'Segoe UI', Arial, sans-serif; font-size: 20pt; font-weight: 600; margin: 6pt 0 2pt; }
.cover .s { color: var(--dim); font-size: 10.5pt; letter-spacing: 0.4pt; }
.doc-footer { margin-top: 16pt; padding-top: 8pt; border-top: 1px solid var(--line); color: var(--dim); font-size: 8.5pt; text-align: center; }
@media print { .cover { border: 1px solid var(--line); } }
`

function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c])
}

function toHtml(mdPath, meta) {
  const raw = readFileSync(path.join(root, mdPath), 'utf8')
  // Drop the markdown flame banner + byline (replaced by the branded cover),
  // and neutralize in-page anchors that would fight Chrome's pagination.
  let md = raw
    .replace(/^<p align="center"><img[^>]*prometheus-flame[^>]*><\/p>\s*/i, '')
    .replace(/^# .*$/m, '')
    .replace(/\*\*Team Prometheus · SIH26141 · \*\*September\s*\d{1,2},\s*2026\*\*/g, '')
    .replace(/\*\*Team Prometheus · SIH26141 · September\s*\d{1,2},\s*2026\*\*/g, '')
  md = md.replace(/\]\(#([^)]+)\)/g, '](#$1)')
  const body = marked.parse(md, { gfm: true })
  // Inline the flame SVG so the intermediate HTML is portable (no file:// refs).
  const flameSvg = readFileSync(FLAME, 'utf8')
    .replace(/width="96" height="96"/, '')
  return `<!doctype html><html><head><meta charset="utf-8"><style>${CSS}</style></head>
<body>
  <div class="cover">
    ${flameSvg}
    <div class="t">${escapeHtml(meta.title)}</div>
    <div class="s">${escapeHtml(meta.subtitle)} · September 29, 2026</div>
  </div>
${body}
  <div class="doc-footer">Team Prometheus · SIH26141 · SigniQ — quantum-inspired threat detection for digital-signature security (classical software simulation)</div>
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
    const before = existsSync(pdfPath)
    if (before) { /* Chrome refuses to overwrite cleanly on some setups */ }
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
