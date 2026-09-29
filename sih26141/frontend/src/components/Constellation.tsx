import { useEffect, useMemo, useRef, useState } from 'react'
import type { AuditEntry } from '../api'

/**
 * The Constellation — the Merkle audit ledger drawn as a night sky.
 *
 * Every hash-chained event is a star; consecutive entries are joined
 * by fine constellation lines (the chain itself). Kind sets the color:
 * seal/keys gold, transfers silver, verifications verdigris, attacks
 * and rejections a dull ember red. Hovering a star names the event;
 * the newest entry breathes. It is the same data as the table below —
 * visitors can compare the visualization with the event ledger below.
 */

interface StarNode {
  x: number
  y: number
  r: number
  base: number // base alpha
  phase: number
  color: string
  entry: AuditEntry
  idx: number
}

const KIND_COLOR: Record<string, string> = {
  seal: '201, 164, 92', // old gold — the act of sealing
  verify: '134, 191, 156', // verdigris — acceptance
  verify_fail: '214, 127, 114', // ember — rejection
  attack: '214, 127, 114',
  transfer: '143, 176, 201', // moonlight silver
  send: '143, 176, 201',
  receive: '143, 176, 201',
  key: '179, 157, 219', // violet — key ceremonies
  qkd: '179, 157, 219',
}
const FALLBACK = '168, 157, 129'

function colorFor(kind: string): string {
  const k = kind.toLowerCase()
  for (const key of Object.keys(KIND_COLOR)) {
    if (k.includes(key)) return KIND_COLOR[key]
  }
  return FALLBACK
}

/** Deterministic pseudo-random from the entry hash — stars never jump around. */
function hashRand(hex: string, salt: number): number {
  let h = 2166136261 ^ salt
  for (let i = 0; i < hex.length; i += 2) {
    h ^= hex.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 10000) / 10000
}

export function Constellation({ entries }: { entries: AuditEntry[] }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const [hover, setHover] = useState<{ x: number; y: number; entry: AuditEntry } | null>(null)
  const nodesRef = useRef<StarNode[]>([])

  // The slice of sky: the NEWEST 90 events, oldest left → newest right.
  // The feed arrives newest-first, so take the head of the list and flip
  // it — slicing the tail would freeze the sky on the ledger's oldest
  // events once it grows past 90.
  const slice = useMemo(() => entries.slice(0, 90).slice().reverse(), [entries])

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (!canvas || !wrap) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = Math.min(window.devicePixelRatio || 1, 1.75)
    let width = 0
    let height = 0
    let raf = 0
    let visible = true
    let reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let timer: ReturnType<typeof window.setTimeout> | null = null

    const layout = () => {
      width = wrap.clientWidth
      height = 240
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      canvas.style.height = `${height}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

      // Lay stars along a gentle meander — a river of light across the
      // panel, jittered deterministically per entry hash so the pattern
      // is stable between renders.
      nodesRef.current = slice.map((entry, idx) => {
        const fx = slice.length <= 1 ? 0.5 : idx / (slice.length - 1)
        const h = entry.leaf_hash ?? `${entry.seq ?? idx}`
        const jy = (hashRand(h, 2) - 0.5) * 0.62
        const meander = Math.sin(fx * Math.PI * 2.3 + 1.2) * 0.1
        const x = 28 + fx * (width - 56)
        const y = height * (0.5 + jy * 0.34 + meander * 0.5)
        const isBad = colorFor(entry.kind) === KIND_COLOR.attack
        const r = (isBad ? 2.6 : 1.6) + hashRand(h, 3) * 1.7
        return {
          x,
          y,
          r,
          base: 0.55 + hashRand(h, 4) * 0.45,
          phase: hashRand(h, 5) * Math.PI * 2,
          color: colorFor(entry.kind),
          entry,
          idx,
        }
      })
    }

    // One gradient per chain segment, rebuilt only when the layout changes.
    const gradCache = new Map<number, CanvasGradient>()
    const lineGradFor = (i: number, a: StarNode, b: StarNode) => {
      let g = gradCache.get(i)
      if (!g) {
        g = ctx.createLinearGradient(a.x, a.y, b.x, b.y)
        g.addColorStop(0, `rgba(${a.color}, 0.16)`)
        g.addColorStop(1, `rgba(${b.color}, 0.28)`)
        gradCache.set(i, g)
      }
      return g
    }

    // Cached glow sprites per palette color.
    const spriteCache = new Map<string, HTMLCanvasElement>()
    const spriteFor = (rgb: string) => {
      let s = spriteCache.get(rgb)
      if (!s) {
        s = document.createElement('canvas')
        const R = 24
        s.width = s.height = R * 2
        const c = s.getContext('2d')
        if (c) {
          const g = c.createRadialGradient(R, R, 0, R, R, R)
          g.addColorStop(0, `rgba(${rgb}, 0.9)`)
          g.addColorStop(0.35, `rgba(${rgb}, 0.28)`)
          g.addColorStop(1, `rgba(${rgb}, 0)`)
          c.fillStyle = g
          c.fillRect(0, 0, R * 2, R * 2)
        }
        spriteCache.set(rgb, s)
      }
      return s
    }

    const draw = (now: number) => {
      raf = 0
      if (!visible || document.hidden) return
      const t = now / 1000
      ctx.clearRect(0, 0, width, height)

      const nodes = nodesRef.current

      // constellation lines — the Merkle chain, oldest to newest.
      // Gradients are laid down at layout time, not per frame.
      ctx.lineWidth = 0.6
      for (let i = 1; i < nodes.length; i++) {
        const a = nodes[i - 1]
        const b = nodes[i]
        ctx.strokeStyle = lineGradFor(i - 1, a, b)
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.stroke()
      }

      // stars
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i]
        const tw = 0.5 + 0.5 * Math.sin(n.phase + t * 0.9 * (0.6 + (n.idx % 7) * 0.07))
        const isNewest = i === nodes.length - 1
        const alpha = n.base * (0.55 + 0.45 * tw) * (isNewest ? 1 : 0.9)
        const size = n.r * 6
        ctx.globalAlpha = alpha
        ctx.drawImage(spriteFor(n.color), n.x - size / 2, n.y - size / 2, size, size)
        // core point so stars stay crisp
        ctx.globalAlpha = Math.min(1, alpha + 0.25)
        ctx.fillStyle = `rgba(${n.color}, 1)`
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.r * 0.55, 0, Math.PI * 2)
        ctx.fill()
        if (isNewest) {
          // the newest event breathes a soft halo
          ctx.globalAlpha = 0.5 + 0.3 * tw
          ctx.strokeStyle = `rgba(${n.color}, 0.5)`
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r + 4 + 2 * Math.sin(t * 2), 0, Math.PI * 2)
          ctx.stroke()
        }
      }
      ctx.globalAlpha = 1
      if (!reducedMotion && visible && !document.hidden && timer === null) {
        timer = window.setTimeout(() => {
          timer = null
          raf = requestAnimationFrame(draw)
        }, 66)
      }
    }

    const stopDrawing = () => {
      if (timer !== null) window.clearTimeout(timer)
      if (raf) cancelAnimationFrame(raf)
      timer = null
      raf = 0
    }
    const startDrawing = () => {
      if (!raf && timer === null && visible && !document.hidden) {
        if (reducedMotion) draw(performance.now())
        else raf = requestAnimationFrame(draw)
      }
    }
    const onVisibilityChange = () => {
      if (document.hidden) stopDrawing()
      else startDrawing()
    }
    const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)')
    const onMotionChange = (event: MediaQueryListEvent) => {
      reducedMotion = event.matches
      stopDrawing()
      startDrawing()
    }

    layout()
    startDrawing()

    const ro = new ResizeObserver(() => {
      layout()
      gradCache.clear()
      if (reducedMotion) draw(performance.now())
    })
    ro.observe(wrap)

    // Don't animate a canvas nobody is looking at.
    const io = new IntersectionObserver((es) => {
      visible = es[0]?.isIntersecting ?? true
      if (visible) startDrawing()
      else stopDrawing()
    })
    io.observe(canvas)
    document.addEventListener('visibilitychange', onVisibilityChange)
    motionPreference.addEventListener('change', onMotionChange)

    // hover picking — nearest star within 16px
    const onMove = (ev: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      const mx = ev.clientX - rect.left
      const my = ev.clientY - rect.top
      let best: StarNode | null = null
      let bestD = 18 * 18
      for (const n of nodesRef.current) {
        const dx = n.x - mx
        const dy = n.y - my
        const d = dx * dx + dy * dy
        if (d < bestD) {
          bestD = d
          best = n
        }
      }
      if (best) {
        setHover({ x: best.x, y: best.y, entry: best.entry })
        canvas.style.cursor = 'pointer'
      } else {
        setHover(null)
        canvas.style.cursor = 'crosshair'
      }
    }
    const onLeave = () => setHover(null)
    canvas.addEventListener('mousemove', onMove)
    canvas.addEventListener('mouseleave', onLeave)

    return () => {
      stopDrawing()
      document.removeEventListener('visibilitychange', onVisibilityChange)
      motionPreference.removeEventListener('change', onMotionChange)
      ro.disconnect()
      io.disconnect()
      canvas.removeEventListener('mousemove', onMove)
      canvas.removeEventListener('mouseleave', onLeave)
    }
  }, [slice])

  const legend = [
    { c: 'rgb(201, 164, 92)', l: 'seal' },
    { c: 'rgb(143, 176, 201)', l: 'transfer' },
    { c: 'rgb(134, 191, 156)', l: 'verify' },
    { c: 'rgb(179, 157, 219)', l: 'keys' },
    { c: 'rgb(214, 127, 114)', l: 'attack / reject' },
  ]

  return (
    <div className="constellation" ref={wrapRef}>
      <canvas ref={canvasRef} className="constellation-canvas" aria-label="Audit ledger constellation" />
      <div className="constellation-legend" aria-hidden>
        {legend.map((e) => (
          <span key={e.l}>
            <i style={{ background: e.c }} /> {e.l}
          </span>
        ))}
      </div>
      {hover && (
        <div className="constellation-tip" style={{ left: hover.x, top: hover.y }}>
          <div className="ct-kind">
            #{hover.entry.seq ?? '—'} · {hover.entry.kind}
          </div>
          <div className="ct-detail">{hover.entry.detail}</div>
        </div>
      )}
    </div>
  )
}
