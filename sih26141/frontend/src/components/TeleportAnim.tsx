import { useEffect, useState } from 'react'
import type { TeleportSample } from '../api'

/**
 * One genuine teleportation round, staged as a four-beat animation:
 *
 *   1. ENTANGLE   — the EPR pair is shared: Alice's half and Bob's half
 *                   light up joined by an entanglement thread.
 *   2. MEASURE    — the message qubit lands on Alice; her Bell circuit
 *                   (CNOT + H) collapses the pair — the thread snaps.
 *   3. TRANSMIT   — two CLASSICAL bits (the Bell outcome) fly to Bob.
 *                   This is the only thing that crosses the wire.
 *   4. CORRECT    — Bob applies the Pauli (I / X / Z / ZX) and the state
 *                   reconstructs — fidelity 1.0.
 *
 * Pure CSS keyframes on transform/opacity only (compositor-friendly —
 * the site's performance budget forbids rAF loops). Plays once per
 * signature; the `nonce` key re-runs it on every new sign.
 */
export function TeleportAnim({ sample, nonce }: { sample: TeleportSample; nonce: number }) {
  const [phase, setPhase] = useState(0)

  useEffect(() => {
    setPhase(0)
    const timers = [
      window.setTimeout(() => setPhase(1), 900),
      window.setTimeout(() => setPhase(2), 2100),
      window.setTimeout(() => setPhase(3), 3300),
    ]
    return () => timers.forEach((t) => window.clearTimeout(t))
  }, [nonce])

  const corrections = ['I', 'X', 'Z', 'ZX']
  const bellBits = sample.bell_outcome.toString(2).padStart(2, '0')
  const pauli = corrections[sample.bell_outcome & 3] ?? 'I'

  return (
    <div className="tp-anim" key={nonce} aria-label={`teleportation round ${sample.position}: bell outcome ${bellBits}, pauli correction ${pauli}`}>
      <div className="tp-lane">
        {/* the message qubit, waiting above Alice */}
        <div className={`tp-msg ${phase >= 1 ? 'tp-msg-landed' : ''}`} title="the state to teleport: α|0⟩ + β|1⟩ (destroyed by the measurement — no-cloning)">
          ψ
        </div>

        {/* Alice */}
        <div className="tp-node tp-alice">
          <span className="tp-dot" />
          <span className="tp-label">Alice</span>
          <span className={`tp-ring ${phase >= 1 && phase < 2 ? 'tp-ring-live' : phase >= 2 ? 'tp-ring-done' : ''}`}>
            {phase >= 1 && phase < 2 ? 'BELL' : phase >= 2 ? '✓' : ''}
          </span>
        </div>

        {/* entanglement thread */}
        <div className={`tp-thread ${phase >= 2 ? 'tp-thread-snapped' : phase >= 0 ? 'tp-thread-live' : ''}`} />

        {/* the two classical bits in flight */}
        <div className={`tp-bits ${phase >= 2 ? 'tp-bits-fly' : ''}`}>
          <span>{bellBits[0]}</span>
          <span>{bellBits[1]}</span>
        </div>

        {/* Bob */}
        <div className="tp-node tp-bob">
          <span className={`tp-dot ${phase >= 3 ? 'tp-dot-corrected' : ''}`} />
          <span className="tp-label">Bob</span>
          <span className={`tp-pauli ${phase >= 3 ? 'tp-pauli-landed' : ''}`}>{pauli}</span>
        </div>
      </div>

      <div className={`tp-readout ${phase >= 3 ? 'tp-readout-live' : ''}`}>
        {phase >= 3 ? (
          <>
            round #{sample.position} — Bell outcome <b>{bellBits}</b> · Pauli <b>{pauli}</b> · raw{' '}
            <b>{sample.raw_bit}</b> → corrected <b>{sample.corrected_bit}</b> · fidelity <b>1.0</b>
          </>
        ) : (
          <>round #{sample.position} — {phase === 0 ? 'sharing the EPR pair…' : phase === 1 ? 'Bell-measuring Alice’s half…' : 'classical bits in flight…'}</>
        )}
      </div>
    </div>
  )
}
