import { useState } from 'react'
import {
  blindChallengeApi,
  type BlindChallengeMeasurement,
  type BlindChallengeRevealResponse,
  type BlindTreatment,
} from '../api'

const CHOICES: { id: BlindTreatment; title: string; description: string }[] = [
  { id: 'clear', title: 'Clear channel', description: 'No configured noise; no Eve' },
  { id: 'environmental_noise', title: 'Environmental noise', description: 'Bit flips without an interceptor' },
  { id: 'interception', title: 'Eavesdropping', description: 'Intercept-resend on the channel' },
]

function treatmentLabel(value: BlindTreatment): string {
  return CHOICES.find((choice) => choice.id === value)?.title ?? value
}

function float64BitsHex(value: number): string {
  const buffer = new ArrayBuffer(8)
  const view = new DataView(buffer)
  view.setFloat64(0, value, false)
  return view.getBigUint64(0, false).toString(16).padStart(16, '0')
}

function canonicalRevealPayload(reveal: BlindChallengeRevealResponse): string {
  const measurement = reveal.measurement
  const bell = measurement.bell_test
    ? [
        float64BitsHex(measurement.bell_test.s),
        float64BitsHex(measurement.bell_test.sigma),
        String(measurement.bell_test.rounds),
        String(measurement.bell_test.certified),
        float64BitsHex(measurement.bell_test.margin_sigma),
        float64BitsHex(measurement.bell_test.visibility),
      ].join(':')
    : 'none'
  return [
    'signiq-blind-challenge-v1',
    `treatment=${reveal.treatment}`,
    `noise=${Math.round(reveal.noise_rate * 100)}`,
    `intercept=${Math.round(reveal.intercept_ratio * 100)}`,
    `seed=${reveal.seed}`,
    `run_id=${measurement.run_id}`,
    `key_length=${measurement.key_length}`,
    `qber_bits=${float64BitsHex(measurement.qber)}`,
    `threshold_bits=${float64BitsHex(measurement.dynamic_threshold)}`,
    `sifted=${measurement.matching_bases_count}`,
    `mismatches=${measurement.mismatches}`,
    `class=${reveal.channel_class}`,
    `bell=${bell}`,
  ].join('|')
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function MeasurementReadout({ measurement }: { measurement: BlindChallengeMeasurement }) {
  return (
    <div className="blind-readout" aria-label="Measured channel evidence">
      <div><span>Measured QBER</span><b>{(measurement.qber * 100).toFixed(2)}%</b></div>
      <div><span>Dynamic line</span><b>{(measurement.dynamic_threshold * 100).toFixed(2)}%</b></div>
      <div><span>Observed errors</span><b>{measurement.mismatches.toLocaleString()} / {measurement.matching_bases_count.toLocaleString()}</b></div>
      <div><span>Simulated CHSH sample</span><b>{measurement.bell_test ? `S = ${measurement.bell_test.s.toFixed(3)} · ${measurement.bell_test.certified ? 'model threshold cleared' : 'model threshold not cleared'}` : 'not reported'}</b></div>
    </div>
  )
}

export function BlindChallenge({ onLog }: { onLog: (line: string) => void }) {
  const [challengeId, setChallengeId] = useState<string | null>(null)
  const [commitmentPreview, setCommitmentPreview] = useState<string | null>(null)
  const [measurement, setMeasurement] = useState<BlindChallengeMeasurement | null>(null)
  const [reveal, setReveal] = useState<BlindChallengeRevealResponse | null>(null)
  const [guess, setGuess] = useState<BlindTreatment | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function startRound() {
    setBusy(true)
    setError(null)
    setChallengeId(null)
    setCommitmentPreview(null)
    setMeasurement(null)
    setReveal(null)
    setGuess(null)
    try {
      const response = await blindChallengeApi.start()
      setChallengeId(response.challenge_id)
      setCommitmentPreview(response.commitment)
      setMeasurement(response.measurement)
      onLog(`Blind challenge #${response.measurement.run_id}: ${response.measurement.key_length.toLocaleString()} simulated qubits measured; treatment held for reveal`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function submitGuess() {
    if (!challengeId || !guess) return
    setBusy(true)
    setError(null)
    try {
      const response = await blindChallengeApi.reveal(challengeId, guess)
      const payload = canonicalRevealPayload(response)
      const computedCommitment = await sha256Hex(`${payload}|salt=${response.commitment_payload.split('|salt=')[1] ?? ''}`)
      if (payload !== response.commitment_payload.split('|salt=')[0] ||
        computedCommitment !== response.commitment || response.commitment !== commitmentPreview) {
        throw new Error('The pre-reveal commitment did not match the server reveal; treat this round as invalid.')
      }
      setReveal(response)
      setChallengeId(null)
      onLog(`Blind challenge #${response.measurement.run_id}: guessed ${treatmentLabel(response.guess)}; hidden treatment was ${treatmentLabel(response.treatment)} · commitment verified`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const treatmentTone = reveal?.treatment === 'interception' ? 'chip-red' : reveal?.treatment === 'environmental_noise' ? 'chip-amber' : 'chip-green'

  return (
    <section id="challenge" className="panel blind-challenge section-anchor" aria-labelledby="blind-title">
      <div className="panel-title-row">
        <div className="panel-title" id="blind-title">Blind red-team challenge</div>
        <span className="chip chip-violet">treatment withheld</span>
      </div>
      <p className="blind-intro">
        Can you distinguish a clean link, environmental disturbance and an active interceptor from
        the measurements alone? The server chooses one hidden software-model treatment and returns measured QBER, the configured decision line, mismatch count and a simulated CHSH diagnostic.
      </p>
      <div className="blind-protocol-note">
        <b>Scope:</b> this is an educational game, not a security contest. The server publishes a
        SHA-256 commitment before reveal so a changed treatment is detectable after the round;
        it does not prove the simulator/operator is honest. QKD and CHSH are classical software
        simulations, and the Bell-test sample uses independent randomness.
      </div>

      {!measurement && !busy && (
        <button className="btn btn-primary" onClick={() => { void startRound() }}>
          Draw a blind channel →
        </button>
      )}
      {busy && !measurement && <div className="blind-status" role="status">Preparing hidden channel and measuring 12,000 simulated qubits…</div>}
      {error && <div className="verdict-bad ring-error" role="alert">{error}</div>}

      {measurement && (
        <div className="blind-round" aria-live="polite">
          <div className="blind-round-head">
            <div>
              <span className="blind-run-label">Blind round #{measurement.run_id} · {measurement.key_length.toLocaleString()} simulated qubits</span>
              {challengeId && commitmentPreview && <span className="blind-commitment">PRE-REVEAL COMMITMENT · SHA-256 {commitmentPreview}</span>}
              <h3>{reveal ? (reveal.correct ? 'Correct diagnosis.' : 'Not this time.') : 'What disturbed the channel?'}</h3>
            </div>
            {reveal && <span className={`chip ${reveal.correct ? 'chip-green' : 'chip-amber'}`}>{reveal.correct ? 'diagnosis correct' : 'diagnosis missed'}</span>}
          </div>
          <MeasurementReadout measurement={measurement} />

          {!reveal && (
            <>
              <div className="blind-choices" role="group" aria-label="Choose the hidden channel condition">
                {CHOICES.map((choice) => (
                  <button
                    className={`blind-choice ${guess === choice.id ? 'blind-choice-selected' : ''}`}
                    key={choice.id}
                    onClick={() => setGuess(choice.id)}
                    disabled={busy}
                    aria-pressed={guess === choice.id}
                  >
                    <b>{choice.title}</b><span>{choice.description}</span>
                  </button>
                ))}
              </div>
              <div className="blind-actions">
                <button className="btn btn-primary" onClick={() => { void submitGuess() }} disabled={!guess || busy}>
                  {busy ? 'Revealing…' : 'Lock diagnosis & reveal'}
                </button>
                <button className="btn btn-sm" onClick={() => { void startRound() }} disabled={busy}>
                  Discard &amp; draw again
                </button>
              </div>
            </>
          )}

          {reveal && (
            <div className="blind-reveal">
              <div className="blind-reveal-title">
                <span>Hidden treatment</span><span className={`chip ${treatmentTone}`}>{treatmentLabel(reveal.treatment)}</span>
              </div>
              <p>{reveal.explanation}</p>
              <div className="blind-reveal-meta">
                <span>configured noise {(reveal.noise_rate * 100).toFixed(0)}%</span>
                <span>Eve intercepted {(reveal.intercept_ratio * 100).toFixed(0)}%</span>
                <span>channel classifier: {reveal.channel_class.replace('_', ' ')}</span>
                <span>QKD stream seed {reveal.seed} · simulated CHSH uses separate randomness</span>
              </div>
              <details className="blind-proof-details">
                <summary>Verify the pre-reveal commitment</summary>
                <p>The server sends a SHA-256 commitment with the measurement, before revealing the hidden treatment. After you submit a guess, the reveal supplies a salt so you can recompute it. This makes later changes detectable, but does not prove the measurement came from an honest simulation.</p>
                <code>SHA-256({canonicalRevealPayload(reveal)}|salt=[revealed])</code>
                <code>= {reveal.commitment}</code>
                <span className="chip chip-green">commitment matches</span>
              </details>
              <button className="btn btn-primary btn-sm" onClick={() => { void startRound() }} disabled={busy}>
                Run another blind round →
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
