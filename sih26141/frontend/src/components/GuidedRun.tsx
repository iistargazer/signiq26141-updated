export type GuidedRunTarget =
  | 'channel'
  | 'noise-study'
  | 'challenge'
  | 'vault'
  | 'attacks'
  | 'qds'
  | 'consensus'
  | 'ledger'

export type GuidedRunAction = 'comparison' | 'noise-study'

export interface GuidedRunStep {
  target: GuidedRunTarget
  id: string
  title: string
  body: string
  evidence: string
  action?: GuidedRunAction
  actionLabel?: string
}

export const GUIDED_RUN_STEPS: GuidedRunStep[] = [
  {
    target: 'channel',
    id: 'channel',
    title: 'Start with a measured channel',
    body: 'Compare a clean link with an intercept-resend attack using a repeatable QKD seed. The CHSH sample uses independent randomness.',
    evidence: 'Look at measured QBER, the finite-sample decision line, mismatches and the tail probability. A high p-value is not proof of security.',
    action: 'comparison',
    actionLabel: 'Run the comparison',
  },
  {
    target: 'noise-study',
    id: 'noise-study',
    title: 'Separate noise from interception',
    body: 'Hold the QKD seed, key budget and detector fixed while changing environmental bit flips and Eve’s intercept-resend rate.',
    evidence: 'Four live measurements form a 2 × 2 comparison: clean, noise only, Eve only, and both.',
    action: 'noise-study',
    actionLabel: 'Run the 2 × 2 study',
  },
  {
    target: 'challenge',
    id: 'challenge',
    title: 'Try a blind diagnosis',
    body: 'Draw a server-selected channel condition and diagnose it from measured evidence before revealing the treatment.',
    evidence: 'The SHA-256 commitment lets you detect changes to the treatment or measurements after the challenge response. It does not prove the simulator or operator is honest.',
  },
  {
    target: 'vault',
    id: 'vault',
    title: 'Seal a test document',
    body: 'Choose a small test file, derive a session key and seal it into an opaque .qsig container.',
    evidence: 'The vault reports the document digest and audit sequence; the browser never receives the raw session key.',
  },
  {
    target: 'attacks',
    id: 'attacks',
    title: 'Test the seal against tampering',
    body: 'Use a test container in the attack lab to tamper with bytes, swap metadata, forge a seal or truncate the payload.',
    evidence: 'Watch the verification checks reject a forged container and record the attempt in the audit ledger.',
  },
  {
    target: 'qds',
    id: 'qds',
    title: 'Explore the signature protocol',
    body: 'Walk through teleportation-based QDS signing and verification, including the forgery analysis.',
    evidence: 'This is a classical software simulation—not quantum hardware or a physical channel.',
  },
  {
    target: 'consensus',
    id: 'consensus',
    title: 'Add more verifiers',
    body: 'Run the receiver ring and explore the k-of-m transfer rule alongside its finite-sample statistical bounds.',
    evidence: 'Use supplied measurements from a prior QKD run to explore the confidence engine.',
  },
  {
    target: 'ledger',
    id: 'ledger',
    title: 'Take the evidence offline',
    body: 'Export the complete audit snapshot and its per-entry Merkle proofs, then open the self-contained local verifier.',
    evidence: 'The verifier recomputes the hash chain, root and every inclusion proof. Compare the root through a trusted channel to establish who published it.',
  },
]

export function GuidedRun({
  stepIndex,
  onClose,
  onNext,
  onPrevious,
  onJump,
  onAction,
  actionBusy = false,
}: {
  stepIndex: number
  onClose: () => void
  onNext: () => void
  onPrevious: () => void
  onJump: (target: GuidedRunTarget) => void
  onAction: (action: GuidedRunAction) => void
  actionBusy?: boolean
}) {
  const step = GUIDED_RUN_STEPS[stepIndex]

  return (
    <aside className="guided-run-dock" aria-label="Guided run">
      <div className="guided-run-head">
        <div>
          <span className="guided-run-kicker">Guided run · {stepIndex + 1} / {GUIDED_RUN_STEPS.length}</span>
          <h2>{step.title}</h2>
        </div>
        <button className="guided-run-close" onClick={onClose} aria-label="Close guided run">×</button>
      </div>
      <div className="guided-run-progress" aria-hidden>
        {GUIDED_RUN_STEPS.map((item, index) => (
          <span key={item.id} className={index <= stepIndex ? 'guided-run-progress-done' : ''} />
        ))}
      </div>
      <p className="guided-run-body">{step.body}</p>
      <p className="guided-run-evidence"><b>What to look for</b>{step.evidence}</p>
      <div className="guided-run-actions">
        <button className="link-btn" onClick={() => onJump(step.target)}>Go to this section ↓</button>
        {step.action && (
          <button className="btn btn-primary btn-sm" onClick={() => onAction(step.action!)} disabled={actionBusy}>
            {actionBusy ? 'Measuring…' : step.actionLabel}
          </button>
        )}
      </div>
      <div className="guided-run-footer">
        <button className="btn btn-sm" onClick={onPrevious} disabled={stepIndex === 0}>Previous</button>
        <button className="btn btn-primary btn-sm" onClick={onNext}>
          {stepIndex === GUIDED_RUN_STEPS.length - 1 ? 'Finish' : 'Next step →'}
        </button>
        <button className="link-btn guided-run-skip" onClick={onClose}>Skip</button>
      </div>
    </aside>
  )
}
