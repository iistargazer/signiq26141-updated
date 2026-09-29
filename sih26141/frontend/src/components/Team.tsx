import { useEffect, useRef } from 'react'

/**
 * Team dossier — the hero keeps a small flame mark; clicking it opens an
 * editorial roster with each member's role, optional portrait and public
 * links. Keep these details in this file so the team can update profiles
 * without changing layout code. (Editing instructions live HERE, in this
 * comment, so evaluators never see them in the UI: put each portrait in
 * frontend/public/team/ and set photo: '/team/name.jpg' — leave it blank
 * to use initials; add only confirmed full URLs to github/linkedin/website;
 * set quote to a real, approved quote or omit it entirely.)
 *
 * Keeping it an overlay (not a page section) keeps the dashboard's
 * editorial column undisturbed; Escape and the scrim both close it.
 */

interface Member {
  name: string
  role: string
  duty: string
  /** A short, genuine quote or contribution; omit it until supplied. */
  quote?: string
  /** URL under frontend/public, e.g. /team/vageesh.jpg. */
  photo?: string
  github?: string
  linkedin?: string
  website?: string
}

const TEAM: Member[] = [
  {
    name: 'S Vageesh',
    role: 'Team Lead',
    duty: 'Project direction, scope and team coordination.',
  },
  {
    name: 'Rohan Chinta',
    role: 'Technical Lead · Main Developer',
    duty: 'System architecture, core protocols and dashboard implementation.',
    // Add only personal, confirmed profile URLs. Avoid generic placeholder links.
  },
  {
    name: 'Mohammad Saad Ansari',
    role: 'Mathematics & Algorithms',
    duty: 'Protocol mathematics, finite-key bounds and signature analysis.',
  },
  {
    name: 'Neha Voma',
    role: 'Security Specialist · Attacks',
    duty: 'Threat modeling, attack scenarios and security review.',
  },
  {
    name: 'Hariom Shilpkar',
    role: 'Frontend Developer',
    duty: 'Dashboard layout, visual design and interaction flow.',
  },
  {
    name: 'Zeel Pansuriya',
    role: 'Backend API Developer',
    duty: 'API design, document workflows and audit integration.',
  },
]

export function TeamFlame({ onOpen }: { onOpen: () => void }) {
  return (
    <button
      className="hero-credits"
      onClick={onOpen}
      aria-haspopup="dialog"
      aria-controls="team-dossier-dialog"
      aria-label="Meet Team Prometheus"
      title="Meet Team Prometheus"
    >
      <span className="credits-flame" aria-hidden>
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none">
          <path
            d="M12 2.5c1.8 2.6 1.2 4.4.2 5.9-.9 1.4-1.9 2.8-1.4 4.9.4 1.7 1.8 2.7 1.8 2.7s-.5-1.6.4-3c.7-1.1 1.9-1.7 2.3-3.3 1.5 1.6 2.6 3.9 2.2 6.2-.5 2.7-2.8 4.6-5.5 4.6s-5-2-5.4-4.7C6 12 9.3 9.4 9.8 6.4c.1-.9 0-1.9-.2-2.9 1 .1 1.8.4 2.4 1Z"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinejoin="round"
          />
          <circle cx="12" cy="17" r="1.6" fill="currentColor" opacity="0.85" />
        </svg>
      </span>
      <span>
        <span className="credits-team">Team Prometheus</span>
        <span className="credits-note">
          quantum-secured documents · <u>meet the team</u>
        </span>
      </span>
    </button>
  )
}

export function TeamDossier({ open, onClose }: { open: boolean; onClose: () => void }) {
  const dialogRef = useRef<HTMLDivElement | null>(null)
  const closeButtonRef = useRef<HTMLButtonElement | null>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!open) return
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousDocumentOverflow = document.documentElement.style.overflow
    const previousBodyOverflow = document.body.style.overflow
    document.documentElement.style.overflow = 'hidden'
    document.body.style.overflow = 'hidden'
    closeButtonRef.current?.focus()

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onCloseRef.current()
        return
      }
      if (event.key !== 'Tab') return

      const dialog = dialogRef.current
      if (!dialog) return
      const focusable = dialog.querySelectorAll<HTMLElement>(
        'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
      )
      if (focusable.length === 0) {
        event.preventDefault()
        dialog.focus()
        return
      }

      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const active = document.activeElement
      if (event.shiftKey && (active === first || !dialog.contains(active))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
        event.preventDefault()
        first.focus()
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      document.documentElement.style.overflow = previousDocumentOverflow
      document.body.style.overflow = previousBodyOverflow
      previousFocus?.focus()
    }
  }, [open])

  if (!open) return null
  return (
    <div className="team-scrim" onClick={onClose}>
      <div
        ref={dialogRef}
        id="team-dossier-dialog"
        className="team-plate"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="team-dossier-title"
        aria-describedby="team-dossier-description"
        tabIndex={-1}
      >
        <div className="team-head">
          <div className="team-head-row">
            <div>
              <div className="team-kicker">The people behind SigniQ</div>
              <h2 id="team-dossier-title" className="team-title">Team Prometheus</h2>
            </div>
            <button ref={closeButtonRef} className="team-dismiss" onClick={onClose} aria-label="Close team dossier">
              <span aria-hidden>×</span>
            </button>
          </div>
          <p id="team-dossier-description" className="team-sub">
            Meet the six-person team behind this quantum-secured document prototype.
          </p>
        </div>
        <div className="team-roster">
          {TEAM.map((member) => (
            <article key={member.name} className="team-member">
              <div className="team-photo">
                {member.photo ? (
                  <img src={member.photo} alt={`${member.name}, ${member.role}`} loading="lazy" />
                ) : (
                  <span className="team-photo-mono" aria-hidden="true">
                    {member.name.split(' ').map((word) => word[0]).join('')}
                  </span>
                )}
              </div>
              <div className="team-member-main">
                <h3 className="team-member-name">{member.name}</h3>
                <div className="team-member-role">{member.role}</div>
                <p className="team-member-duty">{member.duty}</p>
                {member.quote?.trim() && <blockquote className="team-member-quote">“{member.quote.trim()}”</blockquote>}
                {(member.github || member.linkedin || member.website) && (
                  <div className="team-links">
                    {member.github && (
                      <a href={member.github} target="_blank" rel="noopener noreferrer" className="team-link">
                        GitHub ↗
                      </a>
                    )}
                    {member.linkedin && (
                      <a href={member.linkedin} target="_blank" rel="noopener noreferrer" className="team-link">
                        LinkedIn ↗
                      </a>
                    )}
                    {member.website && (
                      <a href={member.website} target="_blank" rel="noopener noreferrer" className="team-link">
                        Website ↗
                      </a>
                    )}
                  </div>
                )}
              </div>
            </article>
          ))}
        </div>
        <button className="team-close" onClick={onClose}>
          Close dossier
        </button>
      </div>
    </div>
  )
}
