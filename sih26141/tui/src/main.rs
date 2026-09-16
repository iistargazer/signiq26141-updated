//! Interactive TUI dashboard (Feature 6) — live QKD telemetry with ratatui.
//!
//! Run with: `cargo run -p tui` (from the workspace root).
//!
//! Keys:
//!   1/2/3   scenario (secure / attack / mixed 30%)
//!   n/N     decrease / increase fiber noise (1% steps)
//!   r/R     decrease / increase relay hops
//!   s       seal demo document   v verify it   t tamper + verify   w quorum demo
//!   Q / Esc quit

use rand::rngs::StdRng;
use rand::SeedableRng;
use ratatui::{
    backend::CrosstermBackend,
    crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    },
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Sparkline, Wrap},
    Frame, Terminal,
};
use sha2::{Digest, Sha256};
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use audit::AuditLog;
use detection::{ChannelClass, ThreatDetector};
use quantum::relay::{simulate_relay_transmission, HopStats, RelayRoute, RelayTransmission};
use quantum::{ChannelSession, QuantumKeyGenerator};
use sealing::{
    combine_shares, seal_document, split_secret, verify_document, AuditRef, QsigDocument,
    QuorumSpec,
};

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Simulation engine
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    Secure,
    Attack,
    Mixed,
}

impl Scenario {
    fn label(self) -> &'static str {
        match self {
            Scenario::Secure => "secure",
            Scenario::Attack => "attack",
            Scenario::Mixed => "mixed 30%",
        }
    }
    fn cycle(self) -> Self {
        match self {
            Scenario::Secure => Scenario::Attack,
            Scenario::Attack => Scenario::Mixed,
            Scenario::Mixed => Scenario::Secure,
        }
    }
    fn intercept_ratio(self) -> f64 {
        match self {
            Scenario::Secure => 0.0,
            Scenario::Attack => 1.0,
            Scenario::Mixed => 0.3,
        }
    }
    fn color(self) -> Color {
        match self {
            Scenario::Secure => Color::Green,
            Scenario::Attack => Color::Red,
            Scenario::Mixed => Color::Yellow,
        }
    }
}

/// Rolling sparkline window (one QBER sample per tick, 240 samples).
const WINDOW: usize = 240;
/// QBER above which the detector calls an attack (six-state intercept line).
const ATTACK_LINE: f64 = 0.25;

struct Engine {
    key_length: usize,
    base_threshold: f64,
    noise_rate: f64,
    relay_hops: usize,
    intercept_ratio: f64,
    scenario: Scenario,
    rng: StdRng,
}

struct ChannelState {
    processed: usize,
    sifted: usize,
    mismatches: usize,
    qber: f64,
    threshold: f64,
    class: ChannelClass,
    history: Vec<u64>, // per-mille samples for the sparkline
}

impl ChannelState {
    fn new() -> Self {
        Self {
            processed: 0,
            sifted: 0,
            mismatches: 0,
            qber: 0.0,
            threshold: 0.0,
            class: ChannelClass::Secure,
            history: Vec::with_capacity(WINDOW),
        }
    }
}

struct VaultState {
    doc: Option<QsigDocument>,
    secret_hex: String,
    threshold_k: u8,
    last_result: Option<(String, bool)>,
}

struct App {
    engine: Engine,
    channel: ChannelState,
    relay: Option<RelayTransmission>,
    audit: AuditLog,
    vault: VaultState,
    log: Vec<String>,
    quanta_per_tick: usize,
    running: bool,
}

fn empty_relay(route: &RelayRoute) -> RelayTransmission {
    let links = route.link_count();
    RelayTransmission {
        sifted_key_bits: Vec::new(),
        alice_sifted_bits: Vec::new(),
        mismatch_rate: 0.0,
        matching_bases_count: 0,
        hops: (0..links)
            .map(|link| HopStats {
                hop: link,
                from: route.node_label(link),
                to: if link + 1 < links {
                    route.node_label(link + 1)
                } else {
                    "Bob".into()
                },
                noise_rate: route.noise_rate,
                intercept_ratio: route.intercept_ratio,
                ..Default::default()
            })
            .collect(),
        noise_rate: route.noise_rate,
        interceptions: 0,
    }
}

impl App {
    fn new() -> Self {
        let mut audit = AuditLog::new();
        audit.append(
            "system",
            "tui",
            true,
            "TUI dashboard attached — session opened",
            &hex::encode(sha256(b"tui-session")),
            &now_stamp(),
        );
        Self {
            engine: Engine {
                key_length: 40_000,
                base_threshold: 0.15,
                noise_rate: 0.0,
                relay_hops: 0,
                intercept_ratio: 0.0,
                scenario: Scenario::Secure,
                rng: StdRng::from_entropy(),
            },
            channel: ChannelState::new(),
            relay: None,
            audit,
            vault: VaultState {
                doc: None,
                secret_hex: String::new(),
                threshold_k: 3,
                last_result: None,
            },
            log: Vec::with_capacity(200),
            quanta_per_tick: 400,
            running: true,
        }
    }

    fn say(&mut self, line: impl Into<String>) {
        let line = line.into();
        let ts = now_stamp_short();
        if self.log.len() >= 200 {
            self.log.remove(0);
        }
        self.log.push(format!("{ts} {line}"));
    }

    /// Reset live statistics (keeps the audit log and log pane).
    fn reset_channel(&mut self) {
        self.channel = ChannelState::new();
        self.relay = None;
        self.engine.intercept_ratio = self.engine.scenario.intercept_ratio();
    }

    /// Auto-restart when a transmission completes so the demo keeps moving.
    fn tick(&mut self) {
        let remaining = self.engine.key_length.saturating_sub(self.channel.processed);
        if remaining == 0 {
            let keep_history = std::mem::take(&mut self.channel.history);
            self.reset_channel();
            self.channel.history = keep_history;
            return;
        }

        let n = self.quanta_per_tick.min(remaining);
        if self.engine.relay_hops > 0 {
            self.tick_relay(n);
        } else {
            self.tick_direct(n);
        }

        let qber = if self.channel.sifted > 0 {
            self.channel.mismatches as f64 / self.channel.sifted as f64
        } else {
            0.0
        };
        let detector = ThreatDetector::new(self.engine.base_threshold).expect("valid threshold");
        if let Ok(res) = detector.evaluate_channel(
            qber,
            self.channel.sifted,
            self.engine.noise_rate,
            self.engine.noise_rate,
        ) {
            self.channel.qber = qber;
            self.channel.threshold = res.dynamic_threshold;
            self.channel.class = res.channel_class;
        }

        self.channel.history.push((qber * 1000.0) as u64);
        if self.channel.history.len() > WINDOW {
            self.channel.history.remove(0);
        }
    }

    fn tick_direct(&mut self, n: usize) {
        let mut session = ChannelSession::new(self.engine.intercept_ratio)
            .with_noise(self.engine.noise_rate);
        let mut rng = self.engine.rng.clone();
        let gen = QuantumKeyGenerator::new(n).expect("n > 0");
        let eigenstates = gen.generate_eigenstates(&mut rng);

        for (basis, state) in &eigenstates {
            if let Some(step) = session.transmit(*basis, *state, &mut rng) {
                self.channel.sifted += 1;
                if step.alice_bit != step.bob_bit {
                    self.channel.mismatches += 1;
                }
            }
        }
        self.channel.processed += n;
        self.engine.rng = rng;
    }

    fn tick_relay(&mut self, n: usize) {
        let route = RelayRoute::new(self.engine.relay_hops)
            .with_noise(self.engine.noise_rate)
            .with_intercept(self.engine.intercept_ratio);
        let mut rng = self.engine.rng.clone();
        let gen = QuantumKeyGenerator::new(n).expect("n > 0");
        let eigenstates = gen.generate_eigenstates(&mut rng);

        let batch = simulate_relay_transmission(&eigenstates, &route, &mut rng);

        if self.relay.is_none() {
            self.relay = Some(empty_relay(&route));
        }
        let total = self.relay.as_mut().expect("just set");
        for (i, h) in batch.hops.iter().enumerate() {
            total.hops[i].in_qubits += h.in_qubits;
            total.hops[i].out_qubits += h.out_qubits;
            total.hops[i].mismatches += h.mismatches;
            total.hops[i].interceptions += h.interceptions;
            total.hops[i].qber = if total.hops[i].out_qubits > 0 {
                total.hops[i].mismatches as f64 / total.hops[i].out_qubits as f64
            } else {
                0.0
            };
        }
        total.matching_bases_count += batch.matching_bases_count;
        total.sifted_key_bits.extend_from_slice(&batch.sifted_key_bits);
        total.alice_sifted_bits.extend_from_slice(&batch.alice_sifted_bits);
        total.interceptions += batch.interceptions;
        let mismatches = total
            .sifted_key_bits
            .iter()
            .zip(total.alice_sifted_bits.iter())
            .filter(|(a, b)| a != b)
            .count();
        total.mismatch_rate = if total.matching_bases_count > 0 {
            mismatches as f64 / total.matching_bases_count as f64
        } else {
            0.0
        };

        self.channel.processed += n;
        self.channel.sifted = total.matching_bases_count;
        self.channel.mismatches = mismatches;
        self.engine.rng = rng;
    }
}

// ---------------------------------------------------------------------------
// Vault actions
// ---------------------------------------------------------------------------

impl App {
    fn seal_demo(&mut self) {
        let secret = hex::encode(sha256(format!("tui-session-{}", now_stamp()).as_bytes()));
        let audit_ref = AuditRef {
            first_seq: self.audit.entries().first().map(|e| e.seq),
            last_seq: self.audit.entries().last().map(|e| e.seq),
            root: self.audit.root(),
        };
        let payload = format!(
            "SIH26141 demo payload — generated {}\nrelay hops: {}\nnoise: {:.1}%",
            now_stamp(),
            self.engine.relay_hops,
            self.engine.noise_rate * 100.0
        );
        let mut rng = self.engine.rng.clone();
        let doc = seal_document(
            "demo-brief.txt",
            "text/plain",
            payload.as_bytes(),
            &secret,
            &now_stamp(),
            audit_ref,
            QuorumSpec::default(),
            &mut rng,
        );
        self.engine.rng = rng;

        match doc {
            Ok(d) => {
                let size = d.meta.size;
                let sha = d.meta.sha256.clone();
                let seq = self.audit.append(
                    "seal",
                    "tui",
                    true,
                    &format!("sealed demo-brief.txt ({size} bytes)"),
                    &sha,
                    &now_stamp(),
                );
                self.vault.secret_hex = secret;
                self.vault.doc = Some(d);
                let seq = seq.seq;
                self.vault.last_result = Some((format!("sealed ✓ (audit seq {seq})"), true));
                self.say(format!("vault: sealed demo-brief.txt → .qsig ({size} bytes, key committed)"));
            }
            Err(e) => {
                self.vault.last_result = Some((format!("seal failed: {e}"), false));
                self.say(format!("vault: seal FAILED: {e}"));
            }
        }
    }

    fn verify_demo(&mut self) {
        let Some(doc) = self.vault.doc.clone() else {
            self.say("vault: nothing sealed yet — press s first");
            return;
        };
        match verify_document(&doc, &self.vault.secret_hex) {
            Ok(out) => {
                let ok = out.passed();
                let seq = self.audit.append(
                    "verify",
                    "tui",
                    ok,
                    &format!("verify demo-brief.txt: {}", out.note),
                    &doc.meta.sha256,
                    &now_stamp(),
                )
                .seq;
                self.vault.last_result =
                    Some((format!("verify {} — {}", if ok { "✓" } else { "✗" }, out.note), ok));
                self.say(format!("vault: verify → {} (audit seq {seq})", out.note));
            }
            Err(e) => {
                self.vault.last_result = Some((format!("verify error: {e}"), false));
                self.say(format!("vault: verify error: {e}"));
            }
        }
    }

    fn tamper_demo(&mut self) {
        let Some(mut doc) = self.vault.doc.clone() else {
            self.say("vault: nothing sealed yet — press s first");
            return;
        };
        if let Some(first) = doc.ciphertext.first_mut() {
            *first ^= 0x01; // flip one bit of the masked payload
        }
        match verify_document(&doc, &self.vault.secret_hex) {
            Ok(out) => {
                let ok = out.passed();
                let seq = self.audit.append(
                    "flag",
                    "tui",
                    false,
                    &format!("tamper check: {}", out.note),
                    &doc.meta.sha256,
                    &now_stamp(),
                )
                .seq;
                self.vault.last_result = Some((
                    format!("tampered → {}", if ok { "NOT DETECTED?!" } else { "✗ caught" }),
                    ok,
                ));
                self.say(format!("vault: tamper test → {} (audit seq {seq})", out.note));
            }
            Err(e) => self.say(format!("vault: tamper verify error: {e}")),
        }
    }

    fn quorum_demo(&mut self) {
        if self.vault.secret_hex.is_empty() {
            self.say("vault: seal a document first (s)");
            return;
        }
        let k = self.vault.threshold_k;
        let mut rng = self.engine.rng.clone();
        match split_secret(&self.vault.secret_hex, k, 5, &mut rng) {
            Ok(shares) => {
                self.engine.rng = rng;
                let recon = combine_shares(&shares[..k as usize]);
                let short = combine_shares(&shares[..(k as usize - 1).max(1)]);
                match (recon, short) {
                    (Ok(secret), Err(_)) => {
                        let seq = self.audit.append(
                            "quorum",
                            "tui",
                            true,
                            &format!("{k}-of-5 quorum reconstructed the sealing key (k−1 rejected)"),
                            &hex::encode(sha256(secret.as_bytes())),
                            &now_stamp(),
                        )
                        .seq;
                        self.say(format!(
                            "vault: quorum {k}-of-5 ✓ reconstructed (k−1 correctly rejected, audit seq {seq})"
                        ));
                    }
                    (Ok(_), Ok(_)) => {
                        self.say("vault: quorum ERROR — k−1 shares also reconstructed (bug!)");
                    }
                    (Err(e), _) => self.say(format!("vault: quorum reconstruct failed: {e}")),
                }
            }
            Err(e) => self.say(format!("vault: split failed: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// TUI rendering
// ---------------------------------------------------------------------------

fn now_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("t={secs}")
}

fn now_stamp_short() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let within = secs % 86400;
    let (h, m, s) = (within / 3600, (within % 3600) / 60, within % 60);
    format!("[{h:02}:{m:02}:{s:02}]")
}

fn class_style(class: ChannelClass) -> Style {
    match class {
        ChannelClass::Secure => Style::new().fg(Color::Green),
        ChannelClass::Degraded => Style::new().fg(Color::Yellow),
        ChannelClass::UnderAttack => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn class_label(class: ChannelClass) -> &'static str {
    match class {
        ChannelClass::Secure => "SECURE",
        ChannelClass::Degraded => "DEGRADED",
        ChannelClass::UnderAttack => "UNDER ATTACK",
    }
}

fn themed_block<'a>(title: &'a str) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Rgb(60, 90, 110)))
        .title(Span::styled(
            format!(" {title} "),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
}

fn draw(f: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(8),    // status + sparkline
            Constraint::Length(7), // relay route
            Constraint::Length(5), // vault
            Constraint::Length(6), // audit tail
            Constraint::Length(6), // log
        ])
        .split(f.area());

    draw_top(f, app, root[0]);
    draw_relay(f, app, root[1]);
    draw_vault(f, app, root[2]);
    draw_audit(f, app, root[3]);
    draw_log(f, app, root[4]);
}

fn draw_top(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    // ---- status pane ----
    let c = &app.channel;
    let pct = if app.engine.key_length > 0 {
        (c.processed as f64 / app.engine.key_length as f64 * 100.0).min(100.0)
    } else {
        0.0
    };
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("scenario ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{:<10}", app.engine.scenario.label()),
                Style::new().fg(app.engine.scenario.color()).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  noise ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>4.1}%", app.engine.noise_rate * 100.0),
                Style::new().fg(if app.engine.noise_rate > 0.0 { Color::Yellow } else { Color::Green }),
            ),
            Span::styled("  hops ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", app.engine.relay_hops),
                Style::new().fg(if app.engine.relay_hops > 0 { Color::Cyan } else { Color::DarkGray }),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("qber     ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>6.2}%", c.qber * 100.0),
                Style::new()
                    .fg(if c.qber > ATTACK_LINE { Color::Red } else { Color::Cyan })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("threshold", Style::new().fg(Color::DarkGray)),
            Span::styled(format!("{:>6.2}%", c.threshold * 100.0), Style::new().fg(Color::Blue)),
        ]),
        Line::from(vec![
            Span::styled("sifted   ", Style::new().fg(Color::DarkGray)),
            Span::styled(format!("{:>6}", c.sifted), Style::new().fg(Color::White)),
            Span::styled(format!("  of {:>6} qubits", c.processed), Style::new().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("verdict  ", Style::new().fg(Color::DarkGray)),
            Span::styled(class_label(c.class), class_style(c.class)),
        ]),
    ];
    if let Some((msg, ok)) = &app.vault.last_result {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("vault    {msg}"),
            Style::new().fg(if *ok { Color::Green } else { Color::Red }),
        )));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), cols[0]);

    // ---- gauge + sparkline pane ----
    let gauge_area = Rect { height: 1, y: area.y, ..cols[1] };
    let chart_area = Rect { y: area.y + 2, height: area.height.saturating_sub(2), ..cols[1] };
    let gauge = Gauge::default()
        .gauge_style(Style::new().fg(Color::Cyan).bg(Color::Rgb(20, 30, 45)))
        .percent(pct as u16)
        .label(format!("{} / {} qubits", c.processed, app.engine.key_length));
    f.render_widget(gauge, gauge_area);

    let spark = Sparkline::default()
        .block(themed_block("qber history (per-mille)"))
        .data(&c.history)
        .style(Style::new().fg(Color::Cyan));
    f.render_widget(spark, chart_area);
}

fn draw_relay(f: &mut Frame, app: &App, area: Rect) {
    let hops = app.engine.relay_hops;
    let title = if hops == 0 {
        "relay route — direct Alice → Bob".to_string()
    } else {
        format!("relay route — Alice → {hops} relay(s) → Bob")
    };
    let block = themed_block(&title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if hops == 0 {
        f.render_widget(
            Paragraph::new(Span::styled(
                "press R to add trusted relay nodes (quantum repeaters)",
                Style::new().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    }

    let Some(relay) = &app.relay else {
        f.render_widget(
            Paragraph::new(Span::styled("initializing…", Style::new().fg(Color::DarkGray))),
            inner,
        );
        return;
    };

    let mut line1 = vec![Span::styled("● Alice", Style::new().fg(Color::Cyan))];
    for i in 0..hops {
        line1.push(Span::raw(" ── "));
        let intercepted = relay.hops[i].interceptions > 0;
        line1.push(Span::styled(
            format!("R{}", i + 1),
            Style::new().fg(if intercepted { Color::Red } else { Color::Green }),
        ));
    }
    line1.push(Span::raw(" ── "));
    line1.push(Span::styled("● Bob", Style::new().fg(Color::Cyan)));

    let mut line2 = Vec::new();
    for (i, h) in relay.hops.iter().enumerate() {
        if i > 0 {
            line2.push(Span::styled(" · ", Style::new().fg(Color::DarkGray)));
        }
        line2.push(Span::styled(
            format!("{}→{}: {}", h.from, h.to, h.out_qubits),
            Style::new().fg(Color::DarkGray),
        ));
    }

    let line3 = vec![
        Span::styled(
            format!("interceptions: {}", relay.interceptions),
            Style::new().fg(if relay.interceptions > 0 { Color::Red } else { Color::Green }),
        ),
        Span::styled(
            format!("   end-to-end QBER: {:.2}%", relay.mismatch_rate * 100.0),
            Style::new().fg(if relay.mismatch_rate > ATTACK_LINE { Color::Red } else { Color::Cyan }),
        ),
        Span::styled(
            format!("   sifted: {}", relay.matching_bases_count),
            Style::new().fg(Color::DarkGray),
        ),
    ];

    f.render_widget(Paragraph::new(vec![Line::from(line1), Line::from(line2), Line::from(line3)]), inner);
}

fn draw_vault(f: &mut Frame, app: &App, area: Rect) {
    let block = themed_block("document vault — [s]eal  [v]erify  [t]amper  [w]uorum");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines: Vec<Line> = match (&app.vault.doc, &app.vault.last_result) {
        (Some(doc), Some((msg, ok))) => vec![
            Line::from(vec![
                Span::styled("demo-brief.txt ", Style::new().fg(Color::White)),
                Span::styled(format!("sha256:{} ", &doc.meta.sha256[..16]), Style::new().fg(Color::DarkGray)),
                Span::styled(format!("tag:{}", &doc.tag[..16]), Style::new().fg(Color::Magenta)),
            ]),
            Line::from(Span::styled(
                format!("→ {msg}"),
                Style::new().fg(if *ok { Color::Green } else { Color::Red }),
            )),
        ],
        (Some(doc), None) => vec![Line::from(vec![
            Span::styled("demo-brief.txt ", Style::new().fg(Color::White)),
            Span::styled(
                format!("sealed under commitment {}", &doc.key_commitment[..16]),
                Style::new().fg(Color::DarkGray),
            ),
        ])],
        _ => vec![Line::from(Span::styled(
            "press s to seal a demo document with the current session key",
            Style::new().fg(Color::DarkGray),
        ))],
    };
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_audit(f: &mut Frame, app: &App, area: Rect) {
    let root = app.audit.root().unwrap_or_else(|| "—".into());
    let verdict = app.audit.verify_chain();
    let title = format!(
        "merkle audit ledger — root {}…  chain {}",
        &root[..root.len().min(12)],
        if verdict.ok { "✓ intact" } else { "✗ BROKEN" }
    );
    let block = themed_block(&title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    for e in app.audit.recent(inner.height.saturating_sub(1) as usize) {
        let (glyph, color) = if e.accepted { ("✓", Color::Green) } else { ("✗", Color::Red) };
        lines.push(Line::from(vec![
            Span::styled(format!("{:>4} ", e.seq), Style::new().fg(Color::DarkGray)),
            Span::styled(format!("{:<8}", e.kind), Style::new().fg(Color::Cyan)),
            Span::styled(format!("{glyph} "), Style::new().fg(color)),
            Span::styled(
                truncate(&e.detail, inner.width.saturating_sub(24) as usize),
                Style::new().fg(Color::Gray),
            ),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("no audit events yet", Style::new().fg(Color::DarkGray))));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let block = themed_block("pipeline log — 1/2/3 scenario · n/N noise · r/R hops · s/v/t/w vault · Q quit");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let start = app.log.len().saturating_sub(height);
    let lines: Vec<Line> = app.log[start..]
        .iter()
        .map(|l| Line::from(Span::styled(l.clone(), Style::new().fg(Color::Gray))))
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

// ---------------------------------------------------------------------------
// main loop
// ---------------------------------------------------------------------------

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    app.say("TUI dashboard started — QKD channel streaming live");
    app.say(format!(
        "channel: {} qubits · threshold {:.0}% · scenario {}",
        app.engine.key_length,
        app.engine.base_threshold * 100.0,
        app.engine.scenario.label()
    ));

    let res = run_loop(&mut terminal, &mut app);
    restore_terminal(&mut terminal);
    res
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> io::Result<()> {
    let tick_rate = Duration::from_millis(60);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| draw(f, app))?;

        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or(Duration::ZERO);
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                // Fire on press only (Windows sends press + release events).
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                            app.running = false;
                        }
                        KeyCode::Char('1') => {
                            app.engine.scenario = Scenario::Secure;
                            app.reset_channel();
                            app.say("scenario → secure channel");
                        }
                        KeyCode::Char('2') => {
                            app.engine.scenario = Scenario::Attack;
                            app.reset_channel();
                            app.say("scenario → full intercept-resend attack");
                        }
                        KeyCode::Char('3') => {
                            app.engine.scenario = Scenario::Mixed;
                            app.reset_channel();
                            app.say("scenario → mixed 30% intercept ratio");
                        }
                        KeyCode::Tab => {
                            app.engine.scenario = app.engine.scenario.cycle();
                            app.reset_channel();
                            app.say(format!("scenario → {}", app.engine.scenario.label()));
                        }
                        KeyCode::Char('n') => {
                            app.engine.noise_rate = (app.engine.noise_rate - 0.01).max(0.0);
                            app.reset_channel();
                            app.say(format!("fiber noise → {:.0}% (channel reset)", app.engine.noise_rate * 100.0));
                        }
                        KeyCode::Char('N') => {
                            app.engine.noise_rate = (app.engine.noise_rate + 0.01).min(0.20);
                            app.reset_channel();
                            app.say(format!("fiber noise → {:.0}% (channel reset)", app.engine.noise_rate * 100.0));
                        }
                        KeyCode::Char('r') => {
                            app.engine.relay_hops = app.engine.relay_hops.saturating_sub(1);
                            app.reset_channel();
                            app.say(format!("relay hops → {}", app.engine.relay_hops));
                        }
                        KeyCode::Char('R') => {
                            app.engine.relay_hops = (app.engine.relay_hops + 1).min(4);
                            app.reset_channel();
                            app.say(format!("relay hops → {}", app.engine.relay_hops));
                        }
                        KeyCode::Char('s') => app.seal_demo(),
                        KeyCode::Char('v') => app.verify_demo(),
                        KeyCode::Char('t') => app.tamper_demo(),
                        KeyCode::Char('w') => app.quorum_demo(),
                        _ => {}
                    }
                }
            }
        }

        if !app.running {
            return Ok(());
        }

        if last_tick.elapsed() >= tick_rate {
            app.tick();
            last_tick = Instant::now();
        }
    }
}
