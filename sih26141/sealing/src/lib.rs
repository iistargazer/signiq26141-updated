//! Quantum-secured document sealing: bind a file's bytes to a QKD-derived
//! HMAC key and package everything into a portable `.qsig` container.
//!
//! A `.qsig` file is JSON:
//!
//! ```text
//! magic     "QSIG1"
//! meta      { name, size, mime, sha256, sealed_at }
//! audit_ref { first_seq, last_seq, root }   — Merkle audit-log coverage
//! payload   { v, scheme, key_commitment, nonce, tag, quorum, ciphertext }
//! ```
//!
//! Container versioning (`v` field):
//!   * `v = 2` (current): the payload is sealed with **AES-256-GCM**
//!     (authenticated encryption) under the canonical session key. The
//!     container metadata is bound as GCM associated data, so a swapped
//!     document with an intact body fails decryption. The 12-byte GCM nonce
//!     is derived from a fresh random 64-bit per-seal nonce. A separate
//!     HMAC-SHA256 tag over (metadata ‖ plaintext) is kept as an
//!     independent integrity factor.
//!   * `v = 1` (legacy, verified for compatibility): XOR-masked payload with
//!     a SHA-256-CTR keystream — demo-grade confidentiality, no GCM.
//!
//! Security model:
//!   * Key commitment: `SHA-256(canonical_key)` where the canonical key is
//!     the session key with its final byte reduced into GF(251) (the same
//!     masking Shamir splitting applies). This is the single commitment
//!     definition used by sealing, the server, and quorum reconstruction —
//!     v1 containers committed to the raw key instead (kept for verify).
//!   * Verification comparisons are constant-time (GCM tag check is
//!     authenticated-decrypt; the HMAC comparison folds XOR without
//!     early exit).
//!   * Threshold mode: the seal key is Shamir-split across `m` officers;
//!     `k` valid shares reconstruct it (feature 7). Below k shares the
//!     document is cryptographically unrecoverable.
//!   * AEAD is the load-bearing confidentiality primitive; the HMAC is a
//!     belt-and-braces integrity factor.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Container magic + format family.
pub const MAGIC: &str = "QSIG1";

/// Current container format version (AES-256-GCM payload).
pub const FORMAT_VERSION: u32 = 2;

/// Envelope format version (v3): the container JSON itself is sealed inside
/// AES-256-GCM, so a `.qsig` file on disk shows only the header + ciphertext
/// — no filename, no size, no hashes. Only the key commitment (a SHA-256
/// digest — leaks nothing) and the envelope nonce stay outside.
pub const ENVELOPE_VERSION: u32 = 3;

fn hmac_tag(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Constant-time byte-slice equality (no early exit on mismatch).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Canonical seal key: the session key with its final byte reduced into
/// GF(251). Every commitment, seal, and verification operates on this
/// canonical form so the Shamir path (which reconstructs residues mod 251)
/// and the direct-key path agree byte for byte.
pub fn canonicalize_key(secret: &[u8]) -> Vec<u8> {
    let mut k = secret.to_vec();
    if let Some(last) = k.last_mut() {
        *last %= GF_P;
    }
    k
}

/// The single key-commitment definition: SHA-256 of the canonical key.
pub fn key_commitment_for(canonical_key: &[u8]) -> String {
    hex::encode(sha256(canonical_key))
}

/// Legacy v1 keystream: SHA-256 in counter mode as an XOR mask.
/// Kept only for verifying v1 containers; new seals use AES-256-GCM.
fn keystream(secret: &[u8], nonce: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(secret);
        h.update(nonce.to_le_bytes());
        h.update(counter.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Derive the 12-byte AES-GCM nonce from the 8-byte per-seal nonce
/// (64 bits of per-seal randomness + 4 zero counter bytes).
fn gcm_nonce(nonce: u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[..8].copy_from_slice(&nonce.to_le_bytes());
    iv
}

// ---------------------------------------------------------------------------
// Metadata + container
// ---------------------------------------------------------------------------

/// Document metadata bound into the seal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DocumentMeta {
    pub name: String,
    pub size: usize,
    pub mime: String,
    /// SHA-256 of the plaintext file bytes, hex.
    pub sha256: String,
    pub sealed_at: String,
}

/// Reference into the Merkle audit log covering this seal's lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AuditRef {
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// Audit root at seal time (the log may grow afterwards — the seal pins
    /// the root that existed when the document was sealed).
    pub root: Option<String>,
}

/// Threshold-authorization parameters recorded in the container.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct QuorumSpec {
    /// Shares required to reconstruct the seal key (k of m).
    pub threshold: Option<u8>,
    pub shares: Option<u8>,
    /// Per-officer commitments (officer i holds share i+1):
    /// SHA-256(x_i ‖ y_i) as hex.
    pub officer_commitments: Vec<String>,
}

/// The full `.qsig` container payload (the JSON after the magic line).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QsigDocument {
    pub magic: String,
    pub meta: DocumentMeta,
    /// The canonical sealing key (v3 envelope only). Never serialized —
    /// lives only in memory so the envelope codec can seal/unseal the
    /// container JSON without every call site re-deriving the key.
    #[serde(skip)]
    pub key: Vec<u8>,
    pub audit_ref: AuditRef,
    /// HMAC scheme identifier (informational).
    pub scheme: String,
    /// Container format version. Absent/1 = legacy XOR payload; 2 = GCM.
    #[serde(default)]
    pub v: u32,
    /// SHA-256(canonical key) — binds the container to the sealing key.
    pub key_commitment: String,
    /// Fresh 64-bit per-seal nonce (GCM nonce derivation / legacy keystream).
    pub nonce: u64,
    /// HMAC-SHA256 over (meta ‖ plaintext) under the canonical key, hex.
    pub tag: String,
    pub quorum: QuorumSpec,
    /// v2: AES-256-GCM ciphertext (plaintext bound to meta as AAD).
    /// v1: XOR-masked file bytes. Serialized as standard base64 — a JSON
    /// number array would inflate a 5 MB payload to ~20 MB of ASCII digits.
    /// Parsing still accepts the legacy array form for old containers.
    #[serde(with = "b64_bytes")]
    pub ciphertext: Vec<u8>,
    /// Attached quantum digital signature (v2.1): a teleportation-based QDS
    /// signature over the document's SHA-256, produced by the shared Trent
    /// notary at seal time. Optional so v1/v2.0 containers still parse.
    /// Unlock requires this signature to verify — the document is locked
    /// behind BOTH the symmetric seal key AND the quantum signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qds_sig: Option<QdsSigAttachment>,
}

/// A teleportation-QDS signature attached to a sealed container.
/// `correction_bits` is the flattened Bell-outcome sequence (0/1 bytes,
/// base64-encoded — the same wire codec as the payload ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QdsSigAttachment {
    #[serde(with = "b64_bytes")]
    pub correction_bits: Vec<u8>,
    pub nonce: u64,
    /// Trent public-key commitment in force when signed.
    pub key_commitment: String,
    /// Scheme label ("teleport-qds-v1").
    pub scheme: String,
}

/// serde codec: ciphertext as standard base64 (accepts legacy number arrays).
mod b64_bytes {
    use serde::{Deserializer, Serializer};

    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(v.len().div_ceil(3) * 4);
        for chunk in v.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(TABLE[(n >> 18) as usize & 63] as char);
            out.push(TABLE[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_any(B64Visitor)
    }

    struct B64Visitor;

    impl<'de> serde::de::Visitor<'de> for B64Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("base64 string or legacy byte array")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            decode_b64(v).ok_or_else(|| E::custom("invalid base64 ciphertext"))
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Vec<u8>, A::Error> {
            // Legacy containers (and serde_json byte serialization).
            let mut out = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    fn decode_b64(s: &str) -> Option<Vec<u8>> {
        fn val(c: u8) -> Option<u32> {
            match c {
                b'A'..=b'Z' => Some((c - b'A') as u32),
                b'a'..=b'z' => Some((c - b'a' + 26) as u32),
                b'0'..=b'9' => Some((c - b'0' + 52) as u32),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }
        let bytes: Vec<u8> = s
            .bytes()
            .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
            .collect();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes.chunks(4) {
            if chunk.len() == 1 {
                return None;
            }
            let mut n: u32 = 0;
            for (i, &c) in chunk.iter().enumerate() {
                n |= val(c)? << (18 - 6 * i);
            }
            out.push((n >> 16) as u8);
            if chunk.len() > 2 {
                out.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                out.push(n as u8);
            }
        }
        Some(out)
    }
}

/// Outcome of verifying a sealed document.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationOutcome {
    /// HMAC tag matched under the provided (or reconstructed) key.
    pub authentic: bool,
    /// The plaintext file hash matches the recorded metadata hash
    /// (checked after decryption/unmasking). For v2 this also requires the
    /// GCM authentication tag to have verified.
    pub integrity: bool,
    /// Container magic/version accepted.
    pub format_ok: bool,
    /// key_commitment matches SHA-256 of the verification key (canonical).
    pub key_match: bool,
    /// Which key unlocked the container: "direct" or "quorum k-of-m".
    pub unlocked_via: String,
    pub note: String,
    /// Payload scheme that verified ("aes-256-gcm+sha256-hmac/qkd/v2" or
    /// the legacy xor scheme).
    #[serde(rename = "payloadScheme")]
    pub payload_scheme: String,
}

impl VerificationOutcome {
    pub fn passed(&self) -> bool {
        self.format_ok && self.authentic && self.integrity && self.key_match
    }
}

// ---------------------------------------------------------------------------
// Sealing + verification
// ---------------------------------------------------------------------------

/// Build a sealed container for `file_bytes` under `secret_hex` (the
/// QKD-derived shared secret). `audit` pins the current audit-log coverage.
#[allow(clippy::too_many_arguments)]
pub fn seal_document(
    file_name: &str,
    mime: &str,
    file_bytes: &[u8],
    secret_hex: &str,
    sealed_at: &str,
    audit: AuditRef,
    quorum: QuorumSpec,
    rng: &mut impl Rng,
) -> Result<QsigDocument, String> {
    let secret = hex::decode(secret_hex).map_err(|_| "seal key is not valid hex".to_string())?;
    if secret.is_empty() {
        return Err("seal key must not be empty".into());
    }

    let key = canonicalize_key(&secret);
    let meta = DocumentMeta {
        name: file_name.to_string(),
        size: file_bytes.len(),
        mime: mime.to_string(),
        sha256: hex::encode(sha256(file_bytes)),
        sealed_at: sealed_at.to_string(),
    };

    let nonce: u64 = rng.gen();
    // Domain separation: the HMAC binds the metadata into the tag as well,
    // so a swapped document with an intact body still fails verification.
    let mut bound = Vec::with_capacity(file_bytes.len() + 256);
    bound.extend_from_slice(&serde_json::to_vec(&meta).map_err(|e| e.to_string())?);
    bound.push(0u8);
    bound.extend_from_slice(file_bytes);
    let tag = hex::encode(hmac_tag(&key, &bound));

    // AES-256-GCM with the metadata as associated data: tampering with the
    // metadata breaks decryption before the HMAC check is even reached.
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let aad = serde_json::to_vec(&meta).map_err(|e| e.to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&gcm_nonce(nonce)),
            Payload { msg: file_bytes, aad: &aad },
        )
        .map_err(|e| format!("payload encryption failed: {e}"))?;

    Ok(QsigDocument {
        magic: MAGIC.into(),
        meta,
        audit_ref: audit,
        scheme: "aes-256-gcm+sha256-hmac/qkd".into(),
        v: FORMAT_VERSION,
        key_commitment: key_commitment_for(&key),
        nonce,
        tag,
        quorum,
        ciphertext,
        qds_sig: None,
        key,
    })
}

/// Serialize a container to `.qsig` bytes.
///
/// v3 (envelope): header line + AES-256-GCM seal over the container JSON —
/// opaque to anyone without the key (the "locked document" look: opening
/// the file in an editor shows noise, not metadata). Header keeps only
/// `QSIG3 <v> <nonce> <key_commitment>`.
/// v2 and below (legacy, when `envelope=false`): magic line + JSON, base64
/// payload — kept for backward compatibility with old containers.
pub fn container_bytes(doc: &QsigDocument) -> Vec<u8> {
    container_bytes_opt(doc, true)
}

/// As `container_bytes`, with explicit envelope choice.
pub fn container_bytes_opt(doc: &QsigDocument, envelope: bool) -> Vec<u8> {
    let json = serde_json::to_vec(doc).unwrap_or_default();
    if !envelope || doc.key.len() != 32 {
        // Legacy clear-JSON container (v2 and older on-disk format).
        let mut out = Vec::with_capacity(512 + json.len() * 4 / 3);
        out.extend_from_slice(MAGIC.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(json.as_slice());
        return out;
    }
    let mut out = Vec::with_capacity(96 + json.len() + 16);
    out.extend_from_slice(
        format!(
            "QSIG3 {} {} {}",
            ENVELOPE_VERSION, doc.nonce, doc.key_commitment
        )
        .as_bytes(),
    );
    out.push(b'\n');
    let cipher = Aes256Gcm::new_from_slice(&doc.key).expect("32-byte key");
    let sealed = cipher
        .encrypt(Nonce::from_slice(&gcm_nonce(doc.nonce)), Payload { msg: &json, aad: MAGIC.as_bytes() })
        .expect("envelope encryption cannot fail for a valid key");
    out.extend_from_slice(&sealed);
    out
}

/// Parse `.qsig` bytes back into a container.
///
/// Accepts both on-disk formats:
/// * `QSIG3 <v> <nonce> <commitment>\n<ciphertext>` — the v3 envelope. The
///   container JSON cannot be decoded here (it is sealed); the returned
///   document carries the header fields and an **empty meta/metadata** that
///   is filled in by [`unseal_envelope`] once the key is supplied.
/// * `QSIG1\n<json>` — the legacy v1/v2 clear-JSON container.
#[derive(Debug, Clone)]
pub struct ParsedContainer {
    pub doc: QsigDocument,
    /// True when the bytes were a v3 sealed envelope (meta pending unseal).
    pub sealed_envelope: bool,
}

pub fn parse_container(bytes: &[u8]) -> Result<QsigDocument, String> {
    parse_container_full(bytes).map(|p| p.doc)
}

/// Parse preserving the envelope distinction (see [`parse_container`]).
pub fn parse_container_full(bytes: &[u8]) -> Result<ParsedContainer, String> {
    // The v3 envelope body is binary ciphertext — split the header off as
    // bytes first and only require UTF-8 for the (text) header line.
    let header_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| "container has no header line".to_string())?;
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "container header is not UTF-8".to_string())?
        .trim();
    let body = &bytes[header_end + 1..];
    let magic = header;

    // ---- v3 sealed envelope ----
    if magic.starts_with("QSIG3 ") {
        let mut parts = magic.split_ascii_whitespace();
        parts.next(); // "QSIG3"
        let ver: u32 = parts
            .next()
            .ok_or_else(|| "envelope header missing version".to_string())?
            .parse()
            .map_err(|_| "envelope version is not a number".to_string())?;
        let nonce: u64 = parts
            .next()
            .ok_or_else(|| "envelope header missing nonce".to_string())?
            .parse()
            .map_err(|_| "envelope nonce is not a number".to_string())?;
        let commitment = parts
            .next()
            .ok_or_else(|| "envelope header missing key commitment".to_string())?
            .to_string();
        if body.is_empty() {
            return Err("envelope body is empty".to_string());
        }
        return Ok(ParsedContainer {
            doc: QsigDocument {
                magic: MAGIC.into(),
                meta: DocumentMeta {
                    name: String::new(),
                    size: body.len(),
                    mime: "application/octet-stream".into(),
                    sha256: String::new(),
                    sealed_at: String::new(),
                },
                audit_ref: AuditRef::default(),
                scheme: "aes-256-gcm+sha256-hmac/qkd".into(),
                v: FORMAT_VERSION,
                key_commitment: commitment,
                nonce,
                tag: String::new(),
                quorum: QuorumSpec::default(),
                ciphertext: body.to_vec(),
                qds_sig: None,
                key: Vec::new(),
            },
            sealed_envelope: ver == ENVELOPE_VERSION,
        });
    }

    // ---- legacy clear-JSON container ----
    if magic != MAGIC {
        return Err(format!("unknown container format: expected magic {MAGIC} or QSIG3, got '{magic}'"));
    }
    let json = std::str::from_utf8(body).map_err(|_| "container JSON is not UTF-8".to_string())?;
    let doc: QsigDocument =
        serde_json::from_str(json).map_err(|e| format!("container JSON invalid: {e}"))?;
    Ok(ParsedContainer { doc, sealed_envelope: false })
}

/// Unseal a v3 envelope with `secret_hex`: decrypts the container JSON and
/// replaces the placeholder document with the real one. Also verifies the
/// key commitment so a wrong key fails here with a precise reason.
pub fn unseal_envelope(envelope: &QsigDocument, secret_hex: &str) -> Result<QsigDocument, String> {
    let secret = hex::decode(secret_hex).map_err(|_| "seal key is not valid hex".to_string())?;
    let key = canonicalize_key(&secret);
    let got = key_commitment_for(&key);
    if got != envelope.key_commitment {
        return Err(format!(
            "key commitment mismatch: container sealed under a different key (got {got}…, want {}…) supposed",
            &envelope.key_commitment[..16.min(envelope.key_commitment.len())]
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let json = cipher
        .decrypt(
            Nonce::from_slice(&gcm_nonce(envelope.nonce)),
            Payload { msg: envelope.ciphertext.as_slice(), aad: MAGIC.as_bytes() },
        )
        .map_err(|_| "envelope decryption failed — wrong key or corrupted container".to_string())?;
    let mut doc: QsigDocument =
        serde_json::from_slice(&json).map_err(|e| format!("container JSON invalid after unseal: {e}"))?;
    doc.key = key;
    Ok(doc)
}

/// Open (unlock) a sealed container: full verification first, then return
/// the original file bytes. This is the "password-protected document" step —
/// the file is only recoverable under the correct quantum-derived key, and
/// (when a QDS signature is attached) only when Trent's signature over the
/// document hash verifies. Callers layer the QDS check on top (the sealing
/// crate is intentionally QDS-agnostic).
pub fn open_document(
    doc: &QsigDocument,
    secret_hex: &str,
) -> Result<(Vec<u8>, VerificationOutcome), String> {
    let outcome = verify_document(doc, secret_hex)?;
    if !outcome.passed() {
        return Err(outcome.note);
    }
    // Recover the plaintext: v2 GCM decrypt, v1 XOR unmask.
    let secret = hex::decode(secret_hex).map_err(|_| "verification key is not valid hex".to_string())?;
    let plaintext = if doc.v >= FORMAT_VERSION {
        let key = canonicalize_key(&secret);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        let aad = serde_json::to_vec(&doc.meta).map_err(|e| e.to_string())?;
        cipher
            .decrypt(
                Nonce::from_slice(&gcm_nonce(doc.nonce)),
                Payload { msg: doc.ciphertext.as_slice(), aad: aad.as_slice() },
            )
            .map_err(|_| "payload decryption failed after verification (state changed?)".to_string())?
    } else {
        let mask = keystream(&secret, doc.nonce, doc.ciphertext.len());
        doc.ciphertext.iter().zip(mask.iter()).map(|(b, m)| b ^ m).collect()
    };
    Ok((plaintext, outcome))
}

/// Verify a container against `secret_hex`. A single flipped byte anywhere in
/// the file, the metadata, or the tag fails verification (GCM authentication
/// for v2 payloads, HMAC for the tag, SHA-256 for the plaintext).
pub fn verify_document(doc: &QsigDocument, secret_hex: &str) -> Result<VerificationOutcome, String> {
    let secret = hex::decode(secret_hex).map_err(|_| "verification key is not valid hex".to_string())?;
    if secret.is_empty() {
        return Err("verification key must not be empty".into());
    }

    let is_v2 = doc.v >= FORMAT_VERSION;
    let key = canonicalize_key(&secret);

    let format_ok = doc.magic == MAGIC;
    // v2 commits to the canonical key; legacy v1 committed to the raw bytes.
    let key_match = if is_v2 {
        doc.key_commitment == key_commitment_for(&key)
    } else {
        doc.key_commitment == hex::encode(sha256(&secret))
    };

    // Recover the plaintext according to the payload scheme.
    let (plaintext, decrypted) = if is_v2 {
        match Aes256Gcm::new_from_slice(&key) {
            Ok(cipher) => {
                let aad = serde_json::to_vec(&doc.meta).map_err(|e| e.to_string())?;
                match cipher.decrypt(
                    Nonce::from_slice(&gcm_nonce(doc.nonce)),
                    Payload { msg: doc.ciphertext.as_slice(), aad: aad.as_slice() },
                ) {
                    Ok(pt) => (pt, true),
                    // Wrong key or tampered ciphertext/metadata: report as a
                    // verdict (not an error) so the UI can show the reason.
                    Err(_) => (Vec::new(), false),
                }
            }
            Err(_) => (Vec::new(), false),
        }
    } else {
        // Legacy XOR unmask under the raw (un-canonicalized) key.
        let mask = keystream(&secret, doc.nonce, doc.ciphertext.len());
        let pt: Vec<u8> = doc.ciphertext.iter().zip(mask.iter()).map(|(b, m)| b ^ m).collect();
        (pt, true)
    };

    // Rebuild the HMAC binding (metadata recorded in the container).
    let mut bound = Vec::with_capacity(plaintext.len() + 256);
    bound.extend_from_slice(&serde_json::to_vec(&doc.meta).map_err(|e| e.to_string())?);
    bound.push(0u8);
    bound.extend_from_slice(&plaintext);
    let expected = hmac_tag(&key, &bound);
    let authentic = hex::decode(&doc.tag).map(|t| ct_eq(&t, &expected)).unwrap_or(false);

    let integrity = decrypted && hex::encode(sha256(&plaintext)) == doc.meta.sha256;

    let note = if !format_ok {
        "container format not recognized"
    } else if !key_match {
        "key commitment mismatch: document sealed under a different session key (key possibly compromised)"
    } else if is_v2 && !decrypted {
        "payload decryption failed: ciphertext, metadata, or key does not authenticate (AES-GCM tag mismatch)"
    } else if !authentic {
        "HMAC tag mismatch: document bytes or metadata were modified"
    } else if !integrity {
        "payload hash mismatch after decryption"
    } else {
        "document verified: AES-GCM payload, HMAC tag and payload hash all match the QKD session key"
    };

    Ok(VerificationOutcome {
        authentic,
        integrity,
        format_ok,
        key_match,
        unlocked_via: "direct".into(),
        note: note.into(),
        payload_scheme: if is_v2 {
            "aes-256-gcm+sha256-hmac/qkd/v2".into()
        } else {
            "xor-sha256-ctr+sha256-hmac/qkd/v1".into()
        },
    })
}

// ---------------------------------------------------------------------------
// Feature 7: Shamir k-of-m threshold authorization.
//
// Byte-wise Shamir over GF(251): one random degree-(k−1) polynomial per key
// byte, f_b(0) = canonical key byte b. The final key byte is masked into
// GF(251) (< 2 bits of entropy lost) so field arithmetic is exact — that
// masked form IS the canonical key used for commitments, sealing, and
// verification, so reconstructed keys match sealed commitments exactly.
// ---------------------------------------------------------------------------

/// One officer's share: (x, y[32]) over GF(251), byte-wise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Officer index (1..=m); x-coordinate of the Shamir polynomial.
    pub x: u8,
    /// Per-byte y-coordinates for the 32 key bytes.
    pub y: Vec<u8>,
    /// Commitment = SHA-256(x ‖ share bytes) — lets a verifier validate a
    /// presented share without holding it.
    pub commitment: String,
}

/// Public share commitment used by the server: SHA-256(x ‖ y bytes).
pub fn share_commitment(x: u8, y: &[u8]) -> String {
    let mut input = Vec::with_capacity(1 + y.len());
    input.push(x);
    input.extend_from_slice(y);
    hex::encode(sha256(&input))
}

const GF_P: u8 = 251;

fn gf_inv(a: u8) -> u8 {
    // Fermat: a^(p-2) mod p, all arithmetic in u16 to avoid overflow.
    let mut result: u16 = 1;
    let mut exp: u16 = GF_P as u16 - 2;
    let mut base: u16 = a as u16 % GF_P as u16;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % GF_P as u16;
        }
        base = base * base % GF_P as u16;
        exp >>= 1;
    }
    result as u8
}

/// Split a 32-byte hex secret into `m` shares with threshold `k`.
/// Byte-wise Shamir over GF(251); byte 31 of the secret is masked to < 251
/// (loses < 2 bits of entropy — acceptable for the demo, documented).
pub fn split_secret(
    secret_hex: &str,
    threshold: u8,
    shares: u8,
    rng: &mut impl Rng,
) -> Result<Vec<KeyShare>, String> {
    if !(2..=15).contains(&threshold) {
        return Err("threshold must be between 2 and 15".into());
    }
    if shares < threshold || shares > 15 {
        return Err("shares must be >= threshold and <= 15".into());
    }
    let secret = hex::decode(secret_hex).map_err(|_| "secret is not valid hex".to_string())?;
    if secret.len() != 32 {
        return Err("secret must be a 32-byte hex string (SHA-256 output)".into());
    }

    // The canonical key (byte 31 masked) is what gets split — and what the
    // commitment covers, so reconstruction and commitment agree exactly.
    let key = canonicalize_key(&secret);

    // One polynomial per byte: coefficients drawn ONCE (c0 = key byte).
    let mut coefs: Vec<Vec<u16>> = Vec::with_capacity(32);
    for &b in &key {
        let mut row = Vec::with_capacity(threshold as usize);
        row.push(b as u16);
        for _ in 1..threshold {
            row.push(rng.gen_range(0..GF_P as u16));
        }
        coefs.push(row);
    }

    let mut all = Vec::with_capacity(shares as usize);
    for x in 1..=shares {
        // Evaluate every byte polynomial at this share's x (Horner).
        let y: Vec<u8> = coefs
            .iter()
            .map(|row| {
                let mut acc: u16 = 0;
                for &c in row.iter().rev() {
                    acc = (acc * x as u16 + c) % GF_P as u16;
                }
                acc as u8
            })
            .collect();
        let commitment = share_commitment(x, &y);
        all.push(KeyShare { x, y, commitment });
    }
    Ok(all)
}

/// Reconstruct the canonical 32-byte key from `k` valid shares
/// (Lagrange interpolation at 0).
pub fn combine_shares(shares: &[KeyShare]) -> Result<String, String> {
    if shares.len() < 2 {
        return Err("need at least 2 shares".into());
    }
    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    if xs.iter().any(|&x| x == 0) {
        return Err("share x must be nonzero".into());
    }
    if xs.iter().any(|x| xs.iter().filter(|&&y| y == *x).count() > 1) {
        return Err("duplicate share x-coordinates".into());
    }

    let mut key = vec![0u8; 32];
    for byte_i in 0..32 {
        let mut acc: u16 = 0;
        for (i, s) in shares.iter().enumerate() {
            // Lagrange coefficient l_i(0) = Π_{j≠i} x_j / (x_j − x_i) mod p
            let mut num: u16 = 1;
            let mut den: u16 = 1;
            for (j, other) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xi = s.x as u16;
                let xj = other.x as u16;
                num = num * xj % GF_P as u16;
                let diff = (xj + GF_P as u16 - xi) % GF_P as u16;
                den = den * diff % GF_P as u16;
            }
            let l = num * gf_inv(den as u8) as u16 % GF_P as u16;
            acc = (acc + l * s.y[byte_i] as u16) % GF_P as u16;
        }
        key[byte_i] = acc as u8;
    }
    Ok(hex::encode(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const SECRET: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    fn seal() -> QsigDocument {
        seal_document(
            "report.pdf",
            "application/pdf",
            b"CONFIDENTIAL: board meeting minutes Q3",
            SECRET,
            "2026-09-15T00:00:00Z",
            AuditRef::default(),
            QuorumSpec::default(),
            &mut StdRng::seed_from_u64(1),
        )
        .unwrap()
    }

    #[test]
    fn seal_verify_round_trip() {
        let doc = seal();
        assert_eq!(doc.v, FORMAT_VERSION);
        let out = verify_document(&doc, SECRET).unwrap();
        assert!(out.passed(), "{}", out.note);
        assert_eq!(out.unlocked_via, "direct");
        assert!(out.payload_scheme.contains("v2"));

        let bytes = container_bytes(&doc);
        // v3 envelope: on-disk bytes are opaque — nothing but header+noise.
        assert!(bytes.starts_with(b"QSIG3 "), "new seals must use the sealed envelope format");
        let header_end = bytes.iter().position(|&b| b == b'\n').unwrap();
        let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
        assert!(!header.contains("report.pdf"), "envelope header must hide the filename");
        let envelope = parse_container(&bytes).unwrap();
        assert!(envelope.meta.name.is_empty(), "sealed meta stays hidden until unseal");
        let parsed = unseal_envelope(&envelope, SECRET).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn single_byte_tamper_fails() {
        let mut doc = seal();
        doc.ciphertext[0] ^= 1;
        let out = verify_document(&doc, SECRET).unwrap();
        assert!(!out.passed(), "{}", out.note);
        assert!(!out.integrity, "GCM must reject tampered ciphertext");

        // Tampering with the metadata (AAD) must equally fail decryption.
        let mut doc2 = seal();
        doc2.meta.name = "innocent.txt".into();
        let out2 = verify_document(&doc2, SECRET).unwrap();
        assert!(!out2.passed(), "{}", out2.note);
        assert!(!out2.authentic || !out2.integrity);
    }

    #[test]
    fn wrong_key_fails_as_compromise() {
        let doc = seal();
        let other = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let out = verify_document(&doc, other).unwrap();
        assert!(!out.passed());
        assert!(!out.key_match, "wrong session key must fail the commitment check");
    }

    #[test]
    fn commitment_matches_canonical_and_reconstructed_keys() {
        // The canonical key commitment agrees with a Shamir reconstruction.
        let mut rng = StdRng::seed_from_u64(9);
        let shares = split_secret(SECRET, 3, 5, &mut rng).unwrap();
        let recovered = combine_shares(&shares[1..4]).unwrap();
        let doc = seal();
        // Both the reconstructed key and the original verify the container.
        assert!(verify_document(&doc, &recovered).unwrap().passed());
        assert_eq!(
            key_commitment_for(&canonicalize_key(&hex::decode(SECRET).unwrap())),
            doc.key_commitment
        );
    }

    #[test]
    fn open_document_round_trips_the_original_file() {
        let original = b"CONFIDENTIAL: the real file bytes, recoverable only under the key";
        let doc = seal_document(
            "minutes.txt",
            "text/plain",
            original,
            SECRET,
            "2026-09-17T00:00:00Z",
            AuditRef::default(),
            QuorumSpec::default(),
            &mut StdRng::seed_from_u64(5),
        )
        .unwrap();
        let (plaintext, outcome) = open_document(&doc, SECRET).unwrap();
        assert_eq!(plaintext, original);
        assert!(outcome.passed());
        // A wrong key cannot open the document at all.
        let wrong = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        assert!(open_document(&doc, wrong).is_err());
        // A tampered container cannot be opened either.
        let mut tampered = doc.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(open_document(&tampered, SECRET).is_err());
    }

    #[test]
    fn qds_sig_attachment_round_trips() {
        let mut doc = seal();
        assert!(doc.qds_sig.is_none());
        doc.qds_sig = Some(QdsSigAttachment {
            correction_bits: vec![0, 1, 1, 0],
            nonce: 7,
            key_commitment: "abc".into(),
            scheme: "teleport-qds-v1".into(),
        });
        let parsed = unseal_envelope(&parse_container(&container_bytes(&doc)).unwrap(), SECRET).unwrap();
        assert_eq!(parsed.qds_sig, doc.qds_sig);
        // Legacy containers (no field) still parse.
        let legacy_bytes = container_bytes_opt(&seal(), false);
        let legacy = parse_container(&legacy_bytes).unwrap();
        assert!(legacy.qds_sig.is_none());
    }

    #[test]
    fn legacy_v1_container_still_verifies() {
        // Hand-build a v1 container the old code would have produced.
        let secret = hex::decode(SECRET).unwrap();
        let plaintext = b"legacy xor payload";
        let nonce: u64 = 0x1234_5678_9abc_def0;
        let mask = keystream(&secret, nonce, plaintext.len());
        let ciphertext: Vec<u8> = plaintext.iter().zip(mask.iter()).map(|(b, m)| b ^ m).collect();
        let meta = DocumentMeta {
            name: "legacy.txt".into(),
            size: plaintext.len(),
            mime: "text/plain".into(),
            sha256: hex::encode(sha256(plaintext)),
            sealed_at: "2025-01-01T00:00:00Z".into(),
        };
        let mut bound = Vec::new();
        bound.extend_from_slice(&serde_json::to_vec(&meta).unwrap());
        bound.push(0u8);
        bound.extend_from_slice(plaintext);
        let doc = QsigDocument {
            magic: MAGIC.into(),
            meta,
            audit_ref: AuditRef::default(),
            scheme: "hmac-sha256/qkd".into(),
            v: 1,
            key_commitment: hex::encode(sha256(&secret)), // legacy: raw key
            nonce,
            tag: hex::encode(hmac_tag(&secret, &bound)),
            quorum: QuorumSpec::default(),
            ciphertext,
            qds_sig: None,
            key: secret.clone(),
        };
        let out = verify_document(&doc, SECRET).unwrap();
        assert!(out.passed(), "{}", out.note);
        assert!(out.payload_scheme.contains("v1"));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let doc = seal();
        // Verdict is reported (not an error) when the field is wrong.
        let mut tampered = doc.clone();
        tampered.magic = "QSIG0".into();
        assert!(!verify_document(&tampered, SECRET).unwrap().format_ok);
        // Corrupting the raw container's magic line fails parsing.
        let mut raw = container_bytes(&doc);
        raw[0] = b'X';
        assert!(parse_container(&raw).is_err());
    }

    #[test]
    fn shamir_round_trip() {
        let mut rng = StdRng::seed_from_u64(9);
        let shares = split_secret(SECRET, 3, 5, &mut rng);
        let shares = shares.unwrap();
        assert_eq!(shares.len(), 5);
        // Any k shares reconstruct the canonical key.
        let recovered = combine_shares(&shares[1..4]).unwrap();
        let canonical = canonicalize_key(&hex::decode(SECRET).unwrap());
        assert_eq!(hex::decode(&recovered).unwrap(), canonical);
        // A different subset also works.
        assert_eq!(combine_shares(&shares[0..3]).unwrap(), recovered);
    }

    #[test]
    fn shamir_below_threshold_fails() {
        let mut rng = StdRng::seed_from_u64(10);
        let shares = split_secret(SECRET, 3, 5, &mut rng).unwrap();
        let recovered = combine_shares(&shares[..2]).unwrap();
        assert_ne!(recovered, hex::encode(canonicalize_key(&hex::decode(SECRET).unwrap())));
    }

    #[test]
    fn shamir_rejects_duplicate_x() {
        let mut rng = StdRng::seed_from_u64(11);
        let shares = split_secret(SECRET, 2, 3, &mut rng).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(combine_shares(&dup).is_err());
    }

    #[test]
    fn keystream_is_deterministic_and_key_dependent() {
        let a = keystream(&[1u8; 32], 42, 64);
        let b = keystream(&[1u8; 32], 42, 64);
        let c = keystream(&[2u8; 32], 42, 64);
        assert_eq!(a, b);
        assert_neq_placeholder(&a, &c);
    }

    // Kept separate so the constant-time helper is exercised too.
    fn assert_neq_placeholder(a: &[u8], b: &[u8]) {
        assert!(!ct_eq(a, b));
    }

    #[test]
    fn ct_eq_matches_slice_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn container_stays_compact_for_large_payloads() {
        // 1 MB of payload must NOT balloon into a JSON number array.
        let big = vec![0x5Au8; 1024 * 1024];
        let doc = seal_document(
            "big.bin",
            "application/octet-stream",
            &big,
            SECRET,
            "2026-09-16T00:00:00Z",
            AuditRef::default(),
            QuorumSpec::default(),
            &mut StdRng::seed_from_u64(3),
        )
        .unwrap();
        let bytes = container_bytes(&doc);
        assert!(
            bytes.len() < big.len() * 3 / 2 + 96,
            "container is {} bytes for {} payload — base64 framing + header must stay under ~1.5×",
            bytes.len(),
            big.len()
        );
        let parsed = unseal_envelope(&parse_container(&bytes).unwrap(), SECRET).unwrap();
        assert!(verify_document(&parsed, SECRET).unwrap().passed());
    }

    #[test]
    fn legacy_number_array_ciphertext_still_parses() {
        // A container JSON with the pre-b64 array encoding must still verify.
        let doc = seal();
        let json = serde_json::json!({
            "magic": doc.magic,
            "meta": doc.meta,
            "audit_ref": doc.audit_ref,
            "scheme": doc.scheme,
            "v": doc.v,
            "key_commitment": doc.key_commitment,
            "nonce": doc.nonce,
            "tag": doc.tag,
            "quorum": doc.quorum,
            "ciphertext": doc.ciphertext, // serde_json emits a number array
        });
        let bytes = format!("{}\n{}", MAGIC, json);
        let parsed = parse_container(bytes.as_bytes()).unwrap();
        assert_eq!(parsed.ciphertext, doc.ciphertext);
        assert!(verify_document(&parsed, SECRET).unwrap().passed());
    }
}
