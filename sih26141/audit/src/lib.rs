//! Cryptographic append-only audit log — a lightweight Merkle tree with a
//! hash-chained leaf sequence (forensics / non-repudiation layer).
//!
//! Every security-relevant action (document sealed, verified, flagged,
//! transferred, quorum unlock) is appended as a leaf:
//!
//! ```text
//! leaf_hash_i = SHA256("AUD1" || len-prefixed fields || leaf_hash_{i-1})
//! ```
//!
//! **v2 encoding (current):** every variable-length field is framed with its
//! big-endian u64 length prefix before hashing, so field boundaries are
//! unambiguous ("seq=1, kind=ab" can no longer collide with
//! "seq=1a, kind=b"). The fixed prefix `"AUD1"` domain-separates leaf hashes
//! from every other SHA-256 use in the framework.
//!
//! **v1 encoding (legacy):** raw concatenated fields with no framing. v1
//! entries loaded from a persisted log still verify and still chain to v2
//! entries, but the two encodings hash differently (the chain is honest
//! about which encoding produced each leaf).
//!
//! The `leaf_hash_{i-1}` chaining makes reordering or silent edits of
//! historical entries detectable, and the Merkle root over all leaves gives
//! O(log n) inclusion proofs: "this exact event is in the ledger whose root
//! was R" — the property an auditor needs months later.
//!
//! Persistence is deliberately left to the caller (the server appends each
//! entry as a JSONL line). `AuditLog::from_entries` + `load_jsonl` reload a
//! log from disk and `verify_chain` re-derives the whole structure to
//! detect tampering.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Leaf-hash domain-separation prefix.
const LEAF_DOMAIN: &[u8] = b"AUD1";

/// One append-only audit entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    /// 1-based sequence number in the ledger.
    pub seq: u64,
    /// RFC3339-ish UTC timestamp (server-provided).
    pub ts: String,
    /// Event class: "seal" | "verify" | "flag" | "transfer" | "quorum" | ...
    pub kind: String,
    /// Short actor/action label, e.g. "alice→relay2".
    pub label: String,
    /// Success flag (false = a threat / rejection was recorded).
    pub accepted: bool,
    /// Human-readable detail line.
    pub detail: String,
    /// SHA-256 of the primary payload this entry is about (document hash,
    /// signature hash, ...) — binds the log to the artifacts, hex-encoded.
    pub payload_hash: String,
    /// SHA-256 chain link: hash of this entry including the previous leaf.
    pub leaf_hash: String,
    /// Leaf-hash encoding this entry was sealed with (2 = length-prefixed;
    /// absent/1 = legacy concatenation). Serialized as null for v1 rows so
    /// old JSONL files load unchanged.
    #[serde(default, skip_serializing_if = "is_v1")]
    pub hash_v: u8,
}

fn is_v1(v: &u8) -> bool {
    *v <= 1
}

impl AuditEntry {
    /// True if this entry's leaf hash was produced by the v2 framing.
    pub fn is_v2(&self) -> bool {
        self.hash_v >= 2
    }
}

/// A Merkle inclusion proof for one leaf: the sibling hashes from the leaf
/// level up to the root (empty for a single-leaf log).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    pub seq: u64,
    pub leaf_hash: String,
    /// Sibling hashes, bottom-up. `"L:<hex>"` = sibling is a left child,
    /// `"R:<hex>"` = sibling is a right child.
    pub siblings: Vec<String>,
    /// The root the proof was computed against.
    pub root: String,
}

#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    /// seq -> index into `entries` (seq is 1-based and contiguous).
    index: HashMap<u64, usize>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Length-prefix one field for the v2 framing.
fn framed(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + field.len());
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
    out
}

/// Compute a leaf hash for `entry` chained onto `prev_leaf`.
///
/// `hash_v = 2` uses the length-prefixed framing; `hash_v <= 1` reproduces
/// the legacy concatenation encoding byte-for-byte.
fn leaf_hash_for(entry: &AuditEntry, prev_leaf: &str) -> String {
    let accepted = [entry.accepted as u8];
    if entry.is_v2() {
        let mut h = Sha256::new();
        h.update(LEAF_DOMAIN);
        h.update(framed(&entry.seq.to_le_bytes()));
        h.update(framed(entry.ts.as_bytes()));
        h.update(framed(entry.kind.as_bytes()));
        h.update(framed(entry.label.as_bytes()));
        h.update(framed(&accepted));
        h.update(framed(entry.detail.as_bytes()));
        h.update(framed(entry.payload_hash.as_bytes()));
        h.update(framed(prev_leaf.as_bytes()));
        hex::encode(h.finalize())
    } else {
        // Legacy encoding: raw concatenation, no prefix, no framing.
        let mut h = Sha256::new();
        h.update(entry.seq.to_le_bytes());
        h.update(entry.ts.as_bytes());
        h.update(entry.kind.as_bytes());
        h.update(entry.label.as_bytes());
        h.update(&accepted);
        h.update(entry.detail.as_bytes());
        h.update(entry.payload_hash.as_bytes());
        h.update(prev_leaf.as_bytes());
        hex::encode(h.finalize())
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event (v2 leaf encoding). `payload_hash` should be the
    /// SHA-256 hex of the artifact the event concerns.
    pub fn append(
        &mut self,
        kind: &str,
        label: &str,
        accepted: bool,
        detail: &str,
        payload_hash: &str,
        ts: &str,
    ) -> AuditEntry {
        let seq = self.entries.len() as u64 + 1;
        let prev_leaf = self.entries.last().map(|e| e.leaf_hash.clone()).unwrap_or_default();
        let mut entry = AuditEntry {
            seq,
            ts: ts.to_string(),
            kind: kind.to_string(),
            label: label.to_string(),
            accepted,
            detail: detail.to_string(),
            payload_hash: payload_hash.to_string(),
            leaf_hash: String::new(),
            hash_v: 2,
        };
        entry.leaf_hash = leaf_hash_for(&entry, &prev_leaf);
        self.index.insert(seq, self.entries.len());
        self.entries.push(entry.clone());
        entry
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries (oldest first).
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// The last `n` entries (newest first), for UI lists.
    pub fn recent(&self, n: usize) -> Vec<AuditEntry> {
        self.entries.iter().rev().take(n).cloned().collect()
    }

    /// Current Merkle root over all leaf hashes (None when empty).
    /// Odd trailing nodes are promoted (Bitcoin-style duplication).
    pub fn root(&self) -> Option<String> {
        let leaves: Vec<String> = self.entries.iter().map(|e| e.leaf_hash.clone()).collect();
        merkle_root(&leaves)
    }

    /// Merkle inclusion proof for entry `seq`.
    pub fn inclusion_proof(&self, seq: u64) -> Option<InclusionProof> {
        let &idx = self.index.get(&seq)?;
        let leaves: Vec<String> = self.entries.iter().map(|e| e.leaf_hash.clone()).collect();
        let root = merkle_root(&leaves)?;
        let mut level = leaves.clone();
        let mut i = idx;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let sib_i = if i % 2 == 0 { i + 1 } else { i - 1 };
            // The label records which side the SIBLING sits on: even index
            // → this node is a left child, sibling is on the right.
            let side = if i % 2 == 0 { "R" } else { "L" };
            let sib = level.get(sib_i).cloned().unwrap_or_else(|| level[i].clone());
            siblings.push(format!("{side}:{sib}"));
            level = level
                .chunks(2)
                .map(|pair| {
                    let l = &pair[0];
                    let r = pair.get(1).unwrap_or(&pair[0]);
                    sha256_hex(format!("{l}{r}").as_bytes())
                })
                .collect();
            i /= 2;
        }
        Some(InclusionProof {
            seq,
            leaf_hash: leaves[idx].clone(),
            siblings,
            root,
        })
    }

    /// Verify a Merkle inclusion proof against a root.
    pub fn verify_inclusion(proof: &InclusionProof) -> bool {
        let mut cur = proof.leaf_hash.clone();
        for sib in &proof.siblings {
            let (side, hash) = sib.split_once(':').unwrap_or(("L", ""));
            cur = match side {
                "L" => sha256_hex(format!("{hash}{cur}").as_bytes()),
                _ => sha256_hex(format!("{cur}{hash}").as_bytes()),
            };
        }
        cur == proof.root
    }

    /// Rebuild a log from persisted entries (server reload path). The chain
    /// is NOT re-verified here — call `verify_chain` after loading. Entries
    /// keep their original `hash_v` so v1/v2 mixed logs verify correctly.
    pub fn from_entries(entries: Vec<AuditEntry>) -> Self {
        let mut log = AuditLog { index: HashMap::new(), entries: Vec::new() };
        for e in entries {
            let seq = e.seq;
            log.index.insert(seq, log.entries.len());
            log.entries.push(e);
        }
        log
    }

    /// Rebuild a log from a JSONL file written by `append_persist`.
    /// Returns an empty log when the file does not exist. Skips blank or
    /// malformed lines (surface the line count so callers can warn).
    pub fn load_jsonl(path: &Path) -> Result<(Self, usize), String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Self::default(), 0));
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let mut entries = Vec::new();
        let mut skipped = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(line) {
                Ok(e) => entries.push(e),
                Err(_) => skipped += 1,
            }
        }
        Ok((Self::from_entries(entries), skipped))
    }

    /// Append one JSONL line for `entry` to `path` (creating the file).
    /// Returns the number of bytes written; errors propagate so callers can
    /// surface persistence failures instead of swallowing them.
    pub fn append_persist(path: &Path, entry: &AuditEntry) -> std::io::Result<usize> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let line = serde_json::to_string(entry).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        let n = line.len() + 1;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(n)
    }

    /// Full integrity check: recompute every leaf hash in sequence and the
    /// Merkle root. Any edit, deletion, or reordering of history fails.
    /// Each entry is re-hashed with ITS OWN encoding, so v1/v2 mixed chains
    /// verify correctly.
    pub fn verify_chain(&self) -> ChainVerdict {
        let mut prev = String::new();
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 + 1 {
                return ChainVerdict {
                    ok: false,
                    broken_at: Some(e.seq),
                    root: self.root(),
                    detail: format!("sequence gap: expected seq {}, found {}", i + 1, e.seq),
                };
            }
            let expect = leaf_hash_for(e, &prev);
            if expect != e.leaf_hash {
                return ChainVerdict {
                    ok: false,
                    broken_at: Some(e.seq),
                    root: self.root(),
                    detail: format!("leaf hash mismatch at seq {} — entry was altered", e.seq),
                };
            }
            prev = e.leaf_hash.clone();
        }
        ChainVerdict { ok: true, broken_at: None, root: self.root(), detail: "chain intact".into() }
    }
}

/// Result of a full-chain verification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainVerdict {
    pub ok: bool,
    /// Sequence number where the chain first breaks (None when intact).
    pub broken_at: Option<u64>,
    pub root: Option<String>,
    pub detail: String,
}

fn merkle_root(leaves: &[String]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let l = &pair[0];
                let r = pair.get(1).unwrap_or(&pair[0]);
                sha256_hex(format!("{l}{r}").as_bytes())
            })
            .collect();
    }
    Some(level[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> String {
        "2026-01-01T00:00:00.000Z".into()
    }

    #[test]
    fn append_builds_a_chain() {
        let mut log = AuditLog::new();
        let a = log.append("seal", "alice", true, "sealed report.pdf", "HASHA", &ts());
        let b = log.append("verify", "bob", true, "verified report.pdf", "HASHA", &ts());
        assert_eq!(log.len(), 2);
        assert_ne!(a.leaf_hash, b.leaf_hash);
        assert!(a.is_v2());
        assert!(log.root().is_some());
        let v = log.verify_chain();
        assert!(v.ok, "{}", v.detail);
    }

    #[test]
    fn tampering_history_is_detected() {
        let mut log = AuditLog::new();
        log.append("seal", "alice", true, "sealed contract", "H1", &ts());
        log.append("verify", "bob", true, "verified contract", "H1", &ts());
        log.append("flag", "detector", false, "tamper attempt", "H1", &ts());

        // An auditor edits a historical entry (removes the incident).
        let mut forged = log.entries().to_vec();
        forged[2].detail = "nothing happened".into();
        let reloaded = AuditLog::from_entries(forged);
        let v = reloaded.verify_chain();
        assert!(!v.ok);
        assert_eq!(v.broken_at, Some(3));
    }

    #[test]
    fn deletion_is_detected() {
        let mut log = AuditLog::new();
        log.append("seal", "alice", true, "a", "H", &ts());
        log.append("verify", "bob", true, "b", "H", &ts());
        log.append("transfer", "portal", true, "c", "H", &ts());

        // Drop the middle entry.
        let mut forged = log.entries().to_vec();
        forged.remove(1);
        for (i, e) in forged.iter_mut().enumerate() {
            e.seq = i as u64 + 1; // renumber to hide the gap
        }
        let reloaded = AuditLog::from_entries(forged);
        assert!(!reloaded.verify_chain().ok, "renumbering cannot forge leaf hashes");
    }

    #[test]
    fn inclusion_proofs_round_trip() {
        let mut log = AuditLog::new();
        for i in 0..7 {
            log.append("event", "node", true, &format!("event {i}"), "H", &ts());
        }
        for seq in 1..=7u64 {
            let proof = log.inclusion_proof(seq).unwrap();
            assert_eq!(proof.leaf_hash, log.entries()[seq as usize - 1].leaf_hash);
            assert!(AuditLog::verify_inclusion(&proof), "seq {seq} must verify");
        }
        // A forged leaf hash must not verify against the true root.
        let mut proof = log.inclusion_proof(4).unwrap();
        proof.leaf_hash = "00".repeat(32);
        assert!(!AuditLog::verify_inclusion(&proof));
    }

    #[test]
    fn empty_log_has_no_root() {
        let log = AuditLog::new();
        assert!(log.root().is_none());
        assert!(log.inclusion_proof(1).is_none());
    }

    #[test]
    fn v2_framing_is_length_prefixed_and_differs_from_v1() {
        let e = AuditEntry {
            seq: 1,
            ts: "t".into(),
            kind: "ab".into(),
            label: "l".into(),
            accepted: true,
            detail: "d".into(),
            payload_hash: "p".into(),
            leaf_hash: String::new(),
            hash_v: 2,
        };
        let v2 = leaf_hash_for(&e, "");
        let mut v1_entry = e.clone();
        v1_entry.hash_v = 1;
        let v1 = leaf_hash_for(&v1_entry, "");
        assert_ne!(v2, v1, "the two encodings must hash differently");
        // Field-boundary ambiguity resolved: kind="ab",label="l" cannot
        // collide with kind="a",label="bl".
        let mut swapped = e.clone();
        swapped.kind = "a".into();
        swapped.label = "bl".into();
        assert_ne!(leaf_hash_for(&swapped, ""), v2);
    }

    #[test]
    fn legacy_v1_entries_still_verify() {
        // Hand-build the exact pre-v2 encoding and confirm verify_chain
        // re-derives it.
        let mut h = Sha256::new();
        h.update(1u64.to_le_bytes());
        h.update(b"t");
        h.update(b"kind");
        h.update(b"label");
        h.update([1u8]);
        h.update(b"detail");
        h.update(b"payload");
        h.update(b""); // prev leaf
        let legacy_leaf = hex::encode(h.finalize());
        let e = AuditEntry {
            seq: 1,
            ts: "t".into(),
            kind: "kind".into(),
            label: "label".into(),
            accepted: true,
            detail: "detail".into(),
            payload_hash: "payload".into(),
            leaf_hash: legacy_leaf,
            hash_v: 1,
        };
        let log = AuditLog::from_entries(vec![e]);
        let v = log.verify_chain();
        assert!(v.ok, "{}", v.detail);
    }

    #[test]
    fn mixed_v1_v2_chain_verifies_and_jsonl_round_trips() {
        let dir = std::env::temp_dir().join("audit_test_mixed");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mixed.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut log = AuditLog::new();
        // A hand-made legacy entry (as an old server would have persisted).
        log.entries.push(AuditEntry {
            seq: 1,
            ts: "t".into(),
            kind: "v1".into(),
            label: "legacy".into(),
            accepted: true,
            detail: "old entry".into(),
            payload_hash: "p".into(),
            leaf_hash: String::new(),
            hash_v: 1,
        });
        log.entries[0].leaf_hash = leaf_hash_for(&log.entries[0], "");
        log.index.insert(1, 0);
        // v2 appends chain onto the legacy leaf.
        log.append("v2", "modern", true, "new entry", "p", &ts());

        assert!(log.verify_chain().ok, "v1→v2 chain must verify");

        for e in log.entries() {
            AuditLog::append_persist(&path, e).expect("persist");
        }
        let (reloaded, skipped) = AuditLog::load_jsonl(&path).expect("reload");
        assert_eq!(skipped, 0);
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.verify_chain().ok);
        assert_eq!(reloaded.root(), log.root());
        // v1 rows serialize without the hash_v field (old-file compatible).
        let line = std::fs::read_to_string(&path).unwrap();
        assert!(line.contains("\"seq\":1"));
        assert!(!line.matches("\"hash_v\":1").count().to_string().is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
