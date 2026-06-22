//! `keepsake-firewall` — the Context-Firewall.
//!
//! - [`PrivacyDial`] — per-request posture (Local-Only / Redacted-Cloud / Full-Cloud / No-Memory).
//! - [`Redactor`] — reversible PII tokenization before any cloud egress.
//! - [`ReceiptLog`] — a tamper-evident, HMAC-chained local audit log (the "Memory Receipt").

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Per-request privacy posture (the "Privacy Dial").
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PrivacyDial {
    /// Never leave the device; local inference only. (Default.)
    #[default]
    LocalOnly,
    /// Cloud allowed, but PII is redacted before sending.
    RedactedCloud,
    /// Cloud allowed with the selected context disclosed in full (explicit choice).
    FullCloud,
    /// No memory injection and no write-back; pure passthrough.
    NoMemory,
}

impl PrivacyDial {
    /// Parse a header value like `local-only`, `redacted-cloud`, `full-cloud`, `no-memory`.
    pub fn parse(s: &str) -> Option<PrivacyDial> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local-only" | "local" => Some(PrivacyDial::LocalOnly),
            "redacted-cloud" | "redacted" => Some(PrivacyDial::RedactedCloud),
            "full-cloud" | "full" => Some(PrivacyDial::FullCloud),
            "no-memory" | "none" => Some(PrivacyDial::NoMemory),
            _ => None,
        }
    }

    /// May context be sent to a cloud provider under this dial?
    pub fn allows_cloud_egress(self) -> bool {
        matches!(self, PrivacyDial::RedactedCloud | PrivacyDial::FullCloud)
    }

    /// Should memory be injected / written back under this dial?
    pub fn uses_memory(self) -> bool {
        !matches!(self, PrivacyDial::NoMemory)
    }

    /// Must PII be redacted before egress under this dial?
    pub fn requires_redaction(self) -> bool {
        matches!(self, PrivacyDial::RedactedCloud)
    }
}

/// The result of redacting text: the tokenized text plus the (token, original) map.
pub struct Redacted {
    pub text: String,
    pub map: Vec<(String, String)>,
}

/// Reversible PII tokenizer (best-effort: emails and phone-like digit runs).
pub struct Redactor {
    patterns: Vec<regex::Regex>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    pub fn new() -> Self {
        Redactor {
            patterns: vec![
                regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
                regex::Regex::new(r"\+?\d[\d \-]{7,}\d").unwrap(),
            ],
        }
    }

    /// Replace detected PII with stable `<PII_n>` tokens; returns text + mapping.
    pub fn redact(&self, text: &str) -> Redacted {
        let mut out = text.to_string();
        let mut map: Vec<(String, String)> = Vec::new();
        for pat in &self.patterns {
            while let Some(m) = pat.find(&out) {
                let (range, original) = (m.range(), m.as_str().to_string());
                let token = format!("<PII_{}>", map.len());
                out.replace_range(range, &token);
                map.push((token, original));
            }
        }
        Redacted { text: out, map }
    }

    /// Restore original values from a redaction map into `text`.
    pub fn rehydrate(text: &str, map: &[(String, String)]) -> String {
        let mut out = text.to_string();
        for (token, original) in map {
            out = out.replace(token, original);
        }
        out
    }
}

/// One tamper-evident receipt in the local audit chain.
#[derive(Clone, Debug)]
pub struct Receipt {
    pub seq: u64,
    pub kind: String,
    pub detail: String,
    pub prev: [u8; 32],
    pub mac: [u8; 32],
}

/// Append-only, HMAC-chained local audit log (the "Memory Receipt" ledger).
pub struct ReceiptLog {
    key: [u8; 32],
    entries: Vec<Receipt>,
}

impl ReceiptLog {
    /// Start a fresh log, deriving the MAC key from the `receipt_root`.
    pub fn new(receipt_root: &[u8; 32]) -> Self {
        ReceiptLog {
            key: derive_receipt_key(receipt_root),
            entries: Vec::new(),
        }
    }

    /// Load a persisted log to verify it.
    pub fn from_entries(receipt_root: &[u8; 32], entries: Vec<Receipt>) -> Self {
        ReceiptLog {
            key: derive_receipt_key(receipt_root),
            entries,
        }
    }

    /// Append a receipt for an event (kind + detail), chaining it to the previous.
    pub fn append(&mut self, kind: &str, detail: &str) {
        let seq = self.entries.len() as u64;
        let prev = self.entries.last().map(|r| r.mac).unwrap_or([0u8; 32]);
        let mac = self.mac(seq, kind, detail, &prev);
        self.entries.push(Receipt {
            seq,
            kind: kind.to_string(),
            detail: detail.to_string(),
            prev,
            mac,
        });
    }

    pub fn entries(&self) -> &[Receipt] {
        &self.entries
    }

    /// Verify the chain: sequence numbers, prev-hash links, and HMACs are all intact.
    pub fn verify(&self) -> bool {
        let mut prev = [0u8; 32];
        for (i, r) in self.entries.iter().enumerate() {
            if r.seq != i as u64 || r.prev != prev {
                return false;
            }
            if self.mac(r.seq, &r.kind, &r.detail, &r.prev) != r.mac {
                return false;
            }
            prev = r.mac;
        }
        true
    }

    fn mac(&self, seq: u64, kind: &str, detail: &str, prev: &[u8; 32]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        m.update(&seq.to_le_bytes());
        m.update(kind.as_bytes());
        m.update(&[0]);
        m.update(detail.as_bytes());
        m.update(&[0]);
        m.update(prev);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&m.finalize().into_bytes());
        mac
    }
}

fn derive_receipt_key(receipt_root: &[u8; 32]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(receipt_root).expect("HMAC accepts any key length");
    m.update(b"keepsake/v1/receipt-mac");
    let mut key = [0u8; 32];
    key.copy_from_slice(&m.finalize().into_bytes());
    key
}

/// Object-capability tokens (macaroon construction): offline-verifiable, **attenuable
/// (narrow-only)**, revocable. A third-party agent receives a token scoping exactly which
/// memory it may touch; it can add restrictions but never widen them.
pub mod capability {
    use hmac::{Hmac, Mac};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    /// A single scope constraint, e.g. `("capability","memory:read")`, `("max_records","20")`,
    /// `("scope_topic","health")`, `("cloud_egress","forbidden")`, `("expires","<unix>")`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Caveat {
        pub key: String,
        pub value: String,
    }

    impl Caveat {
        pub fn new(key: &str, value: &str) -> Caveat {
            Caveat {
                key: key.to_string(),
                value: value.to_string(),
            }
        }
    }

    /// A capability token: a chain of caveats bound by a chained HMAC signature.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CapabilityToken {
        pub caveats: Vec<Caveat>,
        pub signature: [u8; 32],
    }

    fn mac_step(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&m.finalize().into_bytes());
        out
    }

    fn caveat_bytes(c: &Caveat) -> Vec<u8> {
        let mut v = Vec::with_capacity(c.key.len() + c.value.len() + 1);
        v.extend_from_slice(c.key.as_bytes());
        v.push(0);
        v.extend_from_slice(c.value.as_bytes());
        v
    }

    fn chain(root_key: &[u8; 32], caveats: &[Caveat]) -> [u8; 32] {
        let mut sig = mac_step(root_key, b"keepsake/v1/capability");
        for c in caveats {
            sig = mac_step(&sig, &caveat_bytes(c));
        }
        sig
    }

    fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b) {
            diff |= x ^ y;
        }
        diff == 0
    }

    impl CapabilityToken {
        /// Mint a token under the vault's capability `root_key` (derived from `signing_root`).
        pub fn issue(root_key: &[u8; 32], caveats: Vec<Caveat>) -> CapabilityToken {
            let signature = chain(root_key, &caveats);
            CapabilityToken { caveats, signature }
        }

        /// Append a caveat (narrowing). Any holder can do this; nobody can widen.
        pub fn attenuate(&self, caveat: Caveat) -> CapabilityToken {
            let signature = mac_step(&self.signature, &caveat_bytes(&caveat));
            let mut caveats = self.caveats.clone();
            caveats.push(caveat);
            CapabilityToken { caveats, signature }
        }

        /// Verify the token was issued by `root_key` and not tampered with.
        pub fn verify(&self, root_key: &[u8; 32]) -> bool {
            ct_eq(&chain(root_key, &self.caveats), &self.signature)
        }

        /// The first value for caveat `key`, if present.
        pub fn caveat(&self, key: &str) -> Option<&str> {
            self.caveats
                .iter()
                .find(|c| c.key == key)
                .map(|c| c.value.as_str())
        }

        /// Whether the token permits cloud egress (default forbidden for third parties).
        pub fn permits_cloud_egress(&self) -> bool {
            self.caveat("cloud_egress") == Some("allowed")
        }

        /// Encode the token for transport (hex of its JSON).
        pub fn encode_hex(&self) -> String {
            hex::encode(serde_json::to_vec(self).expect("CapabilityToken serializes"))
        }

        /// Decode a token produced by [`CapabilityToken::encode_hex`].
        pub fn decode_hex(s: &str) -> Option<CapabilityToken> {
            serde_json::from_slice(&hex::decode(s).ok()?).ok()
        }

        /// Verify the token under `root_key` and collapse ALL of its caveats into the
        /// effective [`Authorization`] with *meet semantics* — every caveat narrows and the
        /// most restrictive value of each kind wins. Enforcement must use this, never a single
        /// first-match `caveat()` (which a later attenuation would silently bypass).
        pub fn authorize(&self, root_key: &[u8; 32]) -> Option<Authorization> {
            if !self.verify(root_key) {
                return None;
            }
            let caps: Vec<&str> = self
                .caveats
                .iter()
                .filter(|c| c.key == "capability")
                .map(|c| c.value.as_str())
                .collect();
            if caps.is_empty() {
                return None; // a capability token must name at least one capability
            }
            // Operation grants INTERSECT (narrow-only); an unknown capability grants nothing.
            // Crucially, write does NOT imply read.
            let (mut read, mut write, mut admin) = (true, true, true);
            for v in caps {
                let (r, w, a) = match v {
                    "memory:read" => (true, false, false),
                    "memory:write" => (false, true, false),
                    "memory:admin" => (true, true, true),
                    _ => (false, false, false),
                };
                read &= r;
                write &= w;
                admin &= a;
            }
            // max_records / expires: the minimum (most restrictive) across every such caveat.
            let mut max_records: Option<usize> = None;
            let mut expires: Option<u64> = None;
            for c in &self.caveats {
                match c.key.as_str() {
                    "max_records" => {
                        let n = c.value.parse::<usize>().ok()?;
                        max_records = Some(max_records.map_or(n, |m| m.min(n)));
                    }
                    "expires" => {
                        let n = c.value.parse::<u64>().ok()?;
                        expires = Some(expires.map_or(n, |m| m.min(n)));
                    }
                    _ => {}
                }
            }
            let topics: std::collections::BTreeSet<String> = self
                .caveats
                .iter()
                .filter(|c| c.key == "scope_topic")
                .map(|c| c.value.clone())
                .collect();
            // Cloud egress: allowed only if explicitly granted and never forbidden.
            let granted = self
                .caveats
                .iter()
                .any(|c| c.key == "cloud_egress" && c.value == "allowed");
            let forbidden = self
                .caveats
                .iter()
                .any(|c| c.key == "cloud_egress" && c.value == "forbidden");
            Some(Authorization {
                read,
                write,
                admin,
                max_records,
                topics,
                cloud_egress: granted && !forbidden,
                expires,
            })
        }
    }

    /// The effective authorization a capability token confers, after collapsing all caveats
    /// with meet semantics. Produced by [`CapabilityToken::authorize`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Authorization {
        read: bool,
        write: bool,
        admin: bool,
        max_records: Option<usize>,
        topics: std::collections::BTreeSet<String>,
        cloud_egress: bool,
        expires: Option<u64>,
    }

    impl Authorization {
        /// May this token recall / read memory?
        pub fn allows_read(&self) -> bool {
            self.read
        }
        /// May this token write / remember memory? (Write does **not** imply read.)
        pub fn allows_write(&self) -> bool {
            self.write
        }
        /// May this token perform owner-level operations (forget, share)?
        pub fn allows_admin(&self) -> bool {
            self.admin
        }
        /// The retrieval cap, if any (the minimum across all `max_records` caveats).
        pub fn max_records(&self) -> Option<usize> {
            self.max_records
        }
        /// May context be disclosed to a cloud provider under this token?
        pub fn permits_cloud_egress(&self) -> bool {
            self.cloud_egress
        }
        /// Whether the token has expired at `now`.
        pub fn is_expired(&self, now: u64) -> bool {
            self.expires.is_some_and(|e| now >= e)
        }
        /// Does `text` satisfy every `scope_topic` caveat? With no topic caveat, all text
        /// passes. Topic scoping is keyword-based over the memory's plaintext, so a token
        /// scoped to a topic can only retrieve memories that actually mention it.
        pub fn permits_topic(&self, text: &str) -> bool {
            if self.topics.is_empty() {
                return true;
            }
            let hay = text.to_lowercase();
            self.topics.iter().all(|t| hay.contains(&t.to_lowercase()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn token_verifies_attenuates_and_cannot_be_widened() {
            let root = [3u8; 32];
            let token = CapabilityToken::issue(
                &root,
                vec![
                    Caveat::new("capability", "memory:read"),
                    Caveat::new("max_records", "20"),
                ],
            );
            assert!(token.verify(&root));
            assert!(!token.permits_cloud_egress(), "cloud egress off by default");

            // Attenuation (narrowing) is allowed and still verifies.
            let narrowed = token.attenuate(Caveat::new("scope_topic", "health"));
            assert!(narrowed.verify(&root));
            assert_eq!(narrowed.caveats.len(), 3);

            // Widening a caveat breaks the chained signature.
            let mut widened = token.clone();
            widened.caveats[1].value = "100".to_string();
            assert!(!widened.verify(&root), "widening must break verification");

            // Removing a caveat breaks it too.
            let mut shortened = token.clone();
            shortened.caveats.pop();
            assert!(!shortened.verify(&root));

            // Wrong root key fails.
            assert!(!token.verify(&[9u8; 32]));
        }

        #[test]
        fn authorization_uses_meet_semantics_across_caveats() {
            let root = [3u8; 32];

            // admin attenuated to read => read only (write/admin do NOT survive).
            let t = CapabilityToken::issue(&root, vec![Caveat::new("capability", "memory:admin")])
                .attenuate(Caveat::new("capability", "memory:read"));
            let a = t.authorize(&root).unwrap();
            assert!(a.allows_read() && !a.allows_write() && !a.allows_admin());

            // write does NOT grant read (KS-010).
            let w = CapabilityToken::issue(&root, vec![Caveat::new("capability", "memory:write")])
                .authorize(&root)
                .unwrap();
            assert!(w.allows_write() && !w.allows_read());

            // The MINIMUM max_records wins, not the first-listed (KS-008).
            let t = CapabilityToken::issue(
                &root,
                vec![
                    Caveat::new("capability", "memory:read"),
                    Caveat::new("max_records", "50"),
                ],
            )
            .attenuate(Caveat::new("max_records", "5"));
            assert_eq!(t.authorize(&root).unwrap().max_records(), Some(5));

            // cloud_egress: a later 'forbidden' overrides an earlier 'allowed'.
            let t = CapabilityToken::issue(
                &root,
                vec![
                    Caveat::new("capability", "memory:read"),
                    Caveat::new("cloud_egress", "allowed"),
                ],
            )
            .attenuate(Caveat::new("cloud_egress", "forbidden"));
            assert!(!t.authorize(&root).unwrap().permits_cloud_egress());

            // topic scoping is enforced over text (KS-007).
            let scoped = CapabilityToken::issue(
                &root,
                vec![
                    Caveat::new("capability", "memory:read"),
                    Caveat::new("scope_topic", "health"),
                ],
            )
            .authorize(&root)
            .unwrap();
            assert!(scoped.permits_topic("my health record"));
            assert!(!scoped.permits_topic("my finances"));

            // a token naming no capability, and a wrong root key, both fail.
            assert!(CapabilityToken::issue(&root, vec![Caveat::new("max_records", "1")])
                .authorize(&root)
                .is_none());
            assert!(CapabilityToken::issue(&root, vec![Caveat::new("capability", "memory:read")])
                .authorize(&[9u8; 32])
                .is_none());
        }

        #[test]
        fn token_round_trips_through_hex_wire() {
            let root = [4u8; 32];
            let token = CapabilityToken::issue(
                &root,
                vec![
                    Caveat::new("capability", "memory:read"),
                    Caveat::new("max_records", "5"),
                ],
            );
            let decoded = CapabilityToken::decode_hex(&token.encode_hex()).unwrap();
            assert!(decoded.verify(&root));
            assert_eq!(decoded.caveat("max_records"), Some("5"));
            assert!(CapabilityToken::decode_hex("zz").is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_dial_parses_and_exposes_flags() {
        assert_eq!(
            PrivacyDial::parse("local-only"),
            Some(PrivacyDial::LocalOnly)
        );
        assert_eq!(
            PrivacyDial::parse("REDACTED"),
            Some(PrivacyDial::RedactedCloud)
        );
        assert_eq!(PrivacyDial::parse("bogus"), None);
        assert_eq!(PrivacyDial::default(), PrivacyDial::LocalOnly);

        assert!(!PrivacyDial::LocalOnly.allows_cloud_egress());
        assert!(PrivacyDial::FullCloud.allows_cloud_egress());
        assert!(PrivacyDial::RedactedCloud.requires_redaction());
        assert!(!PrivacyDial::NoMemory.uses_memory());
    }

    #[test]
    fn redactor_tokenizes_and_rehydrates_email() {
        let r = Redactor::new();
        let red = r.redact("contact me at alice@example.com please");
        assert!(
            !red.text.contains("alice@example.com"),
            "email must be removed"
        );
        assert!(red.text.contains("<PII_"), "a token must be inserted");
        let restored = Redactor::rehydrate(&red.text, &red.map);
        assert_eq!(restored, "contact me at alice@example.com please");
    }

    #[test]
    fn receipt_log_appends_and_verifies() {
        let root = [9u8; 32];
        let mut log = ReceiptLog::new(&root);
        log.append("recall", "cells=3");
        log.append("cloud_egress", "provider=local");
        assert_eq!(log.entries().len(), 2);
        assert!(log.verify(), "an untouched chain must verify");
    }

    #[test]
    fn receipt_log_detects_tampering() {
        let root = [9u8; 32];
        let mut log = ReceiptLog::new(&root);
        log.append("a", "1");
        log.append("b", "2");

        let mut tampered = log.entries().to_vec();
        tampered[0].detail = "TAMPERED".to_string();
        let loaded = ReceiptLog::from_entries(&root, tampered);
        assert!(!loaded.verify(), "a mutated entry must break verification");
    }
}
