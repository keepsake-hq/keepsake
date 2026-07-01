//! `keepsake-vault` — the integration layer: durable two-plane store + local
//! embeddings = a vault that actually *remembers*.
//!
//! `remember` stores the encrypted cell and indexes its embedding; `recall` embeds
//! the query, runs semantic search, and decrypts the hits; `forget` erases content
//! and drops the embedding. The in-RAM index is rebuilt from persisted content on
//! open (embeddings are derived from content, the single erasable source of truth).

use keepsake_core::ledger::ContradictionLedger;
use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_graph::GraphIndex;
pub use keepsake_graph::{parse_triples, Triple};
use keepsake_retrieval::{Embedder, VectorIndex};
use keepsake_store_sqlite::{SqliteVault, StoreError};
use std::collections::HashSet;

/// SAIHM sharing-contract kinds: TEMPORARY (≤24h), PERMANENT, SYNDICATE (multi-party).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractKind {
    Temporary { expires_at: u64 },
    Permanent,
    Syndicate,
}

/// The maximum lifetime of a TEMPORARY contract (SAIHM: ≤ 24h).
pub const TEMPORARY_MAX_SECS: u64 = 24 * 60 * 60;

/// A shared cell under a contract: the content sealed to each grantee's public key.
pub struct ShareContract {
    pub kind: ContractKind,
    pub issued_at: u64,
    /// `(grantee_public_key, sealed_blob)` for each grantee.
    pub portions: Vec<([u8; 32], Vec<u8>)>,
}

impl ShareContract {
    /// Whether the contract is valid at `now` (TEMPORARY honours its expiry).
    pub fn is_valid(&self, now: u64) -> bool {
        match self.kind {
            ContractKind::Temporary { expires_at } => now <= expires_at,
            ContractKind::Permanent | ContractKind::Syndicate => true,
        }
    }
}

/// A grantee opens their portion of a contract, if it is valid and addressed to them.
pub fn open_contract_portion(
    contract: &ShareContract,
    grantee: &keepsake_crypto::ShareKeypair,
    now: u64,
) -> Option<Vec<u8>> {
    if !contract.is_valid(now) {
        return None;
    }
    let pubkey = grantee.public();
    contract
        .portions
        .iter()
        .find(|(g, _)| *g == pubkey)
        .and_then(|(_, sealed)| keepsake_crypto::open_sealed(grantee, sealed).ok())
}

/// Default cosine-similarity threshold above which a new memory is treated as a duplicate of an
/// existing one and not stored again — the write-time anti-bloat guard.
pub const DEDUP_THRESHOLD: f32 = 0.92;

/// Tunables for recency-weighted recall: how strongly newer memories are favoured.
#[derive(Clone, Copy, Debug)]
pub struct RecencyParams {
    /// Half-life of the recency multiplier, in seconds.
    pub half_life_secs: f64,
    /// Floor in `[0, 1]`: an infinitely old memory still keeps at least this fraction of
    /// its similarity score, so an old-but-relevant memory never vanishes — recency only
    /// breaks ties and nudges, it does not erase the past.
    pub floor: f32,
}

impl Default for RecencyParams {
    fn default() -> Self {
        // 90-day half-life, generous 0.5 floor.
        RecencyParams {
            half_life_secs: 90.0 * 24.0 * 60.0 * 60.0,
            floor: 0.5,
        }
    }
}

impl RecencyParams {
    /// The recency multiplier for a memory of the given age (seconds): `1.0` when fresh,
    /// decaying by half every `half_life_secs`, but never below `floor`.
    fn weight(&self, age_secs: f64) -> f32 {
        if age_secs <= 0.0 {
            return 1.0;
        }
        let decay = 0.5_f64.powf(age_secs / self.half_life_secs) as f32;
        self.floor + (1.0 - self.floor) * decay
    }
}

/// A named recall strategy: it picks how strongly recency competes with similarity, and whether the
/// knowledge graph enriches the result — so a caller can choose a retrieval mode per question
/// without hand-tuning weights. Every strategy scores over Keepsake's existing **local** signals
/// (semantic similarity, recency, and — for `GraphFirst` — graph connectivity); none add a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RecallProfile {
    /// Relevance leads, recency breaks ties and nudges (the default): a newer memory edges out an
    /// equally-relevant older one.
    #[default]
    Balanced,
    /// Pure relevance, age-blind — "find whatever is most relevant, no matter how old".
    Semantic,
    /// Recency leads — "what's the latest on X". Short half-life + low floor, so stale memories fade.
    Recent,
    /// Balanced ranking, then also pulls in memories the knowledge graph connects to the query.
    GraphFirst,
    /// User-facing hybrid mode: semantic + recency + graph enrichment, all local.
    Hybrid,
}

impl RecallProfile {
    /// Parse a profile name (case-insensitive). Unknown / empty falls back to [`RecallProfile::Balanced`].
    pub fn parse(s: &str) -> RecallProfile {
        match s.trim().to_ascii_lowercase().as_str() {
            "semantic" => RecallProfile::Semantic,
            "recent" => RecallProfile::Recent,
            "graph" | "graph_first" | "graph-first" | "graphfirst" => RecallProfile::GraphFirst,
            "hybrid" => RecallProfile::Hybrid,
            _ => RecallProfile::Balanced,
        }
    }

    /// The recency curve this profile applies on top of the cosine score.
    fn recency(self) -> RecencyParams {
        match self {
            // Age-blind: a flat floor of 1.0 makes the recency multiplier always 1.0.
            RecallProfile::Semantic => RecencyParams {
                half_life_secs: f64::INFINITY,
                floor: 1.0,
            },
            // Recency dominates: 14-day half-life + low floor so stale memories drop away fast.
            RecallProfile::Recent => RecencyParams {
                half_life_secs: 14.0 * 24.0 * 60.0 * 60.0,
                floor: 0.1,
            },
            RecallProfile::Balanced | RecallProfile::GraphFirst | RecallProfile::Hybrid => {
                RecencyParams::default()
            }
        }
    }
}

/// One node of the visual memory map: a memory and the bits the UI needs to draw, label, and open it.
#[derive(Clone, Debug)]
pub struct GraphNode {
    pub id: CellId,
    /// First non-empty line, truncated — the dot's label.
    pub title: String,
    /// The full memory text (bounded) — shown when the dot is opened.
    pub text: String,
    pub created_at: i64,
    pub source: Option<String>,
}

/// A link between two memories (indices into [`MemoryGraph::nodes`]) with their cosine similarity.
#[derive(Clone, Copy, Debug)]
pub struct GraphEdge {
    pub a: usize,
    pub b: usize,
    pub weight: f32,
}

/// A similarity map of the live memories (nodes + weighted edges) for the visual graph view.
#[derive(Clone, Debug)]
pub struct MemoryGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// A semantic memory vault over a [`SqliteVault`] and a local [`Embedder`].
pub struct MemoryVault<E: Embedder> {
    store: SqliteVault,
    index: VectorIndex,
    embedder: E,
    /// Bi-temporal history of keyed facts (in-session); see [`MemoryVault::remember_fact`].
    ledger: ContradictionLedger,
    /// Cell ids hidden from quality recall because a newer version superseded them.
    superseded: HashSet<[u8; 32]>,
    /// Knowledge-graph index (entities & relations distilled from memories).
    graph: GraphIndex,
}

/// Render graph edges as a compact map: one `[id] subject --relation--> object` line per edge.
/// No full memory text — that is fetched on demand by id. Empty input → empty string.
fn format_map(edges: &[(CellId, Triple)]) -> String {
    if edges.is_empty() {
        return String::new();
    }
    let mut s = String::from("# Memory map — fetch a node's full text by its id\n");
    for (cell, t) in edges {
        s.push_str(&format!(
            "[{}] {} --{}--> {}\n",
            hex::encode(cell.as_bytes()),
            t.subject,
            t.relation,
            t.object
        ));
    }
    // Partial-view marker: tell the agent this is structure (lossy), and exactly how to expand a node,
    // so aggressive compression is self-documenting and never a silent loss of detail.
    s.push_str(
        "# Partial view — this is the map, not the memories. Fetch a node's full text by its id: \
         saihm_recall_cell(<id>)  (CLI: keepsake get <id>).\n",
    );
    s
}

impl<E: Embedder> MemoryVault<E> {
    /// Wrap a store and embedder. The in-RAM index starts empty; call
    /// [`MemoryVault::rebuild_index`] to populate it from persisted content.
    pub fn new(store: SqliteVault, embedder: E) -> Self {
        MemoryVault {
            store,
            index: VectorIndex::new(),
            embedder,
            ledger: ContradictionLedger::new(),
            superseded: HashSet::new(),
            graph: GraphIndex::new(),
        }
    }

    /// Borrow the underlying durable store — used by the sync layer to snapshot and merge records.
    pub fn store(&self) -> &SqliteVault {
        &self.store
    }

    /// The most recent `limit` memories as plain text (newest first) — the input the in-loop
    /// model distills into the profile.
    pub fn recent_texts(&self, kek: &Kek, limit: usize) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        for (id, _ts) in self.store.recent(limit)? {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                out.push(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        Ok(out)
    }

    /// The distilled profile (a compact, model-written overview), or `None` if not built yet.
    pub fn profile(&self) -> Result<Option<String>, StoreError> {
        self.store.profile()
    }

    /// Store the distilled profile.
    pub fn set_profile(&self, text: &str) -> Result<(), StoreError> {
        self.store.set_profile(text)
    }

    /// Clear the distilled profile. Memories remain intact; the summary can be rebuilt locally.
    pub fn clear_profile(&self) -> Result<(), StoreError> {
        self.store.clear_profile()
    }

    /// Store `text` as an encrypted cell and index its embedding. Returns the id.
    pub fn remember(&mut self, kek: &Kek, text: &str) -> Result<CellId, StoreError> {
        let id = self.store.remember(kek, text.as_bytes())?;
        let vector = self
            .embedder
            .embed(text)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        self.index.add(id.clone(), &vector);
        Ok(id)
    }

    /// Like [`MemoryVault::remember`] but skip writing if an existing memory is at least
    /// `threshold` cosine-similar — the write-time anti-bloat guard. Returns `(id, stored)`:
    /// `stored == false` means a near-duplicate already existed (its id is returned) and nothing
    /// new was written.
    pub fn remember_deduped(
        &mut self,
        kek: &Kek,
        text: &str,
        threshold: f32,
    ) -> Result<(CellId, bool), StoreError> {
        self.remember_deduped_with_source(kek, text, threshold, now_unix(), None)
    }

    /// Like [`MemoryVault::remember_deduped`] but stamps an explicit creation time and an
    /// optional provenance `source` on a newly-stored memory (skipped writes keep the
    /// existing cell untouched).
    pub fn remember_deduped_with_source(
        &mut self,
        kek: &Kek,
        text: &str,
        threshold: f32,
        created_at: i64,
        source: Option<&str>,
    ) -> Result<(CellId, bool), StoreError> {
        // Exact-duplicate fast path: a seed-keyed tag of the plaintext (HMAC under a kek-derived key,
        // so it's local-only and not a global fingerprint — see `Kek::content_tag`). If we've stored
        // this exact text before, skip the embedding entirely.
        let tag = kek.content_tag(text.as_bytes());
        if let Some(existing) = self.store.dedup_lookup(&tag)? {
            return Ok((existing, false));
        }
        let vector = self
            .embedder
            .embed(text)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        if let Some((existing, score)) = self.index.search(&vector, 1).into_iter().next() {
            if score >= threshold {
                // Near-duplicate by meaning: record the exact tag too, so a re-send short-circuits.
                self.store.dedup_record(&tag, &existing)?;
                return Ok((existing, false));
            }
        }
        let id = self
            .store
            .remember_with_source(kek, text.as_bytes(), created_at, source)?;
        self.index.add(id.clone(), &vector);
        self.store.dedup_record(&tag, &id)?;
        Ok((id, true))
    }

    /// Semantic recall: embed `query`, search the index, decrypt up to `k` hits.
    /// Returns `(cell_id, plaintext)` pairs, most relevant first.
    pub fn recall(
        &self,
        kek: &Kek,
        query: &str,
        k: usize,
    ) -> Result<Vec<(CellId, String)>, StoreError> {
        let query_vec = self
            .embedder
            .embed(query)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        let mut out = Vec::new();
        for (id, _score) in self.index.search(&query_vec, k) {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    out.push((id, text));
                }
            }
        }
        Ok(out)
    }

    /// Compact "symbol-graph" recall: the query-relevant region of the knowledge graph as a terse
    /// map (entities + relations, each tagged with the backing cell id) **instead of** the full
    /// memory texts. Picks the cells most relevant to `query` (top-`k`), then renders their triples
    /// — the model reads the structure cheaply and fetches a node's full text by id on demand via
    /// [`MemoryVault::get_cell`]. Empty when no relevant edges exist.
    pub fn recall_map(&self, kek: &Kek, query: &str, k: usize) -> Result<String, StoreError> {
        let cells: Vec<CellId> = self
            .recall(kek, query, k)?
            .into_iter()
            .map(|(c, _)| c)
            .collect();
        Ok(format_map(&self.graph.subgraph(&cells)))
    }

    /// The full plaintext of a single memory by cell id — the on-demand fetch behind a map entry.
    /// `None` if the cell is absent or was forgotten (its key is gone), so erasure stays honest.
    pub fn get_cell(&self, kek: &Kek, id: &CellId) -> Result<Option<String>, StoreError> {
        Ok(self
            .store
            .recall(kek, id)?
            .and_then(|bytes| String::from_utf8(bytes).ok()))
    }

    /// Like [`MemoryVault::remember`] but with an explicit creation time (Unix seconds);
    /// indexes the embedding too. Used by the recency timeline and deterministic tests.
    pub fn remember_at(
        &mut self,
        kek: &Kek,
        text: &str,
        created_at: i64,
    ) -> Result<CellId, StoreError> {
        let id = self.store.remember_at(kek, text.as_bytes(), created_at)?;
        let vector = self
            .embedder
            .embed(text)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        self.index.add(id.clone(), &vector);
        Ok(id)
    }

    /// Semantic recall, re-ranked so a more recent memory edges out an equally-relevant
    /// older one. `now` is the reference time (Unix seconds). Every indexed candidate is
    /// scored as `cosine * recency_weight(age)` (so recency can promote a slightly-less
    /// similar but newer hit), then the top `k` are decrypted, most relevant first.
    pub fn recall_ranked(
        &self,
        kek: &Kek,
        query: &str,
        k: usize,
        now: i64,
        params: RecencyParams,
    ) -> Result<Vec<(CellId, String)>, StoreError> {
        let query_vec = self
            .embedder
            .embed(query)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        // Score every candidate (not just the top-k by cosine) so recency can promote a
        // slightly-less-similar but newer hit above an older one.
        let mut scored: Vec<(CellId, f32)> = Vec::new();
        for (id, cosine) in self.index.search(&query_vec, self.index.len()) {
            if self.superseded.contains(id.as_bytes()) {
                continue; // a newer version of this fact exists — hide the stale one
            }
            let weight = match self.store.created_at(&id)? {
                Some(ts) => params.weight((now - ts).max(0) as f64),
                None => 1.0,
            };
            scored.push((id, cosine * weight));
        }
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored.truncate(k);
        let mut out = Vec::new();
        for (id, _score) in scored {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    out.push((id, text));
                }
            }
        }
        Ok(out)
    }

    /// Like [`MemoryVault::remember_at`] but also records a provenance `source` (where the
    /// memory came from, e.g. `proxy:openai:gpt-4` / `mcp:claude` / `desktop` / `cli`).
    pub fn remember_with_source(
        &mut self,
        kek: &Kek,
        text: &str,
        created_at: i64,
        source: Option<&str>,
    ) -> Result<CellId, StoreError> {
        let id = self
            .store
            .remember_with_source(kek, text.as_bytes(), created_at, source)?;
        let vector = self
            .embedder
            .embed(text)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        self.index.add(id.clone(), &vector);
        Ok(id)
    }

    /// The provenance `source` of a memory, if one was recorded.
    pub fn source(&self, id: &CellId) -> Result<Option<String>, StoreError> {
        self.store.source(id)
    }

    /// Remember a keyed fact: record `value` for `subject` in the bi-temporal ledger and,
    /// if it changes a previously-stored value, mark the old cell **superseded** (kept and
    /// still erasable, but hidden from quality recall). Returns `(cell_id, changed)`;
    /// `changed` is `false` when that value was already current (no new cell is written).
    ///
    /// The `subject` key is supplied by the caller; entity-derived keys — so that
    /// differently-worded updates of the same fact link up — arrive with the graph layer.
    pub fn remember_fact(
        &mut self,
        kek: &Kek,
        subject: &str,
        value: &str,
        now: i64,
    ) -> Result<(CellId, bool), StoreError> {
        let prior = self.store.subject_current(subject)?;
        let changed = self.ledger.record(subject, value, now as u64);
        match (prior, changed) {
            // The same value is already current → don't write a duplicate cell.
            (Some(existing), false) => Ok((existing, false)),
            // A different value → store the new one and supersede the old.
            (Some(old), true) => {
                let id = self.remember_with_source(kek, value, now, Some("fact"))?;
                self.store.mark_superseded(&old)?;
                self.superseded.insert(*old.as_bytes());
                self.store.set_subject_current(subject, &id)?;
                Ok((id, true))
            }
            // First value ever recorded for this subject.
            (None, _) => {
                let id = self.remember_with_source(kek, value, now, Some("fact"))?;
                self.store.set_subject_current(subject, &id)?;
                Ok((id, true))
            }
        }
    }

    /// The currently-valid value for fact `subject` (in-session ledger view).
    pub fn current_fact(&self, subject: &str) -> Option<&str> {
        self.ledger.current(subject)
    }

    /// Record knowledge-graph triples distilled from memory `cell`: persist each edge and add it
    /// to the in-RAM graph. Idempotent per `(cell, subject, relation, object)`.
    pub fn add_triples(
        &mut self,
        cell: &CellId,
        triples: &[Triple],
        now: i64,
    ) -> Result<(), StoreError> {
        for t in triples {
            self.store
                .add_edge(cell, &t.subject, &t.relation, &t.object, now)?;
            self.graph.add(cell.clone(), t.clone());
        }
        Ok(())
    }

    /// Convenience: record a single `(subject, relation, object)` triple from `cell`.
    pub fn add_triple(
        &mut self,
        cell: &CellId,
        subject: &str,
        relation: &str,
        object: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        self.add_triples(cell, &[Triple::new(subject, relation, object)], now)
    }

    /// What `entity` is connected to in the knowledge graph: `(relation, other entity)` pairs.
    pub fn graph_neighbors(&self, entity: &str) -> Vec<(String, String)> {
        self.graph.neighbors(entity)
    }

    /// Graph-enriched recall: the recency-ranked vector hits, plus any memory connected through
    /// the knowledge graph to an entity named in `query` (deduped; superseded/forgotten cells
    /// excluded). Surfaces relevant memories a pure vector search would miss.
    pub fn recall_with_graph(
        &self,
        kek: &Kek,
        query: &str,
        k: usize,
        now: i64,
        params: RecencyParams,
    ) -> Result<Vec<(CellId, String)>, StoreError> {
        let mut out = self.recall_ranked(kek, query, k, now, params)?;
        let mut seen: HashSet<[u8; 32]> = out.iter().map(|(id, _)| *id.as_bytes()).collect();
        for cell in self.graph.cells_for_text(query) {
            if self.superseded.contains(cell.as_bytes()) || !seen.insert(*cell.as_bytes()) {
                continue;
            }
            if let Some(bytes) = self.store.recall(kek, &cell)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    out.push((cell, text));
                }
            }
        }
        Ok(out)
    }

    /// Recall using a named [`RecallProfile`] — the unifying entry point for callers that expose a
    /// retrieval mode. The profile selects the recency curve and whether the knowledge graph
    /// enriches the result; everything stays local to the encrypted vault.
    pub fn recall_with_profile(
        &self,
        kek: &Kek,
        query: &str,
        k: usize,
        now: i64,
        profile: RecallProfile,
    ) -> Result<Vec<(CellId, String)>, StoreError> {
        match profile {
            RecallProfile::GraphFirst | RecallProfile::Hybrid => {
                self.recall_with_graph(kek, query, k, now, profile.recency())
            }
            _ => self.recall_ranked(kek, query, k, now, profile.recency()),
        }
    }

    /// Erase a memory: forget the content (cryptographic erasure) and drop its
    /// embedding from the index.
    pub fn forget(&mut self, id: &CellId) -> Result<(), StoreError> {
        self.store.forget(id)?;
        self.index.remove(id);
        self.superseded.remove(id.as_bytes());
        self.graph.remove_cell(id);
        Ok(())
    }

    /// Share a cell's content with a grantee by sealing it to their X25519 public key.
    /// The grantee opens it with `keepsake_crypto::open_sealed`; nobody else can, and the
    /// proxy never hands out plaintext.
    pub fn share(
        &self,
        kek: &Kek,
        id: &CellId,
        grantee_public: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        match self.store.recall(kek, id)? {
            Some(plaintext) => Ok(keepsake_crypto::seal_to(grantee_public, &plaintext)),
            None => Ok(None),
        }
    }

    /// Number of live (non-forgotten) memories.
    pub fn count(&self) -> Result<usize, StoreError> {
        Ok(self.store.live_cell_ids()?.len())
    }

    /// Merge near-duplicate live memories: forget any memory at least `threshold` cosine-similar
    /// to an earlier one, keeping a single representative. Returns the number merged away — the
    /// background anti-bloat sweep that catches near-duplicates slipping past the write-time
    /// guard. (Index vectors are unit-normalized, so a dot product is the cosine similarity.)
    pub fn consolidate(&mut self, threshold: f32) -> Result<usize, StoreError> {
        let entries: Vec<(CellId, Vec<f32>)> = self.index.entries().to_vec();
        let mut gone: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for i in 0..entries.len() {
            if gone.contains(entries[i].0.as_bytes()) {
                continue;
            }
            for j in (i + 1)..entries.len() {
                if gone.contains(entries[j].0.as_bytes()) {
                    continue;
                }
                let sim: f32 = entries[i]
                    .1
                    .iter()
                    .zip(&entries[j].1)
                    .map(|(a, b)| a * b)
                    .sum();
                if sim >= threshold {
                    self.forget(&entries[j].0)?;
                    gone.insert(*entries[j].0.as_bytes());
                }
            }
        }
        Ok(gone.len())
    }

    /// Build a **similarity map** of the live memories for the visual graph view: every memory is a
    /// node, and two memories are linked when their on-device embeddings are similar (cosine ≥
    /// `threshold`). Reuses the in-RAM unit-normalized vector index (so a dot product *is* the
    /// cosine), keeps at most `max_edges_per_node` strongest links per node (union of either
    /// endpoint's top-k, so nothing is orphaned), drops superseded cells, and caps to the most-recent
    /// `max_nodes`. Node titles are the first non-empty line of each memory. Local + model-free.
    pub fn memory_graph(
        &self,
        kek: &Kek,
        threshold: f32,
        max_edges_per_node: usize,
        max_nodes: usize,
    ) -> Result<MemoryGraph, StoreError> {
        let mut entries: Vec<(CellId, Vec<f32>)> = self.index.entries().to_vec();
        entries.retain(|(id, _)| !self.superseded.contains(id.as_bytes()));

        // Cap huge vaults to the most-recent max_nodes (don't silently truncate the middle).
        if entries.len() > max_nodes {
            let mut with_ts: Vec<(i64, (CellId, Vec<f32>))> = Vec::with_capacity(entries.len());
            for e in entries.drain(..) {
                let ts = self.store.created_at(&e.0)?.unwrap_or(0);
                with_ts.push((ts, e));
            }
            with_ts.sort_by_key(|x| std::cmp::Reverse(x.0));
            with_ts.truncate(max_nodes);
            entries = with_ts.into_iter().map(|(_, e)| e).collect();
        }

        // Nodes: decrypt each cell once for a short title + the (bounded) full text.
        let mut nodes = Vec::with_capacity(entries.len());
        for (id, _) in &entries {
            let full = self
                .store
                .recall(kek, id)?
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            let title: String = full
                .lines()
                .find(|l| !l.trim().is_empty())
                .map(|l| l.trim().chars().take(60).collect())
                .unwrap_or_default();
            let text: String = full.chars().take(2000).collect();
            nodes.push(GraphNode {
                id: id.clone(),
                title,
                text,
                created_at: self.store.created_at(id)?.unwrap_or(0),
                source: self.store.source(id)?,
            });
        }

        // Edges: pairwise cosine (dot of unit vectors), keep those ≥ threshold.
        let mut all: Vec<(usize, usize, f32)> = Vec::new();
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                let sim: f32 = entries[i]
                    .1
                    .iter()
                    .zip(&entries[j].1)
                    .map(|(a, b)| a * b)
                    .sum();
                if sim >= threshold {
                    all.push((i, j, sim));
                }
            }
        }

        // Per-node degree cap: keep an edge if EITHER endpoint ranks it in its top-k (union).
        let mut incident: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
        for (e, &(i, j, _)) in all.iter().enumerate() {
            incident[i].push(e);
            incident[j].push(e);
        }
        let mut keep = vec![false; all.len()];
        for inc in &incident {
            let mut es = inc.clone();
            es.sort_by(|&x, &y| all[y].2.total_cmp(&all[x].2));
            for &e in es.iter().take(max_edges_per_node) {
                keep[e] = true;
            }
        }
        let edges = all
            .iter()
            .enumerate()
            .filter(|(e, _)| keep[*e])
            .map(|(_, &(a, b, weight))| GraphEdge { a, b, weight })
            .collect();

        Ok(MemoryGraph { nodes, edges })
    }

    /// Share a cell under a SAIHM contract: atomically seal the content to each grantee's
    /// public key. A TEMPORARY contract is rejected if its window is empty or exceeds 24h.
    pub fn share_with_contract(
        &self,
        kek: &Kek,
        id: &CellId,
        kind: ContractKind,
        grantees: &[[u8; 32]],
        now: u64,
    ) -> Result<Option<ShareContract>, StoreError> {
        if let ContractKind::Temporary { expires_at } = kind {
            if expires_at <= now || expires_at - now > TEMPORARY_MAX_SECS {
                return Ok(None);
            }
        }
        let Some(plaintext) = self.store.recall(kek, id)? else {
            return Ok(None);
        };
        // Atomic: if sealing to any grantee fails (e.g. a low-order / invalid key), reject
        // the whole contract rather than issuing a partial one.
        let Some(portions) = grantees
            .iter()
            .map(|g| keepsake_crypto::seal_to(g, &plaintext).map(|s| (*g, s)))
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(None);
        };
        Ok(Some(ShareContract {
            kind,
            issued_at: now,
            portions,
        }))
    }

    /// The most recent live memories, newest first, as `(cell_id, plaintext,
    /// created_at)`. Chronological (no embedding/search) — backs the dashboard timeline.
    pub fn recent(
        &self,
        kek: &Kek,
        limit: usize,
    ) -> Result<Vec<(CellId, String, i64)>, StoreError> {
        let mut out = Vec::new();
        for (id, created_at) in self.store.recent(limit)? {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    out.push((id, text, created_at));
                }
            }
        }
        Ok(out)
    }

    /// Rebuild the in-RAM index from persisted content by re-embedding each live cell.
    pub fn rebuild_index(&mut self, kek: &Kek) -> Result<(), StoreError> {
        let mut index = VectorIndex::new();
        for id in self.store.live_cell_ids()? {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    let vector = self
                        .embedder
                        .embed(&text)
                        .map_err(|e| StoreError::Embed(e.to_string()))?;
                    index.add(id, &vector);
                }
            }
        }
        self.index = index;
        self.superseded = self.store.superseded_ids()?.into_iter().collect();
        let mut graph = GraphIndex::new();
        for (sc, s, r, o) in self.store.live_edges()? {
            graph.add(CellId::from_bytes(sc), Triple::new(&s, &r, &o));
        }
        self.graph = graph;
        Ok(())
    }

    /// Export the whole vault as a portable, encrypted [`keepsake_store_sqlite::Passport`] —
    /// sealed records + tombstones, inert without the seed.
    pub fn export_passport(&self) -> Result<keepsake_store_sqlite::Passport, StoreError> {
        self.store.export_passport()
    }

    /// Import a passport (merge; local erasures always win), then rebuild the index so the imported
    /// memories are immediately recallable. Returns how many records were applied.
    pub fn import_passport(
        &mut self,
        kek: &Kek,
        passport: &keepsake_store_sqlite::Passport,
    ) -> Result<usize, StoreError> {
        let n = self.store.import_passport(passport)?;
        self.rebuild_index(kek)?;
        Ok(n)
    }
}

/// Current wall-clock time in Unix seconds (0 if the clock predates the epoch).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::RootKeys;
    use keepsake_retrieval::MockEmbedder;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_kek() -> Kek {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        Kek::from_root(&roots.encryption_root)
    }

    fn memory_vault() -> MemoryVault<MockEmbedder> {
        MemoryVault::new(
            SqliteVault::open_in_memory().unwrap(),
            MockEmbedder::new(64),
        )
    }

    #[test]
    fn recent_texts_returns_recent_memories_for_distillation() {
        let mut vault = memory_vault();
        let kek = test_kek();
        vault.remember_at(&kek, "older note", 100).unwrap();
        vault.remember_at(&kek, "newer note", 200).unwrap();
        let texts = vault.recent_texts(&kek, 10).unwrap();
        assert!(texts.iter().any(|t| t == "newer note"), "got: {texts:?}");
        assert!(texts.iter().any(|t| t == "older note"), "got: {texts:?}");
    }

    #[test]
    fn semantic_recall_returns_the_matching_memory() {
        let kek = test_kek();
        let mut vault = memory_vault();
        vault.remember(&kek, "alpha alpha alpha").unwrap();
        vault.remember(&kek, "bravo bravo bravo").unwrap();
        vault.remember(&kek, "charlie charlie charlie").unwrap();

        let hits = vault.recall(&kek, "bravo bravo bravo", 1).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "bravo bravo bravo");
    }

    #[test]
    fn recency_weight_decays_to_floor_not_zero() {
        let p = RecencyParams::default();
        assert!(
            (p.weight(0.0) - 1.0).abs() < 1e-6,
            "fresh memory keeps full weight"
        );
        assert!(
            (p.weight(p.half_life_secs) - 0.75).abs() < 1e-3,
            "one half-life ≈ floor + half of the remainder (0.5 + 0.25)"
        );
        assert!(p.weight(1e12) >= p.floor, "never decays below the floor");
        assert!(
            p.weight(1e12) < 0.51,
            "but approaches the floor for ancient memories"
        );
    }

    #[test]
    fn recall_ranked_prefers_recent_among_equally_similar() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let now = 1_700_000_000i64;
        let day = 86_400i64;
        // Same text → identical embedding → identical cosine; only the age differs, so
        // recency must break the tie toward the newer memory.
        let old = vault
            .remember_at(&kek, "alpha alpha alpha", now - 365 * day)
            .unwrap();
        let new = vault.remember_at(&kek, "alpha alpha alpha", now).unwrap();

        let hits = vault
            .recall_ranked(&kek, "alpha alpha alpha", 2, now, RecencyParams::default())
            .unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, new, "the newer memory ranks first");
        assert_eq!(hits[1].0, old, "the older one second");
    }

    #[test]
    fn recall_profiles_parse_and_shape_the_recency_curve() {
        use RecallProfile::*;
        assert_eq!(RecallProfile::parse("semantic"), Semantic);
        assert_eq!(RecallProfile::parse("RECENT"), Recent);
        assert_eq!(RecallProfile::parse("graph_first"), GraphFirst);
        assert_eq!(RecallProfile::parse("hybrid"), Hybrid);
        assert_eq!(RecallProfile::parse(""), Balanced);
        assert_eq!(RecallProfile::parse("nonsense"), Balanced);

        let year = 365.0 * 86_400.0;
        // Semantic is age-blind: even an ancient memory keeps full weight.
        assert!((Semantic.recency().weight(year) - 1.0).abs() < 1e-6);
        // Recent lets recency dominate: a one-year-old memory decays far harder than under Balanced.
        assert!(Recent.recency().weight(year) < Balanced.recency().weight(year));
        // ...but never below the profile's own floor.
        assert!(Recent.recency().weight(year) >= Recent.recency().floor);
    }

    #[test]
    fn recall_with_profile_dispatches_over_existing_signals() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let now = 1_700_000_000i64;
        let day = 86_400i64;
        vault
            .remember_at(&kek, "alpha alpha alpha", now - 365 * day)
            .unwrap();
        let new = vault.remember_at(&kek, "alpha alpha alpha", now).unwrap();

        // Balanced keeps recency-ranked behaviour: the newer of two equally-similar hits leads.
        let balanced = vault
            .recall_with_profile(&kek, "alpha alpha alpha", 2, now, RecallProfile::Balanced)
            .unwrap();
        assert_eq!(balanced[0].0, new, "Balanced ranks the newer memory first");

        // GraphFirst dispatches to the graph-enriched path and still returns the vector hits.
        let graph = vault
            .recall_with_profile(&kek, "alpha alpha alpha", 2, now, RecallProfile::GraphFirst)
            .unwrap();
        assert!(
            graph.len() >= 2,
            "GraphFirst returns at least the vector hits"
        );

        let hybrid = vault
            .recall_with_profile(&kek, "alpha alpha alpha", 2, now, RecallProfile::Hybrid)
            .unwrap();
        assert_eq!(
            hybrid, graph,
            "Hybrid is the user-facing graph-enriched mode"
        );
    }

    #[test]
    fn clear_profile_removes_the_derived_summary_without_touching_memories() {
        let kek = test_kek();
        let mut vault = memory_vault();
        vault
            .remember_at(&kek, "Berlin dentist Monday", 100)
            .unwrap();
        vault
            .set_profile("The user likes local-first tools.")
            .unwrap();

        vault.clear_profile().unwrap();

        assert_eq!(vault.profile().unwrap(), None);
        assert_eq!(vault.count().unwrap(), 1);
    }

    #[test]
    fn remember_with_source_records_provenance_and_stays_recallable() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault
            .remember_with_source(&kek, "berlin trip friday", 100, Some("proxy:openai:gpt-4"))
            .unwrap();
        assert_eq!(
            vault.source(&id).unwrap().as_deref(),
            Some("proxy:openai:gpt-4")
        );
        let hits = vault.recall(&kek, "berlin trip friday", 1).unwrap();
        assert_eq!(hits[0].0, id, "a sourced memory is recalled like any other");
    }

    #[test]
    fn remember_fact_supersedes_old_value_and_hides_it_from_recall() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let now = 1_700_000_000i64;
        let (py, first) = vault
            .remember_fact(&kek, "language", "I code in Python", now)
            .unwrap();
        assert!(first, "the first value is stored");
        let (rs, changed) = vault
            .remember_fact(&kek, "language", "I switched to Rust", now + 100)
            .unwrap();
        assert!(changed, "a different value supersedes the old one");
        assert_ne!(py, rs);
        assert_eq!(vault.current_fact("language"), Some("I switched to Rust"));

        let ids: Vec<CellId> = vault
            .recall_ranked(
                &kek,
                "I code in Python switched Rust language",
                5,
                now + 100,
                RecencyParams::default(),
            )
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(ids.contains(&rs), "the current fact surfaces");
        assert!(
            !ids.contains(&py),
            "the superseded fact is hidden from recall"
        );
    }

    #[test]
    fn remember_fact_same_value_twice_writes_one_cell() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let now = 1_700_000_000i64;
        let (a, first) = vault.remember_fact(&kek, "home", "Vienna", now).unwrap();
        let (b, second) = vault
            .remember_fact(&kek, "home", "Vienna", now + 10)
            .unwrap();
        assert!(first, "first record stores");
        assert!(
            !second,
            "the same value again does not create a second cell"
        );
        assert_eq!(a, b);
        assert_eq!(vault.count().unwrap(), 1);
    }

    #[test]
    fn recall_with_graph_surfaces_a_connected_memory_vector_search_misses() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let now = 1_700_000_000i64;
        // X names Apollo directly; W's text does not, but a triple links W to Apollo.
        let x = vault
            .remember_at(&kek, "Apollo launches on March 14", now)
            .unwrap();
        let w = vault
            .remember_at(&kek, "the keynote slot is confirmed", now)
            .unwrap();
        vault
            .add_triples(&x, &[Triple::new("Apollo", "launches_on", "March 14")], now)
            .unwrap();
        vault
            .add_triples(&w, &[Triple::new("Apollo", "has_event", "keynote")], now)
            .unwrap();

        // Plain vector recall (k=1) for "Apollo" returns the directly-matching X, not W.
        let plain: Vec<CellId> = vault
            .recall_ranked(&kek, "Apollo", 1, now, RecencyParams::default())
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(plain.contains(&x) && !plain.contains(&w));

        // Graph-enriched recall also pulls in W, connected to Apollo, that the vector search missed.
        let enriched: Vec<CellId> = vault
            .recall_with_graph(&kek, "Apollo", 1, now, RecencyParams::default())
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(enriched.contains(&x), "keeps the direct hit");
        assert!(enriched.contains(&w), "adds the graph-connected memory");
    }

    #[test]
    fn recall_map_shows_triples_with_ids_and_get_cell_fetches_text_erasure_honest() {
        let mut vault = memory_vault();
        let kek = test_kek();
        let now = 1_000;
        let text = "Apollo is our secret flagship, launching on March 14";
        let cell = vault.remember(&kek, text).unwrap();
        vault
            .add_triples(
                &cell,
                &[Triple::new("Apollo", "launches_on", "March 14")],
                now,
            )
            .unwrap();

        // The map shows STRUCTURE (triples + the backing id), not the full memory prose.
        let map = vault.recall_map(&kek, text, 5).unwrap();
        let id_hex = hex::encode(cell.as_bytes());
        assert!(map.contains("launches_on"), "map shows the relation: {map}");
        assert!(map.contains(&id_hex), "map tags the edge with its cell id");
        assert!(
            !map.contains("secret flagship"),
            "map must NOT carry the full memory text"
        );
        assert!(
            map.contains("Partial view") && map.contains("saihm_recall_cell"),
            "the map self-documents that it is a partial view and how to expand a node: {map}"
        );

        // Fetch the full text by id, on demand.
        assert_eq!(vault.get_cell(&kek, &cell).unwrap().as_deref(), Some(text));

        // Erasure stays honest: forget → gone from the map AND get_cell returns None.
        vault.forget(&cell).unwrap();
        assert!(
            vault.recall_map(&kek, text, 5).unwrap().is_empty(),
            "forgotten cell → empty map"
        );
        assert!(
            vault.get_cell(&kek, &cell).unwrap().is_none(),
            "forgotten cell → no text"
        );
    }

    #[test]
    fn exact_duplicate_is_caught_by_the_keyed_tag_and_storeable_again_after_forget() {
        let kek = test_kek();
        let mut vault = memory_vault();
        // Threshold > 1.0 disables the cosine near-dup path, isolating the keyed-tag exact-dup.
        let (id1, stored1) = vault
            .remember_deduped_with_source(&kek, "buy milk on tuesday", 2.0, 100, None)
            .unwrap();
        assert!(stored1, "first save stores");
        let (id2, stored2) = vault
            .remember_deduped_with_source(&kek, "buy milk on tuesday", 2.0, 200, None)
            .unwrap();
        assert!(!stored2, "an exact re-save is a no-op via the keyed tag");
        assert_eq!(id1, id2, "and maps back to the same cell");

        // Erasure-honest: after forgetting it, the same text stores fresh (the tag was cleaned).
        vault.forget(&id1).unwrap();
        let (_id3, stored3) = vault
            .remember_deduped_with_source(&kek, "buy milk on tuesday", 2.0, 300, None)
            .unwrap();
        assert!(stored3, "after forget, the same text is stored anew");
    }

    #[test]
    fn exported_passport_never_carries_local_dedup_tags() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let secret = "my PIN is 1234";
        vault
            .remember_deduped_with_source(&kek, secret, 2.0, 100, None)
            .unwrap();
        let tag = kek.content_tag(secret.as_bytes());
        // The tag exists locally...
        assert!(vault.store().dedup_lookup(&tag).unwrap().is_some());
        // ...but must NEVER appear in an exported/synced passport (zero-knowledge: keyed-or-it-leaks).
        let passport = vault.export_passport().unwrap();
        let json = serde_json::to_string(&passport).unwrap();
        assert!(
            !json.contains(&hex::encode(tag)),
            "the local dedup tag must not appear in an exported passport"
        );
    }

    #[test]
    fn memory_graph_has_one_node_per_memory_and_filters_edges_by_threshold() {
        let kek = test_kek();
        let mut vault = memory_vault();
        vault
            .remember_at(&kek, "berlin trip on friday", 100)
            .unwrap();
        vault
            .remember_at(&kek, "berlin flight friday morning", 110)
            .unwrap();
        vault.remember_at(&kek, "buy milk and eggs", 120).unwrap();

        let g = vault.memory_graph(&kek, 0.0, 8, 3000).unwrap();
        assert_eq!(g.nodes.len(), 3, "one node per memory");
        assert!(
            g.nodes.iter().all(|n| !n.title.is_empty()),
            "every node has a title"
        );
        for e in &g.edges {
            assert!(
                e.a < g.nodes.len() && e.b < g.nodes.len() && e.a != e.b,
                "valid endpoints"
            );
            assert!(e.weight >= 0.0, "kept edges meet the threshold");
        }

        // An impossible threshold yields no edges, but the nodes stay.
        let g2 = vault.memory_graph(&kek, 2.0, 8, 3000).unwrap();
        assert!(g2.edges.is_empty(), "no cosine reaches 2.0");
        assert_eq!(g2.nodes.len(), 3);

        // An empty vault is an empty map (no panic, no nodes).
        let empty = memory_vault();
        let g3 = empty.memory_graph(&kek, 0.5, 8, 3000).unwrap();
        assert!(g3.nodes.is_empty() && g3.edges.is_empty());
    }

    #[test]
    fn recent_returns_decrypted_memories_with_timestamps() {
        let kek = test_kek();
        let mut vault = memory_vault();
        vault.remember(&kek, "first thing").unwrap();
        vault.remember(&kek, "second thing").unwrap();

        let recent = vault.recent(&kek, 10).unwrap();
        assert_eq!(recent.len(), 2);
        let texts: Vec<&str> = recent.iter().map(|(_, t, _)| t.as_str()).collect();
        assert!(texts.contains(&"first thing") && texts.contains(&"second thing"));
        assert!(
            recent.iter().all(|(_, _, ts)| *ts > 0),
            "carries a real timestamp"
        );
        assert_eq!(vault.recent(&kek, 1).unwrap().len(), 1, "limit respected");
    }

    #[test]
    fn forget_removes_from_semantic_recall() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "secret note").unwrap();
        vault.forget(&id).unwrap();

        let hits = vault.recall(&kek, "secret note", 5).unwrap();
        assert!(
            hits.iter().all(|(hid, _)| hid != &id),
            "forgotten memory must not surface"
        );
    }

    #[test]
    fn count_tracks_live_memories() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let a = vault.remember(&kek, "one").unwrap();
        vault.remember(&kek, "two").unwrap();
        assert_eq!(vault.count().unwrap(), 2);
        vault.forget(&a).unwrap();
        assert_eq!(vault.count().unwrap(), 1);
    }

    #[test]
    fn remember_deduped_skips_near_duplicates() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let (_, stored) = vault
            .remember_deduped(&kek, "alpha alpha alpha", 0.95)
            .unwrap();
        assert!(stored, "the first write stores");
        let (_, dup) = vault
            .remember_deduped(&kek, "alpha alpha alpha", 0.95)
            .unwrap();
        assert!(!dup, "an identical memory is not stored twice");
        assert_eq!(vault.count().unwrap(), 1, "no duplicate cell created");
        let (_, fresh) = vault
            .remember_deduped(&kek, "zulu zulu zulu", 0.95)
            .unwrap();
        assert!(fresh, "a clearly different memory is stored");
        assert_eq!(vault.count().unwrap(), 2);
    }

    #[test]
    fn consolidate_merges_near_duplicates() {
        let kek = test_kek();
        let mut vault = memory_vault();
        // Raw remember (no write-time dedup) creates two identical memories…
        vault.remember(&kek, "yankee yankee yankee").unwrap();
        vault.remember(&kek, "yankee yankee yankee").unwrap();
        vault.remember(&kek, "distinct other thing").unwrap();
        assert_eq!(vault.count().unwrap(), 3);
        let merged = vault.consolidate(0.95).unwrap();
        assert_eq!(merged, 1, "the duplicate is merged away");
        assert_eq!(vault.count().unwrap(), 2);
    }

    #[test]
    fn share_seals_content_to_grantee_only() {
        use keepsake_crypto::{open_sealed, ShareKeypair};
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "shared secret note").unwrap();

        let grantee = ShareKeypair::from_seed(&[5u8; 32]);
        let other = ShareKeypair::from_seed(&[6u8; 32]);

        let sealed = vault.share(&kek, &id, &grantee.public()).unwrap().unwrap();
        let opened = open_sealed(&grantee, &sealed).unwrap();
        assert_eq!(String::from_utf8(opened).unwrap(), "shared secret note");
        assert!(
            open_sealed(&other, &sealed).is_err(),
            "only the grantee can open the shared cell"
        );
    }

    #[test]
    fn syndicate_contract_seals_to_all_grantees_only() {
        use keepsake_crypto::ShareKeypair;
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "syndicate secret").unwrap();

        let g1 = ShareKeypair::from_seed(&[1u8; 32]);
        let g2 = ShareKeypair::from_seed(&[2u8; 32]);
        let outsider = ShareKeypair::from_seed(&[9u8; 32]);

        let contract = vault
            .share_with_contract(
                &kek,
                &id,
                ContractKind::Syndicate,
                &[g1.public(), g2.public()],
                0,
            )
            .unwrap()
            .unwrap();
        assert_eq!(contract.portions.len(), 2);
        assert_eq!(
            String::from_utf8(open_contract_portion(&contract, &g1, 0).unwrap()).unwrap(),
            "syndicate secret"
        );
        assert_eq!(
            String::from_utf8(open_contract_portion(&contract, &g2, 0).unwrap()).unwrap(),
            "syndicate secret"
        );
        assert!(open_contract_portion(&contract, &outsider, 0).is_none());
    }

    #[test]
    fn temporary_contract_expires_and_rejects_over_24h() {
        use keepsake_crypto::ShareKeypair;
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "temp secret").unwrap();
        let g = ShareKeypair::from_seed(&[1u8; 32]);

        let contract = vault
            .share_with_contract(
                &kek,
                &id,
                ContractKind::Temporary { expires_at: 100 },
                &[g.public()],
                0,
            )
            .unwrap()
            .unwrap();
        assert!(
            open_contract_portion(&contract, &g, 50).is_some(),
            "valid before expiry"
        );
        assert!(
            open_contract_portion(&contract, &g, 200).is_none(),
            "expired afterwards"
        );

        // A window longer than 24h is rejected at issue.
        assert!(vault
            .share_with_contract(
                &kek,
                &id,
                ContractKind::Temporary {
                    expires_at: TEMPORARY_MAX_SECS + 1
                },
                &[g.public()],
                0,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn rebuild_index_restores_recall_from_persisted_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let kek = test_kek();

        {
            let mut vault = MemoryVault::new(
                SqliteVault::open(&path, &[0x33u8; 32]).unwrap(),
                MockEmbedder::new(64),
            );
            vault.remember(&kek, "alpha alpha alpha").unwrap();
            vault.remember(&kek, "bravo bravo bravo").unwrap();
        }

        let mut reopened = MemoryVault::new(
            SqliteVault::open(&path, &[0x33u8; 32]).unwrap(),
            MockEmbedder::new(64),
        );
        // Fresh index is empty until rebuilt.
        assert!(reopened
            .recall(&kek, "alpha alpha alpha", 1)
            .unwrap()
            .is_empty());

        reopened.rebuild_index(&kek).unwrap();
        let hits = reopened.recall(&kek, "alpha alpha alpha", 1).unwrap();
        assert_eq!(hits[0].1, "alpha alpha alpha");
    }
}
