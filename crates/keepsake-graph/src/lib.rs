//! `keepsake-graph` — a small knowledge graph over the vault's memories.
//!
//! Memories are distilled into `(subject, relation, object)` triples; each triple becomes an
//! edge linked to the **source cell** it came from. An in-RAM [`GraphIndex`] answers "which
//! memories mention this entity?" and "what is this entity connected to?", and forgetting a
//! cell drops its edges so cryptographic erasure stays real. Triple *extraction* (a model
//! pass) lives in the gateway; this crate is the pure, deterministic graph core.

use keepsake_core::CellId;
use std::collections::HashMap;

/// A `(subject, relation, object)` fact distilled from a memory, e.g.
/// `("Ada", "uses", "Rust")`. Stored verbatim; matched case-insensitively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Triple {
    pub subject: String,
    pub relation: String,
    pub object: String,
}

impl Triple {
    pub fn new(subject: &str, relation: &str, object: &str) -> Self {
        Triple {
            subject: subject.trim().to_string(),
            relation: relation.trim().to_string(),
            object: object.trim().to_string(),
        }
    }
}

/// Parse a model reply into triples: one per line as `subject | relation | object` (the format
/// the extraction prompt asks for). Bullets, blank lines, a bare `NONE`, and malformed lines are
/// ignored, so a noisy model reply degrades to fewer triples rather than garbage.
pub fn parse_triples(reply: &str) -> Vec<Triple> {
    reply
        .lines()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches(['-', '*', '•']).trim();
            if line.is_empty() || line.eq_ignore_ascii_case("none") {
                return None;
            }
            let parts: Vec<&str> = line.split('|').map(str::trim).collect();
            if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
                Some(Triple::new(parts[0], parts[1], parts[2]))
            } else {
                None
            }
        })
        .collect()
}

/// Normalize an entity label for matching (trim + lowercase).
fn norm(entity: &str) -> String {
    entity.trim().to_lowercase()
}

/// In-RAM adjacency over `(cell → triples)` and `(entity → cells)`, rebuilt from the store's
/// edges on unlock — the graph counterpart of the vector index.
#[derive(Default)]
pub struct GraphIndex {
    /// Every edge: `(source cell, triple)`.
    edges: Vec<(CellId, Triple)>,
    /// Normalized entity → the source cells mentioning it (as subject or object).
    by_entity: HashMap<String, Vec<CellId>>,
}

impl GraphIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Record that `triple` was distilled from memory `cell`.
    pub fn add(&mut self, cell: CellId, triple: Triple) {
        for entity in [triple.subject.as_str(), triple.object.as_str()] {
            let cells = self.by_entity.entry(norm(entity)).or_default();
            if !cells.contains(&cell) {
                cells.push(cell.clone());
            }
        }
        self.edges.push((cell, triple));
    }

    /// The memories whose triples mention `entity` (as subject or object), in insertion order —
    /// used to expand recall with graph-connected memories a pure vector search would miss.
    pub fn cells_mentioning(&self, entity: &str) -> Vec<CellId> {
        self.by_entity
            .get(&norm(entity))
            .cloned()
            .unwrap_or_default()
    }

    /// What `entity` is connected to: `(relation, other entity)` for each edge touching it.
    pub fn neighbors(&self, entity: &str) -> Vec<(String, String)> {
        let key = norm(entity);
        let mut out = Vec::new();
        for (_, t) in &self.edges {
            if norm(&t.subject) == key {
                out.push((t.relation.clone(), t.object.clone()));
            } else if norm(&t.object) == key {
                out.push((t.relation.clone(), t.subject.clone()));
            }
        }
        out
    }

    /// The memories connected to any entity that appears in `text` — a cheap one-hop expansion
    /// for recall: normalize the text and union the cells of every known entity (≥ 3 chars) that
    /// occurs in it. It only ever *adds* candidates a pure vector search would miss; crude by
    /// design (substring, no word boundaries), so callers treat it as a recall booster, not truth.
    pub fn cells_for_text(&self, text: &str) -> Vec<CellId> {
        let hay = norm(text);
        let mut out: Vec<CellId> = Vec::new();
        for (entity, cells) in &self.by_entity {
            if entity.len() >= 3 && hay.contains(entity.as_str()) {
                for c in cells {
                    if !out.contains(c) {
                        out.push(c.clone());
                    }
                }
            }
        }
        out
    }

    /// Drop every edge sourced from `cell` — cryptographic erasure cascades into the graph.
    pub fn remove_cell(&mut self, cell: &CellId) {
        self.edges.retain(|(c, _)| c != cell);
        for cells in self.by_entity.values_mut() {
            cells.retain(|c| c != cell);
        }
        self.by_entity.retain(|_, cells| !cells.is_empty());
    }

    /// All edges, for persistence or snapshotting.
    pub fn all_edges(&self) -> &[(CellId, Triple)] {
        &self.edges
    }

    /// The edges whose source cell is in `cells` — the query-relevant region of the graph. Used to
    /// render a compact "map" (structure first) instead of injecting full memory texts: callers
    /// pick the relevant cells (e.g. via vector recall), then show their triples with cell ids the
    /// model can fetch full text by, on demand.
    pub fn subgraph(&self, cells: &[CellId]) -> Vec<(CellId, Triple)> {
        self.edges
            .iter()
            .filter(|(c, _)| cells.contains(c))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(n: u8) -> CellId {
        CellId::from_bytes([n; 32])
    }

    #[test]
    fn parse_triples_reads_pipe_separated_lines_and_ignores_noise() {
        let reply = "Ada | uses | Rust\n- Keepsake | is | sovereign\ngarbage line\nNONE\n| | |\n";
        let triples = parse_triples(reply);
        assert_eq!(triples.len(), 2);
        assert_eq!(triples[0], Triple::new("Ada", "uses", "Rust"));
        assert_eq!(triples[1], Triple::new("Keepsake", "is", "sovereign"));
    }

    #[test]
    fn index_links_entities_to_their_memories_case_insensitively() {
        let mut g = GraphIndex::new();
        g.add(cell(1), Triple::new("Apollo", "ships_in", "March"));
        g.add(cell(2), Triple::new("Apollo", "led_by", "Ada"));

        let mut cells = g.cells_mentioning("apollo");
        cells.sort_by_key(|c| *c.as_bytes());
        assert_eq!(cells, vec![cell(1), cell(2)], "both memories mention Apollo");
        assert_eq!(g.cells_mentioning("March"), vec![cell(1)]);

        let n = g.neighbors("Apollo");
        assert!(n.contains(&("ships_in".to_string(), "March".to_string())));
        assert!(n.contains(&("led_by".to_string(), "Ada".to_string())));
    }

    #[test]
    fn forgetting_a_cell_drops_its_edges() {
        let mut g = GraphIndex::new();
        g.add(cell(1), Triple::new("Apollo", "ships_in", "March"));
        g.add(cell(2), Triple::new("Apollo", "led_by", "Ada"));

        g.remove_cell(&cell(1));
        assert_eq!(g.cells_mentioning("Apollo"), vec![cell(2)]);
        assert!(
            g.cells_mentioning("March").is_empty(),
            "the forgotten memory's entity link is gone"
        );
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn cells_for_text_expands_to_connected_memories() {
        let mut g = GraphIndex::new();
        g.add(cell(1), Triple::new("Apollo", "launches_on", "March 14"));
        g.add(cell(2), Triple::new("Apollo", "has_event", "keynote"));
        g.add(cell(3), Triple::new("Zephyr", "is", "unrelated"));

        let mut cells = g.cells_for_text("when does Apollo launch?");
        cells.sort_by_key(|c| *c.as_bytes());
        assert_eq!(cells, vec![cell(1), cell(2)], "both Apollo memories, not Zephyr");
        assert!(g.cells_for_text("nothing pertinent stated").is_empty());
    }

    #[test]
    fn subgraph_returns_only_edges_backed_by_the_requested_cells() {
        let mut g = GraphIndex::new();
        g.add(cell(1), Triple::new("Apollo", "ships_in", "March"));
        g.add(cell(2), Triple::new("Apollo", "led_by", "Ada"));
        g.add(cell(3), Triple::new("Zephyr", "is", "unrelated"));

        let sub = g.subgraph(&[cell(1), cell(3)]);
        assert_eq!(sub.len(), 2);
        assert!(sub.iter().any(|(c, t)| *c == cell(1) && t.object == "March"));
        assert!(sub.iter().any(|(c, t)| *c == cell(3) && t.subject == "Zephyr"));
        assert!(
            !sub.iter().any(|(c, _)| *c == cell(2)),
            "cell 2 was not requested"
        );
        assert!(g.subgraph(&[]).is_empty(), "no cells → empty subgraph");
    }
}
