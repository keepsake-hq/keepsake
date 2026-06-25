# Compact Graph Recall ("symbol-graph" context compression)

*Design — 2026-06-25. Concept 2 of the Tencent-inspired memory work (Concept 1 was the
distilled profile pyramid).*

## Goal

Token-efficient memory for agents. Instead of injecting the full text of N recalled memories,
hand the model a **compact map** first — the relevant entities and their relations, each tagged
with the cell-id that backs it — and let the model fetch a node's **full text on demand, by id**.

The compression comes from showing *structure* (triples) instead of *prose*. A map of 20 edges is
a fraction of the tokens of 20 full memories, yet it tells the model what exists and how it
connects, so it can pull only the 1–2 nodes it actually needs.

## Why agent-facing (not the proxy)

The payoff only materialises when the consumer can **ask a follow-up** — read the map, then fetch
a node. Agentic clients (Claude Code, Codex, Cursor over MCP) work step by step and can do this.
The one-shot OpenAI-compatible proxy injects context once and cannot fetch back mid-turn, so it
keeps its existing graph-enriched recall. Concept 2 lives on the **MCP + CLI + daemon** surface.

This is opt-in: it adds new tools/commands. Existing `recall` is unchanged.

## The map format

One edge per line, each carrying the backing cell-id (full hex, unambiguous) as the fetch handle:

```
# Memory map — fetch a node's full text with saihm_recall_cell <id>
[<cell_id_hex>] <subject> --<relation>--> <object>
[<cell_id_hex>] <subject> --<relation>--> <object>
...
```

Empty graph (or no relevant edges) → an empty string. No prose, no embeddings, no secrets beyond
what the triples already encode.

## Vertical layers (bottom-up), each TDD'd

1. **`keepsake-graph` — render a subgraph.**
   - `GraphIndex::subgraph(cells: &HashSet<CellId>) -> Vec<(CellId, Triple)>` — the edges whose
     backing cell is in `cells` (the query-relevant region). Reuses the existing edge store.
   - `format_map(edges: &[(CellId, Triple)]) -> String` — renders the compact lines above.
   - *Proof:* a subgraph over a cell-set returns only its edges; `format_map` emits one line per
     edge with the id, subject, relation, object, and **no full memory text**.

2. **`keepsake-vault` — query → map, and fetch-by-id.**
   - `recall_map(kek, query, k) -> String` — vector-recall the top-`k` relevant cell-ids for the
     query, then render the subgraph map over those cells.
   - `get_cell(kek, cell_id) -> Option<String>` — the decrypted full text of one cell (the store
     already supports recall-by-id; this exposes it at the vault).
   - *Proof:* `recall_map` returns a map mentioning a stored fact's entities; `get_cell` returns a
     cell's text; a **forgotten** cell is absent from the map **and** `get_cell` returns `None`
     (erasure stays honest — the graph already drops forgotten cells via `remove_cell`, and the
     store's key-row is gone).

3. **`keepsake-daemon` — hub RPCs.**
   - `graph/map` (params: `query`, `k`) → map string. **Read**-scoped.
   - `vault/get` (params: `cell_id`) → text or null. **Read**-scoped.
   - `DaemonClient::recall_map(query, k)` and `get_cell(cell_id)`.
   - *Proof:* a read-only capability can call both over the hub and round-trip a stored fact;
     map/get respect capability scope.

4. **`keepsake-mcp` — agent tools.**
   - `saihm_recall_map` (`query`, optional `k`) → map. **Read** permission.
   - `saihm_recall_cell` (`cell_id`) → full text. **Read** permission.
   - Added to the tool list, dispatch, per-tool permission check, and the advertised schemas.
   - *Proof:* both tools listed and callable; both require read; `recall_cell` on a forgotten id
     returns empty.

5. **`keepsake-cli` — inspection commands.**
   - `keepsake map "<query>" [--k N]` → prints the compact map.
   - `keepsake get <cell_id>` → prints the full text.
   - These need the live graph (the daemon's rebuilt index), so they talk to the hub via
     `DaemonClient` (like the hooks), seedless with a capability token.
   - *Proof:* against a live hub, `map` lists a stored fact's edges and `get <id>` returns its text.

## Erasure (the invariant)

`forget(cell)` already (a) deletes the cell's key-row + secure-deletes pages in the store and
(b) calls `GraphIndex::remove_cell`. Therefore a forgotten cell cannot appear in a map and cannot
be fetched by id. No new erasure surface is introduced; new code only *reads*. A test asserts the
full round-trip: remember → appears in map + get → forget → absent from map + get returns None.

## Out of scope (named, not silently dropped)

- **Proxy map-mode** (one-shot "map only" injection): possible later, but loses fetch-back, so not
  built now.
- **Desktop UI** for the map: the daemon RPCs make it trivial to add later; not in this slice.
- **Id prefixes / short symbols:** v1 uses full hex ids (safe, unambiguous). Prefix resolution can
  shorten the map later if token budgets demand it.

## Gate

`cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings` green; desktop
crate `cargo check` green. Anonymous push under `keepsake-dev` via the deploy key; CI `success`.
