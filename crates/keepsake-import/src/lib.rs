//! `keepsake-import` — readers that turn another system's memory into normalized
//! [`MemoryItem`]s, so a user switching to Keepsake can bring their existing memory in.
//!
//! These readers are PURE parsing: they read local files/exports and emit items. They add no dedup,
//! no embedding, no crypto — the caller feeds each item through the vault's existing
//! `remember_deduped_with_source`, which already deduplicates, orders by recency, and consolidates.
//! Tag every item's `source` as `import:<system>` so provenance is visible and a full import can be
//! rolled back by forgetting all cells with that source.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One unit of memory pulled out of a source system, ready to be remembered into a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryItem {
    /// The memory text itself (one natural unit: a note, a rule section, a chat turn, a row).
    pub text: String,
    /// Provenance, e.g. `import:claude-code` — surfaces in recall + the timeline, enables rollback.
    pub source: String,
    /// Where it came from on disk (a file path), for the preview grouping. May be empty.
    pub origin_path: String,
    /// Creation time in Unix seconds (the source's own timestamp when known, else the file mtime),
    /// so Keepsake's recency ranking stays honest. `0` when unknown.
    pub created_at: i64,
    /// A coarse kind: `rule` (hand-written instructions), `memory` (a saved fact/note), `note`, `chat`.
    pub role: String,
}

/// Minimum non-whitespace characters for a chunk to count as a real memory (drops blank/heading-only bits).
const MIN_CHARS: usize = 3;

fn meaningful(s: &str) -> bool {
    s.chars().filter(|c| !c.is_whitespace()).count() >= MIN_CHARS
}

/// Strip a leading YAML frontmatter block (`---\n … \n---`) if present; otherwise return `text` as-is.
pub fn strip_frontmatter(text: &str) -> &str {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text); // tolerate a BOM
    if let Some(rest) = t.strip_prefix("---\n").or_else(|| t.strip_prefix("---\r\n")) {
        // Find the closing delimiter line.
        for (idx, line) in rest.match_indices('\n') {
            let _ = line;
            let after = &rest[idx + 1..];
            if after.starts_with("---\n") || after.starts_with("---\r\n") || after.trim_end() == "---"
            {
                // Return everything after the closing fence line.
                let close = &rest[idx + 1..];
                let body = close
                    .strip_prefix("---\r\n")
                    .or_else(|| close.strip_prefix("---\n"))
                    .unwrap_or("");
                return body;
            }
        }
    }
    t
}

fn is_heading(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('#') && t.trim_start_matches('#').starts_with(' ')
}

/// Split a markdown body into sections: a new section starts at each heading (`#`..`######`). If the
/// document has no headings, fall back to blank-line-separated paragraphs. Pure string work.
fn split_sections(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut saw_heading = false;
    for line in body.lines() {
        if is_heading(line) {
            if !cur.trim().is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            saw_heading = true;
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    if !saw_heading {
        return body
            .split("\n\n")
            .map(|s| s.to_string())
            .filter(|s| !s.trim().is_empty())
            .collect();
    }
    out
}

/// Turn a Markdown document into one item per section (heading-delimited, or paragraph if no headings),
/// stripping any YAML frontmatter first. Used for multi-topic docs like `CLAUDE.md`/`AGENTS.md`.
pub fn split_markdown(
    text: &str,
    source: &str,
    origin_path: &str,
    created_at: i64,
    role: &str,
) -> Vec<MemoryItem> {
    split_sections(strip_frontmatter(text))
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| meaningful(s))
        .map(|text| MemoryItem {
            text,
            source: source.to_string(),
            origin_path: origin_path.to_string(),
            created_at,
            role: role.to_string(),
        })
        .collect()
}

/// Turn a whole file into ONE item (frontmatter stripped) — for already-atomic notes (one topic per
/// file), like Claude Code's per-project memory notes. `None` if the body is effectively empty.
pub fn whole_note(
    text: &str,
    source: &str,
    origin_path: &str,
    created_at: i64,
    role: &str,
) -> Option<MemoryItem> {
    let body = strip_frontmatter(text).trim();
    if !meaningful(body) {
        return None;
    }
    Some(MemoryItem {
        text: body.to_string(),
        source: source.to_string(),
        origin_path: origin_path.to_string(),
        created_at,
        role: role.to_string(),
    })
}

/// File modification time in Unix seconds, or `0` if unavailable.
fn mtime(p: &Path) -> i64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const CLAUDE_SOURCE: &str = "import:claude-code";

/// Read Claude Code's local memory: the global + per-project rule files (`CLAUDE.md`, split by
/// section) and the per-project auto-memory notes (`~/.claude/projects/*/memory/*.md`, one atomic
/// item each). `home` is the user's home dir; `project_roots` are repos to also scan for a `CLAUDE.md`.
pub fn read_claude_code(home: &Path, project_roots: &[PathBuf]) -> Vec<MemoryItem> {
    let mut items = Vec::new();

    // Rule files (hand-written instructions) → split into per-section items.
    let mut rule_files: Vec<PathBuf> = vec![home.join(".claude").join("CLAUDE.md")];
    for root in project_roots {
        rule_files.push(root.join("CLAUDE.md"));
        rule_files.push(root.join("CLAUDE.local.md"));
        if let Ok(rd) = std::fs::read_dir(root.join(".claude").join("rules")) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "md") {
                    rule_files.push(p);
                }
            }
        }
    }
    for f in rule_files {
        if let Ok(text) = std::fs::read_to_string(&f) {
            items.extend(split_markdown(
                &text,
                CLAUDE_SOURCE,
                &f.to_string_lossy(),
                mtime(&f),
                "rule",
            ));
        }
    }

    // Per-project auto-memory notes (already atomic) → one item per file. Skip the MEMORY.md index.
    let projects = home.join(".claude").join("projects");
    if let Ok(rd) = std::fs::read_dir(&projects) {
        for proj in rd.flatten() {
            let memdir = proj.path().join("memory");
            let Ok(md) = std::fs::read_dir(&memdir) else {
                continue;
            };
            for e in md.flatten() {
                let p = e.path();
                if p.extension().is_none_or(|x| x != "md") {
                    continue;
                }
                if p.file_name().is_some_and(|n| n == "MEMORY.md") {
                    continue; // a pointer index, not a memory
                }
                if let Ok(text) = std::fs::read_to_string(&p) {
                    if let Some(it) =
                        whole_note(&text, CLAUDE_SOURCE, &p.to_string_lossy(), mtime(&p), "memory")
                    {
                        items.push(it);
                    }
                }
            }
        }
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_frontmatter_removes_yaml_block_only() {
        let doc = "---\nname: x\ndescription: y\n---\nThe real body.\n";
        assert_eq!(strip_frontmatter(doc).trim(), "The real body.");
        // No frontmatter → unchanged.
        assert_eq!(strip_frontmatter("Just text"), "Just text");
        // A '---' rule mid-document is not frontmatter.
        assert_eq!(strip_frontmatter("Top\n\n---\n\nBottom"), "Top\n\n---\n\nBottom");
    }

    #[test]
    fn split_markdown_splits_by_heading_and_strips_frontmatter() {
        let doc = "---\nname: rules\n---\n# Comms\nBe brief.\n\n## Autonomy\nJust do it.\n";
        let items = split_markdown(doc, "import:claude-code", "/x/CLAUDE.md", 100, "rule");
        assert_eq!(items.len(), 2, "one item per heading section: {items:?}");
        assert!(items[0].text.starts_with("# Comms"));
        assert!(items[0].text.contains("Be brief."));
        assert!(items[1].text.contains("Autonomy"));
        assert!(!items.iter().any(|i| i.text.contains("name: rules")), "frontmatter stripped");
        assert_eq!(items[0].source, "import:claude-code");
        assert_eq!(items[0].role, "rule");
        assert_eq!(items[0].created_at, 100);
    }

    #[test]
    fn split_markdown_with_no_headings_falls_back_to_paragraphs() {
        let items = split_markdown("First para.\n\nSecond para.", "s", "p", 0, "note");
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].text, "Second para.");
    }

    #[test]
    fn whole_note_keeps_one_atomic_item_body_only() {
        let note = "---\nname: dog\n---\nAda's dog is a golden retriever named Max.";
        let it = whole_note(note, "import:claude-code", "/m/dog.md", 50, "memory").unwrap();
        assert_eq!(it.text, "Ada's dog is a golden retriever named Max.");
        assert_eq!(it.role, "memory");
        // An empty body yields nothing.
        assert!(whole_note("---\nname: x\n---\n\n", "s", "p", 0, "memory").is_none());
    }

    #[test]
    fn read_claude_code_collects_rules_split_and_memory_notes_whole() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        // Global rules with two sections.
        std::fs::create_dir_all(h.join(".claude")).unwrap();
        std::fs::write(
            h.join(".claude").join("CLAUDE.md"),
            "# Tone\nFriendly.\n\n# Quality\nTests must pass.\n",
        )
        .unwrap();
        // A per-project memory note + an index that must be skipped.
        let memdir = h.join(".claude").join("projects").join("proj-1").join("memory");
        std::fs::create_dir_all(&memdir).unwrap();
        std::fs::write(
            memdir.join("note.md"),
            "---\nname: launch\n---\nLaunch date is March 14.",
        )
        .unwrap();
        std::fs::write(memdir.join("MEMORY.md"), "- [launch](note.md) — the date").unwrap();

        let items = read_claude_code(h, &[]);
        let texts: Vec<&str> = items.iter().map(|i| i.text.as_str()).collect();
        // Two rule sections, split.
        assert!(items.iter().any(|i| i.role == "rule" && i.text.contains("Friendly.")));
        assert!(items.iter().any(|i| i.role == "rule" && i.text.contains("Tests must pass.")));
        // One memory note, whole, frontmatter stripped.
        assert!(items
            .iter()
            .any(|i| i.role == "memory" && i.text == "Launch date is March 14."));
        // The MEMORY.md index is NOT imported.
        assert!(!texts.iter().any(|t| t.contains("note.md) — the date")), "index skipped");
        assert!(items.iter().all(|i| i.source == "import:claude-code"));
    }
}
