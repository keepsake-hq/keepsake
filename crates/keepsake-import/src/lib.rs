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

// ===================== Universal catch-all reader =====================
// The "no source is unsupported" path: eat any folder / file / ZIP / pasted text. Every dedicated
// reader reuses these splitters. Output is the same normalized MemoryItem fed to the vault engine.

/// Split free-form pasted text (e.g. a ChatGPT/Gemini "saved memory" list) into one item per
/// non-empty line/bullet; if it's really a single prose blob, fall back to paragraphs.
pub fn read_pasted_text(text: &str, source: &str) -> Vec<MemoryItem> {
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim_start_matches(['-', '*', '•', ' ', '\t']).trim().to_string())
        .filter(|l| meaningful(l))
        .collect();
    let chunks: Vec<String> = if lines.len() >= 2 {
        lines
    } else {
        text.split("\n\n")
            .map(|s| s.trim().to_string())
            .filter(|s| meaningful(s))
            .collect()
    };
    chunks
        .into_iter()
        .map(|text| MemoryItem {
            text,
            source: source.to_string(),
            origin_path: String::new(),
            created_at: 0,
            role: "memory".to_string(),
        })
        .collect()
}

fn split_paragraphs(text: &str, source: &str, origin: &str, ts: i64) -> Vec<MemoryItem> {
    text.split("\n\n")
        .map(|s| s.trim().to_string())
        .filter(|s| meaningful(s))
        .map(|text| MemoryItem {
            text,
            source: source.to_string(),
            origin_path: origin.to_string(),
            created_at: ts,
            role: "note".to_string(),
        })
        .collect()
}

/// Read ANY local path into items: a directory is walked recursively (hidden dirs skipped); a file is
/// parsed by type — Markdown, text, JSON (generic array OR ChatGPT `conversations.json`), and ZIP
/// archives are unzipped and recursed. `source` tags provenance (default `import:folder`).
pub fn read_path(path: &Path, source: &str) -> Vec<MemoryItem> {
    if path.is_dir() {
        let mut out = Vec::new();
        read_dir_into(path, source, &mut out, 0);
        out
    } else {
        read_file(path, source)
    }
}

fn read_dir_into(dir: &Path, source: &str, out: &mut Vec<MemoryItem>, depth: usize) {
    if depth > 12 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let hidden = p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.'));
        if p.is_dir() {
            if !hidden {
                read_dir_into(&p, source, out, depth + 1);
            }
        } else {
            out.extend(read_file(&p, source));
        }
    }
}

fn read_file(path: &Path, source: &str) -> Vec<MemoryItem> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ts = mtime(path);
    let origin = path.to_string_lossy().to_string();
    match ext.as_str() {
        "md" | "markdown" | "mdx" => std::fs::read_to_string(path)
            .map(|t| split_markdown(&t, source, &origin, ts, "note"))
            .unwrap_or_default(),
        "txt" | "text" => std::fs::read_to_string(path)
            .map(|t| split_paragraphs(&t, source, &origin, ts))
            .unwrap_or_default(),
        "json" => std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .map(|v| read_json_value(&v, source, &origin, ts))
            .unwrap_or_default(),
        "zip" => read_zip(path, source),
        _ => Vec::new(),
    }
}

/// Interpret a parsed JSON value: ChatGPT `conversations.json` (array whose objects carry `mapping` +
/// `current_node`) is walked as conversations; any other array of objects becomes one item per object
/// (auto-picking a text + time field); a lone object becomes one item.
pub fn read_json_value(v: &serde_json::Value, source: &str, origin: &str, fallback_ts: i64) -> Vec<MemoryItem> {
    if let Some(arr) = v.as_array() {
        if arr
            .iter()
            .any(|o| o.get("mapping").is_some() && o.get("current_node").is_some())
        {
            return read_chatgpt(arr, source);
        }
        return arr
            .iter()
            .filter_map(|o| json_object_item(o, source, origin, fallback_ts))
            .collect();
    }
    json_object_item(v, source, origin, fallback_ts)
        .into_iter()
        .collect()
}

fn json_object_item(o: &serde_json::Value, source: &str, origin: &str, fallback_ts: i64) -> Option<MemoryItem> {
    let obj = o.as_object()?;
    let text = ["text", "content", "body", "note", "message", "summary", "value"]
        .iter()
        .find_map(|k| obj.get(*k).and_then(|x| x.as_str()).map(|s| s.to_string()))
        .or_else(|| {
            obj.values()
                .filter_map(|x| x.as_str())
                .max_by_key(|s| s.len())
                .map(|s| s.to_string())
        })?;
    if !meaningful(&text) {
        return None;
    }
    let ts = [
        "create_time",
        "created_at",
        "created",
        "timestamp",
        "updated_at",
        "updated",
        "time",
        "date",
    ]
    .iter()
    .find_map(|k| obj.get(*k).and_then(json_time))
    .unwrap_or(fallback_ts);
    Some(MemoryItem {
        text: text.trim().to_string(),
        source: source.to_string(),
        origin_path: origin.to_string(),
        created_at: ts,
        role: "note".to_string(),
    })
}

/// Best-effort numeric timestamp → Unix seconds, normalizing seconds / millis / micros. Strings (RFC
/// 3339) are left to a later version (`None`), so the caller's fallback time is used.
fn json_time(v: &serde_json::Value) -> Option<i64> {
    let f = v.as_f64()?;
    let n = f as i64;
    Some(if f > 1e14 {
        n / 1_000_000
    } else if f > 1e11 {
        n / 1000
    } else {
        n
    })
}

/// Walk ChatGPT export conversations: for each, follow `current_node` up the `mapping` tree via
/// `parent` links, reverse to chronological order, keep user/assistant turns (drop system/tool), and
/// emit one item per conversation (title + turns).
fn read_chatgpt(convs: &[serde_json::Value], source: &str) -> Vec<MemoryItem> {
    let mut out = Vec::new();
    for conv in convs {
        let title = conv.get("title").and_then(|t| t.as_str()).unwrap_or("Conversation");
        let created = conv.get("create_time").and_then(json_time).unwrap_or(0);
        let mut turns: Vec<String> = Vec::new();
        if let Some(map) = conv.get("mapping").and_then(|m| m.as_object()) {
            let mut node = conv
                .get("current_node")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
            let mut seen = std::collections::HashSet::new();
            while let Some(id) = node {
                if !seen.insert(id.clone()) {
                    break;
                }
                let Some(n) = map.get(&id) else { break };
                if let Some(msg) = n.get("message").filter(|m| !m.is_null()) {
                    let role = msg
                        .get("author")
                        .and_then(|a| a.get("role"))
                        .and_then(|r| r.as_str())
                        .unwrap_or("");
                    if role == "user" || role == "assistant" {
                        if let Some(parts) = msg
                            .get("content")
                            .and_then(|c| c.get("parts"))
                            .and_then(|p| p.as_array())
                        {
                            let text: String = parts
                                .iter()
                                .filter_map(|p| p.as_str())
                                .collect::<Vec<_>>()
                                .join("\n");
                            if meaningful(&text) {
                                turns.push(format!("{role}: {}", text.trim()));
                            }
                        }
                    }
                }
                node = n.get("parent").and_then(|p| p.as_str()).map(|s| s.to_string());
            }
        }
        turns.reverse();
        if !turns.is_empty() {
            out.push(MemoryItem {
                text: format!("{title}\n\n{}", turns.join("\n\n")).trim().to_string(),
                source: source.to_string(),
                origin_path: String::new(),
                created_at: created,
                role: "chat".to_string(),
            });
        }
    }
    out
}

/// Transparently unzip an archive and recurse over its Markdown / text / JSON entries.
fn read_zip(path: &Path, source: &str) -> Vec<MemoryItem> {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        let ext = Path::new(&name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(ext.as_str(), "md" | "markdown" | "mdx" | "txt" | "text" | "json") {
            continue;
        }
        let mut buf = String::new();
        if entry.read_to_string(&mut buf).is_err() {
            continue;
        }
        let origin = format!("{}!{name}", path.to_string_lossy());
        match ext.as_str() {
            "md" | "markdown" | "mdx" => out.extend(split_markdown(&buf, source, &origin, 0, "note")),
            "txt" | "text" => out.extend(split_paragraphs(&buf, source, &origin, 0)),
            "json" => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&buf) {
                    out.extend(read_json_value(&v, source, &origin, 0));
                }
            }
            _ => {}
        }
    }
    out
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

    #[test]
    fn read_pasted_text_splits_lines_and_strips_bullets() {
        let items = read_pasted_text("- Lives in Berlin\n* Prefers German\n  • Has a dog named Max", "import:paste");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].text, "Lives in Berlin");
        assert_eq!(items[2].text, "Has a dog named Max");
        assert!(items.iter().all(|i| i.role == "memory" && i.source == "import:paste"));
    }

    #[test]
    fn read_json_value_generic_array_picks_text_and_time() {
        let v: serde_json::Value = serde_json::from_str(
            r#"[{"content":"Fact one","created_at":1700000000},{"note":"Fact two"}]"#,
        )
        .unwrap();
        let items = read_json_value(&v, "import:folder", "/x.json", 42);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].text, "Fact one");
        assert_eq!(items[0].created_at, 1_700_000_000);
        assert_eq!(items[1].text, "Fact two");
        assert_eq!(items[1].created_at, 42, "falls back to the provided time");
    }

    #[test]
    fn read_chatgpt_conversations_reconstructs_order_and_drops_system() {
        // current_node = c; c.parent = b; b.parent = a (system, dropped); chronological = user, assistant.
        let v: serde_json::Value = serde_json::from_str(
            r#"[{"title":"Trip","create_time":1700000000.0,"current_node":"c","mapping":{
              "a":{"message":{"author":{"role":"system"},"content":{"parts":["sys"]}},"parent":null},
              "b":{"message":{"author":{"role":"user"},"content":{"parts":["plan my Berlin trip"]}},"parent":"a"},
              "c":{"message":{"author":{"role":"assistant"},"content":{"parts":["arrive Friday"]}},"parent":"b"}
            }}]"#,
        )
        .unwrap();
        let items = read_json_value(&v, "import:chatgpt", "", 0);
        assert_eq!(items.len(), 1);
        let t = &items[0].text;
        assert!(t.contains("Trip"));
        let u = t.find("plan my Berlin trip").unwrap();
        let a = t.find("arrive Friday").unwrap();
        assert!(u < a, "user turn precedes assistant turn");
        assert!(!t.contains("sys"), "system turn dropped");
        assert_eq!(items[0].created_at, 1_700_000_000);
        assert_eq!(items[0].role, "chat");
    }

    #[test]
    fn read_path_walks_a_folder_of_mixed_files() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("notes.md"), "# A\nfirst\n\n# B\nsecond").unwrap();
        std::fs::write(d.join("plain.txt"), "para one\n\npara two").unwrap();
        std::fs::write(d.join("data.json"), r#"[{"text":"json fact"}]"#).unwrap();
        std::fs::write(d.join("ignore.png"), [0u8, 1, 2]).unwrap();
        let items = read_path(d, "import:folder");
        let texts: Vec<&str> = items.iter().map(|i| i.text.as_str()).collect();
        assert!(items.iter().any(|i| i.text.contains("first")), "md split: {texts:?}");
        assert!(items.iter().any(|i| i.text == "para two"), "txt split");
        assert!(items.iter().any(|i| i.text == "json fact"), "json item");
        assert!(items.len() >= 5, "2 md + 2 txt + 1 json: {texts:?}");
    }

    #[test]
    fn read_zip_unpacks_and_recurses() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zw = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zw.start_file("memory.md", opts).unwrap();
        zw.write_all(b"# Hello\nfrom inside a zip").unwrap();
        zw.finish().unwrap();

        let items = read_path(&zip_path, "import:folder");
        assert!(items.iter().any(|i| i.text.contains("from inside a zip")), "zip recursed: {items:?}");
    }
}
