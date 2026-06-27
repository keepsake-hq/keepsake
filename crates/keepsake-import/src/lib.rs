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

/// Coding-agent rule files recognized by exact filename (several are extension-less). Importing one
/// of these tags its items role `rule`. AGENTS.md is the open cross-tool standard.
const RULE_FILENAMES: &[&str] = &[
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".roorules",
    ".rules",
    "AGENTS.md",
    "AGENTS.override.md",
    "CLAUDE.md",
    "GEMINI.md",
    "CONVENTIONS.md",
    "copilot-instructions.md",
    "guidelines.md",
];

fn is_rule_file(name: &str) -> bool {
    RULE_FILENAMES.contains(&name) || name.ends_with(".instructions.md") || name.ends_with(".mdc")
}

fn read_file(path: &Path, source: &str) -> Vec<MemoryItem> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ts = mtime(path);
    let origin = path.to_string_lossy().to_string();
    // Coding-agent rule files (incl. extension-less .cursorrules etc.) → markdown sections, role "rule".
    if is_rule_file(name) {
        return std::fs::read_to_string(path)
            .map(|t| split_markdown(&t, source, &origin, ts, "rule"))
            .unwrap_or_default();
    }
    // A ChromaDB store (mem0 / LangChain / LlamaIndex local backend).
    if name == "chroma.sqlite3" {
        return read_chromadb(path);
    }
    match ext.as_str() {
        "md" | "markdown" | "mdx" | "mdc" => std::fs::read_to_string(path)
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
        "csv" => std::fs::read_to_string(path)
            .map(|t| read_csv(&t, source, &origin))
            .unwrap_or_default(),
        "enex" => std::fs::read_to_string(path)
            .map(|t| read_enex(&t, source, &origin, ts))
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

/// Parse a CSV export (Microsoft Copilot activity, Notion DB, Google Keep, …): pick the most likely
/// free-text column and a timestamp column by header name; one item per row.
fn read_csv(text: &str, source: &str, origin: &str) -> Vec<MemoryItem> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = match rdr.headers() {
        Ok(h) => h.iter().map(|s| s.to_ascii_lowercase()).collect(),
        Err(_) => return Vec::new(),
    };
    let text_col = ["text", "content", "note", "body", "message", "title", "summary"]
        .iter()
        .find_map(|k| headers.iter().position(|h| h == k))
        .unwrap_or(0);
    let time_col = ["created", "created_at", "timestamp", "date", "time", "updated"]
        .iter()
        .find_map(|k| headers.iter().position(|h| h == k));
    let mut out = Vec::new();
    for rec in rdr.records().flatten() {
        let t = rec.get(text_col).unwrap_or("").trim();
        if !meaningful(t) {
            continue;
        }
        let ts = time_col
            .and_then(|c| rec.get(c))
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);
        out.push(MemoryItem {
            text: t.to_string(),
            source: source.to_string(),
            origin_path: origin.to_string(),
            created_at: ts,
            role: "note".to_string(),
        });
    }
    out
}

fn xml_tag_inner(s: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&close)? + start;
    Some(s[start..end].to_string())
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Parse an Evernote `.enex` export: one item per `<note>` (title + the ENML body stripped to text).
/// Per-note timestamps aren't parsed in v1; the file mtime is used as the creation time.
fn read_enex(xml: &str, source: &str, origin: &str, fallback_ts: i64) -> Vec<MemoryItem> {
    let mut out = Vec::new();
    for chunk in xml.split("<note>").skip(1) {
        let note = chunk.split("</note>").next().unwrap_or("");
        let title = xml_tag_inner(note, "title")
            .map(|s| xml_unescape(&s))
            .unwrap_or_default();
        let content = xml_tag_inner(note, "content")
            .unwrap_or_default()
            .replace("<![CDATA[", "")
            .replace("]]>", "");
        let body = strip_tags(&xml_unescape(&content));
        let text = format!("{title}\n{body}").trim().to_string();
        if !meaningful(&text) {
            continue;
        }
        out.push(MemoryItem {
            text,
            source: source.to_string(),
            origin_path: origin.to_string(),
            created_at: fallback_ts,
            role: "note".to_string(),
        });
    }
    out
}

/// Auto-detect coding agents' global rules/memory on this machine (Codex, OpenCode, Continue, Gemini,
/// Aider). Project-level AGENTS.md/.cursorrules are picked up when the user points the folder picker
/// at a repo (see [`read_path`] + [`is_rule_file`]). Tagged `import:coding-agents`.
pub fn read_coding_agents(home: &Path) -> Vec<MemoryItem> {
    let mut out = Vec::new();
    let dirs = [
        home.join(".codex"),
        home.join(".codex").join("memories"),
        home.join(".config").join("opencode"),
        home.join(".continue"),
        home.join(".continue").join("rules"),
        home.join(".gemini"),
        home.join(".aider"),
    ];
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                out.extend(read_file(&p, "import:coding-agents"));
            }
        }
    }
    out
}

/// Auto-detect Obsidian vaults via the app's `obsidian.json` registry (macOS path), and read all
/// notes in each as Markdown. Tagged `import:obsidian`. (Logseq is covered by the folder picker.)
pub fn read_obsidian(home: &Path) -> Vec<MemoryItem> {
    let cfg = home
        .join("Library")
        .join("Application Support")
        .join("obsidian")
        .join("obsidian.json");
    let Ok(text) = std::fs::read_to_string(&cfg) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(vaults) = v.get("vaults").and_then(|x| x.as_object()) {
        for vault in vaults.values() {
            if let Some(path) = vault.get("path").and_then(|p| p.as_str()) {
                let dir = Path::new(path);
                if dir.is_dir() {
                    out.extend(read_path(dir, "import:obsidian"));
                }
            }
        }
    }
    out
}

/// Read a ChromaDB `chroma.sqlite3` store (the persistence backend behind mem0 / LangChain /
/// LlamaIndex local setups): pull the document text out of `embedding_metadata` (key
/// `chroma:document`), ignoring the embedding vectors entirely (Keepsake re-embeds). Read-only.
pub fn read_chromadb(path: &Path) -> Vec<MemoryItem> {
    let Ok(conn) = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) else {
        return Vec::new();
    };
    let origin = path.to_string_lossy().to_string();
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT string_value FROM embedding_metadata WHERE key = 'chroma:document' AND string_value IS NOT NULL",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            for doc in rows.flatten() {
                if meaningful(&doc) {
                    out.push(MemoryItem {
                        text: doc,
                        source: "import:chromadb".to_string(),
                        origin_path: origin.clone(),
                        created_at: 0,
                        role: "note".to_string(),
                    });
                }
            }
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

    #[test]
    fn read_csv_picks_text_and_time_columns() {
        let csv = "created,activity,note\n1700000000,chat,\"Asked about, Berlin trips\"\n1700000100,chat,Second row";
        let items = read_csv(csv, "import:folder", "/a.csv");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].text, "Asked about, Berlin trips", "quoted comma kept");
        assert_eq!(items[0].created_at, 1_700_000_000);
    }

    #[test]
    fn read_enex_parses_notes_to_text() {
        let enex = "<en-export><note><title>Trip plan</title><content><![CDATA[<en-note><div>Arrive Friday</div></en-note>]]></content><created>20200101T120000Z</created></note></en-export>";
        let items = read_enex(enex, "import:folder", "/x.enex", 99);
        assert_eq!(items.len(), 1);
        assert!(items[0].text.contains("Trip plan"));
        assert!(items[0].text.contains("Arrive Friday"), "ENML stripped to text: {:?}", items[0].text);
        assert_eq!(items[0].created_at, 99);
    }

    #[test]
    fn folder_scan_reads_coding_agent_rule_files_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("AGENTS.md"), "# Build\nRun the tests.").unwrap();
        std::fs::write(d.join(".cursorrules"), "Always answer in German.").unwrap();
        let items = read_path(d, "import:folder");
        assert!(items.iter().any(|i| i.role == "rule" && i.text.contains("Run the tests.")), "AGENTS.md");
        assert!(items.iter().any(|i| i.role == "rule" && i.text.contains("Always answer in German.")), ".cursorrules (extension-less)");
    }

    #[test]
    fn read_coding_agents_finds_global_codex_files() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".codex").join("memories")).unwrap();
        std::fs::write(h.join(".codex").join("AGENTS.md"), "# Rules\nBe concise.").unwrap();
        std::fs::write(h.join(".codex").join("memories").join("prefs.md"), "Uses Rust.").unwrap();
        let items = read_coding_agents(h);
        assert!(items.iter().any(|i| i.text.contains("Be concise.")));
        assert!(items.iter().any(|i| i.text.contains("Uses Rust.")));
        assert!(items.iter().all(|i| i.source == "import:coding-agents"));
    }

    #[test]
    fn read_obsidian_follows_the_vault_registry() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        let vault = h.join("MyVault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join("idea.md"), "# Idea\nA sovereign memory vault.").unwrap();
        let cfg = h.join("Library").join("Application Support").join("obsidian");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("obsidian.json"),
            format!(r#"{{"vaults":{{"abc":{{"path":"{}","open":true}}}}}}"#, vault.to_string_lossy()),
        )
        .unwrap();
        let items = read_obsidian(h);
        assert!(items.iter().any(|i| i.text.contains("A sovereign memory vault.")), "{items:?}");
        assert!(items.iter().all(|i| i.source == "import:obsidian"));
    }

    #[test]
    fn read_chromadb_pulls_documents_ignores_vectors() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("chroma.sqlite3");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE embedding_metadata (id INTEGER, key TEXT, string_value TEXT);
             INSERT INTO embedding_metadata VALUES (1,'chroma:document','User prefers dark mode');
             INSERT INTO embedding_metadata VALUES (1,'source','some-app');
             INSERT INTO embedding_metadata VALUES (2,'chroma:document','User lives in Berlin');",
        )
        .unwrap();
        drop(conn);
        let items = read_chromadb(&db);
        assert_eq!(items.len(), 2, "two documents, metadata rows ignored: {items:?}");
        assert!(items.iter().any(|i| i.text == "User prefers dark mode"));
        assert!(items.iter().all(|i| i.source == "import:chromadb"));
    }
}
