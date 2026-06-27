//! Dev scan: print what the Claude Code reader finds in $HOME (read-only; no vault writes).
//! Run with: `cargo run -p keepsake-import --example scan_claude`
fn main() {
    let home = std::path::PathBuf::from(std::env::var("HOME").expect("HOME"));
    let items = keepsake_import::read_claude_code(&home, &[]);
    let rules = items.iter().filter(|i| i.role == "rule").count();
    let mem = items.iter().filter(|i| i.role == "memory").count();
    println!("claude-code reader: {} items ({rules} rule, {mem} memory)", items.len());
    for it in items.iter().take(3) {
        let preview: String = it.text.chars().take(70).collect();
        println!("  [{}] {}", it.role, preview.replace('\n', " "));
    }
}
