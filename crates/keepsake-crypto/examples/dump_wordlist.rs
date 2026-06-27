//! Dump the BIP-39 English wordlist (2048 words) so the desktop UI can validate per-word input.
//! Run: `cargo run -p keepsake-crypto --example dump_wordlist`
fn main() {
    for w in bip39::Language::English.word_list() {
        println!("{w}");
    }
}
