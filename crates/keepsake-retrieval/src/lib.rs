//! `keepsake-retrieval` — local semantic retrieval primitives.
//!
//! - [`VectorIndex`] — an in-RAM exact-cosine index materialized while the vault is
//!   unlocked (MVP; `usearch` is the scale-up path for large vaults).
//! - [`Embedder`] — abstraction over a *local* embedding model (real model behind the
//!   optional `fastembed` feature; [`MockEmbedder`] is deterministic for tests).
//! - [`seal_vector`] / [`open_vector`] — per-cell **encrypted** embeddings, so a
//!   forgotten cell's embedding is cryptographically dead just like its content (§5/§4a).

use keepsake_core::CellId;
use keepsake_crypto::{CryptoError, Kek, SealedCell, WrappedDek};

/// In-RAM exact-cosine vector index. Vectors are stored unit-normalized, so a search
/// score is the cosine similarity in `[-1.0, 1.0]`.
#[derive(Default)]
pub struct VectorIndex {
    entries: Vec<(CellId, Vec<f32>)>,
}

impl VectorIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add (or replace) the embedding for `id`.
    pub fn add(&mut self, id: CellId, vector: &[f32]) {
        self.entries.retain(|(eid, _)| eid != &id);
        self.entries.push((id, normalize(vector)));
    }

    /// Remove the embedding for `id`. Returns `true` if something was removed.
    pub fn remove(&mut self, id: &CellId) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(eid, _)| eid != id);
        self.entries.len() != before
    }

    /// Return the top-`k` ids by cosine similarity to `query`, highest first.
    pub fn search(&self, query: &[f32], k: usize) -> Vec<(CellId, f32)> {
        let q = normalize(query);
        let mut scored: Vec<(CellId, f32)> = self
            .entries
            .iter()
            .map(|(id, v)| (id.clone(), dot(&q, v)))
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored.truncate(k);
        scored
    }
}

/// A local embedding model failure (model error, poisoned lock, or empty output).
#[derive(Debug)]
pub struct EmbedError(pub String);

impl std::fmt::Display for EmbedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "embedding failed: {}", self.0)
    }
}

impl std::error::Error for EmbedError {}

/// A local embedding model: text in, vector out. Implementations must keep all
/// computation on-device (no network at inference time). Returns [`EmbedError`] instead of
/// panicking when the model fails.
pub trait Embedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError>;
    fn dimensions(&self) -> usize;
}

/// A deterministic, dependency-free embedder for tests and offline use. It is a byte
/// histogram — not semantically meaningful, but stable and content-sensitive.
pub struct MockEmbedder {
    dim: usize,
}

impl MockEmbedder {
    pub fn new(dim: usize) -> Self {
        MockEmbedder { dim }
    }
}

impl Embedder for MockEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let mut v = vec![0.0f32; self.dim];
        for byte in text.bytes() {
            v[byte as usize % self.dim] += 1.0;
        }
        Ok(v)
    }

    fn dimensions(&self) -> usize {
        self.dim
    }
}

/// Encrypt an embedding vector under `kek` (random per-vector DEK + envelope), so it
/// can be persisted at rest and **erased** by destroying its wrapped key.
pub fn seal_vector(kek: &Kek, vector: &[f32]) -> (SealedCell, WrappedDek) {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for f in vector {
        bytes.extend_from_slice(&f.to_le_bytes());
    }
    kek.seal(&bytes)
}

/// Decrypt an embedding vector sealed with [`seal_vector`].
pub fn open_vector(
    kek: &Kek,
    cell: &SealedCell,
    wrapped: &WrappedDek,
) -> Result<Vec<f32>, CryptoError> {
    let bytes = kek.open(cell, wrapped)?;
    if bytes.len() % 4 != 0 {
        return Err(CryptoError::Aead);
    }
    let out = bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    Ok(out)
}

fn normalize(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm == 0.0 {
        return v.to_vec();
    }
    v.iter().map(|x| x / norm).collect()
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

pub use fast::FastEmbedder;

mod fast {
    use super::{EmbedError, Embedder};
    use fastembed::{
        EmbeddingModel, InitOptionsUserDefined, Pooling, TextEmbedding, TextInitOptions,
        TokenizerFiles, UserDefinedEmbeddingModel,
    };
    use std::path::{Path, PathBuf};

    /// A local embedding model backed by `fastembed` (ONNX). Model files are
    /// downloaded on first construction and then run fully on-device.
    pub struct FastEmbedder {
        // fastembed's `embed` takes `&mut self`; a Mutex keeps the `Embedder` trait
        // immutable (`&self`) and the type `Send + Sync` for a daemon.
        model: std::sync::Mutex<TextEmbedding>,
        dim: usize,
    }

    impl FastEmbedder {
        /// BGE-small-en-v1.5 (384-dim) — lightweight default.
        pub fn bge_small() -> anyhow::Result<Self> {
            let model =
                TextEmbedding::try_new(TextInitOptions::new(EmbeddingModel::BGESmallENV15))?;
            Ok(Self {
                model: std::sync::Mutex::new(model),
                dim: 384,
            })
        }

        /// Nomic-embed-text-v1.5 (768-dim) — higher quality.
        pub fn nomic() -> anyhow::Result<Self> {
            let model =
                TextEmbedding::try_new(TextInitOptions::new(EmbeddingModel::NomicEmbedTextV15))?;
            Ok(Self {
                model: std::sync::Mutex::new(model),
                dim: 768,
            })
        }

        /// Nomic-embed-text-v1.5 cached at a stable path (e.g. `~/.keepsake/models`).
        /// Downloads on first run, then runs fully offline from the cache.
        pub fn nomic_cached(cache_dir: PathBuf) -> anyhow::Result<Self> {
            let model = TextEmbedding::try_new(
                TextInitOptions::new(EmbeddingModel::NomicEmbedTextV15).with_cache_dir(cache_dir),
            )?;
            Ok(Self {
                model: std::sync::Mutex::new(model),
                dim: 768,
            })
        }

        /// Fully offline Nomic from local model files in `dir` — **no network at all**.
        /// Expects `model.onnx` (or `onnx/model.onnx`) plus `tokenizer.json`,
        /// `config.json`, `special_tokens_map.json`, `tokenizer_config.json`. Used when
        /// the model is bundled inside the app so a fresh install never needs internet.
        pub fn nomic_from_dir(dir: &Path) -> anyhow::Result<Self> {
            let onnx_path = {
                let nested = dir.join("onnx").join("model.onnx");
                if nested.exists() {
                    nested
                } else {
                    dir.join("model.onnx")
                }
            };
            let onnx_file = std::fs::read(&onnx_path)
                .map_err(|e| anyhow::anyhow!("read {}: {e}", onnx_path.display()))?;
            let tokenizer_files = TokenizerFiles {
                tokenizer_file: std::fs::read(dir.join("tokenizer.json"))?,
                config_file: std::fs::read(dir.join("config.json"))?,
                special_tokens_map_file: std::fs::read(dir.join("special_tokens_map.json"))?,
                tokenizer_config_file: std::fs::read(dir.join("tokenizer_config.json"))?,
            };
            let user_model = UserDefinedEmbeddingModel::new(onnx_file, tokenizer_files)
                .with_pooling(Pooling::Mean);
            let model = TextEmbedding::try_new_from_user_defined(
                user_model,
                InitOptionsUserDefined::default(),
            )?;
            Ok(Self {
                model: std::sync::Mutex::new(model),
                dim: 768,
            })
        }
    }

    impl Embedder for FastEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut model = self
                .model
                .lock()
                .map_err(|_| EmbedError("embedder mutex poisoned".into()))?;
            model
                .embed(vec![text], None)
                .map_err(|e| EmbedError(e.to_string()))?
                .into_iter()
                .next()
                .ok_or_else(|| EmbedError("model returned no embedding".into()))
        }

        fn dimensions(&self) -> usize {
            self.dim
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::RootKeys;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_kek() -> Kek {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        Kek::from_root(&roots.encryption_root)
    }

    #[test]
    fn search_ranks_by_cosine_similarity() {
        let mut idx = VectorIndex::new();
        let a = CellId::from_bytes([1u8; 32]);
        let b = CellId::from_bytes([2u8; 32]);
        let c = CellId::from_bytes([3u8; 32]);
        idx.add(a.clone(), &[1.0, 0.0]);
        idx.add(b.clone(), &[0.0, 1.0]);
        idx.add(c.clone(), &[0.9, 0.1]);

        let res = idx.search(&[1.0, 0.0], 3);
        assert_eq!(res[0].0, a, "exact match ranks first");
        assert_eq!(res[1].0, c, "near match second");
        assert_eq!(res[2].0, b, "orthogonal last");
    }

    #[test]
    fn remove_drops_entry_from_index() {
        let mut idx = VectorIndex::new();
        let a = CellId::from_bytes([7u8; 32]);
        idx.add(a.clone(), &[1.0, 0.0]);
        assert_eq!(idx.len(), 1);
        assert!(idx.remove(&a));
        assert!(idx.is_empty());
        assert!(idx.search(&[1.0, 0.0], 5).is_empty());
    }

    #[test]
    fn search_respects_k() {
        let mut idx = VectorIndex::new();
        for i in 0..5u8 {
            idx.add(CellId::from_bytes([i; 32]), &[i as f32, 1.0]);
        }
        assert_eq!(idx.search(&[1.0, 1.0], 2).len(), 2);
    }

    #[test]
    fn mock_embedder_is_deterministic_and_content_sensitive() {
        let e = MockEmbedder::new(64);
        assert_eq!(e.dimensions(), 64);
        assert_eq!(
            e.embed("hello world").unwrap(),
            e.embed("hello world").unwrap()
        );
        assert_ne!(e.embed("cat").unwrap(), e.embed("dog").unwrap());
        assert_eq!(e.embed("anything").unwrap().len(), 64);
    }

    #[test]
    fn seal_open_vector_roundtrips() {
        let kek = test_kek();
        let v = vec![0.1f32, -2.5, 3.5, 42.0];
        let (cell, wrapped) = seal_vector(&kek, &v);
        assert_eq!(open_vector(&kek, &cell, &wrapped).unwrap(), v);
    }

    #[test]
    #[ignore = "downloads a ~100MB ONNX model on first run"]
    fn fastembed_bge_small_embeds_with_expected_dim() {
        let e = FastEmbedder::bge_small().unwrap();
        assert_eq!(e.dimensions(), 384);
        assert_eq!(e.embed("hello world").unwrap().len(), 384);
    }
}
