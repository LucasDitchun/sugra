//! Atomic per-run JSON persistence.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sugra_domain::RunReport;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

/// Persisted artifact metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Path relative to the configured store root.
    pub path: PathBuf,
    /// IANA media type.
    pub media_type: String,
    /// Lowercase SHA-256 digest.
    pub sha256: String,
    /// Artifact size in bytes.
    pub bytes: u64,
}

/// Run-store failure.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Configured root is not a safe relative or absolute normal path.
    #[error("unsafe store path")]
    UnsafePath,
    /// Run directory already exists and will not be overwritten.
    #[error("run directory already exists: {0}")]
    AlreadyExists(PathBuf),
    /// Serialization failed.
    #[error("could not serialize report: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Filesystem operation failed.
    #[error("store I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Filesystem store that creates one immutable directory per run.
#[derive(Debug, Clone)]
pub struct RunStore {
    root: PathBuf,
}

impl RunStore {
    /// Constructs a store after rejecting traversal components.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::UnsafePath` for an empty path or a path containing
    /// parent traversal components.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        if root.as_os_str().is_empty()
            || root
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(StoreError::UnsafePath);
        }
        Ok(Self { root })
    }

    /// Persists a canonical JSON report with create-new and atomic rename semantics.
    ///
    /// # Errors
    ///
    /// Returns a store error when the run already exists, serialization fails,
    /// or an atomic filesystem operation cannot be completed.
    pub async fn persist(&self, report: &RunReport) -> Result<Artifact, StoreError> {
        tokio::fs::create_dir_all(&self.root).await?;
        let run_name = report.run_id.to_string();
        let run_dir = self.root.join(&run_name);
        match tokio::fs::create_dir(&run_dir).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::AlreadyExists(run_dir));
            }
            Err(error) => return Err(StoreError::Io(error)),
        }
        let bytes = serde_json::to_vec_pretty(report)?;
        let temporary = run_dir.join("report.json.tmp");
        let final_path = run_dir.join("report.json");
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await?;
        file.write_all(&bytes).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, &final_path).await?;
        let digest = hex::encode(Sha256::digest(&bytes));
        Ok(Artifact {
            path: Path::new(&run_name).join("report.json"),
            media_type: "application/json".into(),
            sha256: digest,
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use sugra_domain::{RunId, RunReport};
    use time::OffsetDateTime;

    use super::*;

    fn report() -> RunReport {
        RunReport {
            schema_version: 1,
            run_id: RunId::new(),
            app_version: "test".into(),
            started_at: OffsetDateTime::UNIX_EPOCH,
            finished_at: OffsetDateTime::UNIX_EPOCH,
            executions: Vec::new(),
        }
    }

    #[test]
    fn empty_and_parent_traversal_roots_are_rejected() {
        assert!(matches!(RunStore::new(""), Err(StoreError::UnsafePath)));
        assert!(matches!(
            RunStore::new("../outside"),
            Err(StoreError::UnsafePath)
        ));
        assert!(matches!(
            RunStore::new("runs/../outside"),
            Err(StoreError::UnsafePath)
        ));
        assert!(RunStore::new("runs/safe").is_ok());
    }

    #[tokio::test]
    async fn report_is_written_once() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = RunStore::new(root.path())?;
        let report = report();
        let artifact = store.persist(&report).await?;
        let path = root.path().join(&artifact.path);
        let bytes = tokio::fs::read(&path).await?;
        assert!(path.is_file());
        assert_eq!(artifact.media_type, "application/json");
        assert_eq!(artifact.bytes, u64::try_from(bytes.len())?);
        assert_eq!(artifact.sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(artifact.path.file_name(), Some("report.json".as_ref()));
        assert!(!path.with_file_name("report.json.tmp").exists());
        assert!(matches!(
            store.persist(&report).await,
            Err(StoreError::AlreadyExists(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn filesystem_failures_are_typed_without_overwriting_the_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let file_root = root.path().join("not-a-directory");
        tokio::fs::write(&file_root, b"preserve").await?;
        let store = RunStore::new(&file_root)?;

        assert!(matches!(
            store.persist(&report()).await,
            Err(StoreError::Io(_))
        ));
        assert_eq!(tokio::fs::read(file_root).await?, b"preserve");
        Ok(())
    }
}
