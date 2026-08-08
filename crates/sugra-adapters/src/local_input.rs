//! Explicit bounded local text-file input.

use async_trait::async_trait;
use sugra_core::{LocalInputPort, LocalInputRequest, LocalInputResponse, PortError, PortErrorKind};
use tokio::io::AsyncReadExt;

/// Operating-system local input boundary.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLocalInput;

#[async_trait]
impl LocalInputPort for SystemLocalInput {
    async fn read_lines(
        &self,
        request: LocalInputRequest,
    ) -> Result<LocalInputResponse, PortError> {
        if !request.path.is_absolute() {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                "local input path must be absolute",
            ));
        }
        let metadata = tokio::fs::symlink_metadata(&request.path)
            .await
            .map_err(|_| unavailable())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                "local input must be a regular file",
            ));
        }
        if metadata.len() > request.budget.max_response_bytes as u64 {
            return Err(too_large("local input exceeds the byte budget"));
        }
        let file = tokio::fs::File::open(&request.path)
            .await
            .map_err(|_| unavailable())?;
        if !file.metadata().await.map_err(|_| unavailable())?.is_file() {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                "local input must be a regular file",
            ));
        }
        let limit = u64::try_from(request.budget.max_response_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Vec::new();
        file.take(limit)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| unavailable())?;
        if bytes.len() > request.budget.max_response_bytes {
            return Err(too_large("local input exceeds the byte budget"));
        }
        let text = String::from_utf8(bytes).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "local input must contain UTF-8 text",
            )
        })?;
        let lines: Vec<_> = text.lines().map(str::to_owned).collect();
        if lines.len() > request.budget.max_requests {
            return Err(too_large("local input exceeds the line budget"));
        }
        Ok(LocalInputResponse { lines })
    }
}

fn unavailable() -> PortError {
    PortError::new(PortErrorKind::Unavailable, "local input is unavailable")
}

fn too_large(message: &'static str) -> PortError {
    PortError::new(PortErrorKind::TooLarge, message)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sugra_core::{LocalInputPort, LocalInputRequest};
    use sugra_domain::Budget;

    use super::*;

    fn fixture_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sugra-local-input-{}-{label}.txt",
            std::process::id()
        ))
    }

    fn require_error<T>(
        result: Result<T, PortError>,
        message: &'static str,
    ) -> Result<PortError, Box<dyn std::error::Error>> {
        match result {
            Ok(_) => Err(message.into()),
            Err(error) => Ok(error),
        }
    }

    #[tokio::test]
    async fn reads_utf8_lines_from_an_explicit_regular_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = fixture_path("success");
        tokio::fs::write(&path, b"/admin\n/api\n").await?;
        let response = SystemLocalInput
            .read_lines(LocalInputRequest {
                path: path.clone(),
                budget: Budget {
                    max_requests: 3,
                    max_response_bytes: 64,
                    ..Budget::DEFAULT
                },
            })
            .await;
        tokio::fs::remove_file(path).await?;

        assert_eq!(response?.lines, vec!["/admin", "/api"]);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_input_larger_than_the_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
        let path = fixture_path("too-large");
        tokio::fs::write(&path, b"123456789").await?;
        let result = SystemLocalInput
            .read_lines(LocalInputRequest {
                path: path.clone(),
                budget: Budget {
                    max_response_bytes: 4,
                    ..Budget::DEFAULT
                },
            })
            .await;
        tokio::fs::remove_file(&path).await?;
        let error = require_error(result, "oversized input must fail")?;

        assert_eq!(error.kind, PortErrorKind::TooLarge);
        assert!(!error.message.contains(path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_more_lines_than_the_request_budget() -> Result<(), Box<dyn std::error::Error>>
    {
        let path = fixture_path("too-many-lines");
        tokio::fs::write(&path, b"one\ntwo\nthree\n").await?;
        let result = SystemLocalInput
            .read_lines(LocalInputRequest {
                path: path.clone(),
                budget: Budget {
                    max_requests: 2,
                    max_response_bytes: 64,
                    ..Budget::DEFAULT
                },
            })
            .await;
        tokio::fs::remove_file(path).await?;
        let error = require_error(result, "excess lines must fail")?;

        assert_eq!(error.kind, PortErrorKind::TooLarge);
        assert_eq!(error.message, "local input exceeds the line budget");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_relative_paths_and_invalid_utf8_without_echoing_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let relative = PathBuf::from("operator-secret.txt");
        let relative_result = SystemLocalInput
            .read_lines(LocalInputRequest {
                path: relative.clone(),
                budget: Budget::DEFAULT,
            })
            .await;
        let relative_error = require_error(relative_result, "relative input must fail")?;
        assert_eq!(relative_error.kind, PortErrorKind::InvalidResponse);
        assert!(!relative_error.message.contains("operator-secret"));

        let path = fixture_path("invalid-utf8");
        tokio::fs::write(&path, [0xff, 0xfe]).await?;
        let utf8_result = SystemLocalInput
            .read_lines(LocalInputRequest {
                path: path.clone(),
                budget: Budget::DEFAULT,
            })
            .await;
        tokio::fs::remove_file(path).await?;
        let utf8_error = require_error(utf8_result, "invalid UTF-8 must fail")?;
        assert_eq!(utf8_error.kind, PortErrorKind::InvalidResponse);
        assert_eq!(utf8_error.message, "local input must contain UTF-8 text");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_directories_as_non_regular_input() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir();
        let result = SystemLocalInput
            .read_lines(LocalInputRequest {
                path,
                budget: Budget::DEFAULT,
            })
            .await;
        let error = require_error(result, "directory input must fail")?;

        assert_eq!(error.kind, PortErrorKind::InvalidResponse);
        assert_eq!(error.message, "local input must be a regular file");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symbolic_links_without_exposing_the_target()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let target = fixture_path("symlink-target");
        let link = fixture_path("symlink-link");
        tokio::fs::write(&target, b"sensitive-entry\n").await?;
        symlink(&target, &link)?;
        let result = SystemLocalInput
            .read_lines(LocalInputRequest {
                path: link.clone(),
                budget: Budget::DEFAULT,
            })
            .await;
        tokio::fs::remove_file(link).await?;
        tokio::fs::remove_file(&target).await?;
        let error = require_error(result, "symbolic link input must fail")?;

        assert_eq!(error.kind, PortErrorKind::InvalidResponse);
        assert_eq!(error.message, "local input must be a regular file");
        assert!(!error.message.contains(target.to_string_lossy().as_ref()));
        Ok(())
    }
}
