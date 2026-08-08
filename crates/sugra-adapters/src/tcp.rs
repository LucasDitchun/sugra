//! Bounded Tokio TCP boundary.

use std::time::Instant;

use async_trait::async_trait;
use sugra_core::{PortError, PortErrorKind, TcpPort, TcpRequest, TcpResponse};
use sugra_domain::{Target, TargetKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Tokio-based TCP connector.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioTcp;

#[async_trait]
impl TcpPort for TokioTcp {
    async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError> {
        let target = request
            .host
            .parse()
            .map(Target::Ip)
            .or_else(|_| Target::parse(TargetKind::Domain, &request.host))
            .map_err(|_| PortError::new(PortErrorKind::InvalidResponse, "TCP host is invalid"))?;
        if !request.scope.allows(&target) {
            return Err(PortError::new(
                PortErrorKind::OutOfScope,
                "TCP host is outside the declared scope",
            ));
        }
        let started = Instant::now();
        let mut stream = tokio::time::timeout(
            request.budget.timeout(),
            TcpStream::connect((request.host.as_str(), request.port)),
        )
        .await
        .map_err(|_| PortError::new(PortErrorKind::Timeout, "TCP connect timed out"))?
        .map_err(|_| PortError::new(PortErrorKind::Transport, "TCP connect failed"))?;
        if !request.payload.is_empty() {
            tokio::time::timeout(request.budget.timeout(), stream.write_all(&request.payload))
                .await
                .map_err(|_| PortError::new(PortErrorKind::Timeout, "TCP write timed out"))?
                .map_err(|_| PortError::new(PortErrorKind::Transport, "TCP write failed"))?;
        }
        let mut bytes = Vec::new();
        let limit = u64::try_from(request.budget.max_response_bytes).unwrap_or(u64::MAX);
        tokio::time::timeout(
            request.budget.timeout(),
            stream.take(limit).read_to_end(&mut bytes),
        )
        .await
        .map_err(|_| PortError::new(PortErrorKind::Timeout, "TCP read timed out"))?
        .map_err(|_| PortError::new(PortErrorKind::Transport, "TCP read failed"))?;
        Ok(TcpResponse {
            endpoint: format!("{}:{}", request.host, request.port),
            bytes,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}
