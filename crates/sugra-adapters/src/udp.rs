//! Bounded Tokio UDP boundary.

use std::time::Instant;

use async_trait::async_trait;
use sugra_core::{PortError, PortErrorKind, UdpPort, UdpRequest, UdpResponse};
use sugra_domain::{Target, TargetKind};
use tokio::net::UdpSocket;

/// Tokio-based UDP client.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioUdp;

#[async_trait]
impl UdpPort for TokioUdp {
    async fn execute(&self, request: UdpRequest) -> Result<UdpResponse, PortError> {
        let target = request
            .host
            .parse()
            .map(Target::Ip)
            .or_else(|_| Target::parse(TargetKind::Domain, &request.host))
            .map_err(|_| PortError::new(PortErrorKind::InvalidResponse, "UDP host is invalid"))?;
        if !request.scope.allows(&target) {
            return Err(PortError::new(
                PortErrorKind::OutOfScope,
                "UDP host is outside the declared scope",
            ));
        }
        let started = Instant::now();
        let bind = if request.host.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|_| PortError::new(PortErrorKind::Transport, "UDP socket creation failed"))?;
        let endpoint = format!("{}:{}", request.host, request.port);
        tokio::time::timeout(request.budget.timeout(), socket.connect(&endpoint))
            .await
            .map_err(|_| PortError::new(PortErrorKind::Timeout, "UDP connect timed out"))?
            .map_err(|_| PortError::new(PortErrorKind::Transport, "UDP connect failed"))?;
        tokio::time::timeout(request.budget.timeout(), socket.send(&request.payload))
            .await
            .map_err(|_| PortError::new(PortErrorKind::Timeout, "UDP send timed out"))?
            .map_err(|_| PortError::new(PortErrorKind::Transport, "UDP send failed"))?;
        let mut bytes = vec![0_u8; request.budget.max_response_bytes.min(65_507)];
        let received = tokio::time::timeout(request.budget.timeout(), socket.recv(&mut bytes))
            .await
            .map_err(|_| PortError::new(PortErrorKind::Timeout, "UDP response timed out"))?
            .map_err(|_| PortError::new(PortErrorKind::Transport, "UDP receive failed"))?;
        bytes.truncate(received);
        Ok(UdpResponse {
            endpoint,
            bytes,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}
