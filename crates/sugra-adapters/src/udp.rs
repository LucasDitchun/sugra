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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use sugra_domain::{Budget, ScopeGrant};
    use time::OffsetDateTime;

    use super::*;

    #[tokio::test]
    async fn datagram_exchange_is_scoped_and_response_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = server.local_addr()?;
        let task = tokio::spawn(async move {
            let mut request = [0_u8; 32];
            let (received, peer) = server.recv_from(&mut request).await?;
            assert_eq!(&request[..received], b"probe");
            server.send_to(b"response", peer).await?;
            Ok::<_, std::io::Error>(())
        });
        let target = Target::Ip(address.ip());
        let response = TokioUdp
            .execute(UdpRequest {
                host: address.ip().to_string(),
                port: address.port(),
                payload: b"probe".to_vec(),
                budget: Budget {
                    timeout_ms: 1_000,
                    max_response_bytes: 4,
                    ..Budget::default()
                },
                scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
            })
            .await?;
        assert_eq!(response.bytes, b"resp");
        task.await??;
        Ok(())
    }
}
