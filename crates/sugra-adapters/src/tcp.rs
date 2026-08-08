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
        let mut bytes = vec![0; request.budget.max_response_bytes];
        if request.read_response && !bytes.is_empty() {
            let received = tokio::time::timeout(request.budget.timeout(), stream.read(&mut bytes))
                .await
                .map_err(|_| PortError::new(PortErrorKind::Timeout, "TCP read timed out"))?
                .map_err(|_| PortError::new(PortErrorKind::Transport, "TCP read failed"))?;
            bytes.truncate(received);
        } else {
            bytes.clear();
        }
        Ok(TcpResponse {
            endpoint: format!("{}:{}", request.host, request.port),
            bytes,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use sugra_domain::{Budget, ScopeGrant};
    use time::OffsetDateTime;
    use tokio::net::TcpListener;

    use super::*;

    fn scope(address: IpAddr) -> ScopeGrant {
        ScopeGrant::exact(&Target::Ip(address), true, OffsetDateTime::UNIX_EPOCH)
    }

    fn budget(timeout_ms: u64) -> Budget {
        Budget {
            timeout_ms,
            max_response_bytes: 128,
            ..Budget::default()
        }
    }

    #[tokio::test]
    async fn connect_only_does_not_wait_for_the_peer_to_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok::<_, std::io::Error>(())
        });
        let response = TokioTcp
            .execute(TcpRequest {
                host: address.ip().to_string(),
                port: address.port(),
                payload: Vec::new(),
                read_response: false,
                budget: budget(50),
                scope: scope(address.ip()),
            })
            .await?;
        assert!(response.bytes.is_empty());
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn protocol_probe_writes_and_reads_one_bounded_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await?;
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await?;
            Ok::<_, std::io::Error>(())
        });
        let response = TokioTcp
            .execute(TcpRequest {
                host: address.ip().to_string(),
                port: address.port(),
                payload: b"ping".to_vec(),
                read_response: true,
                budget: budget(1_000),
                scope: scope(address.ip()),
            })
            .await?;
        assert_eq!(response.bytes, b"pong");
        server.await??;
        Ok(())
    }
}
