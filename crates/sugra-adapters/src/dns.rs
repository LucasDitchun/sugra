//! DNS resolution through the operating-system resolver configuration.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
use hickory_resolver::proto::rr::{Name, RecordType};
use sugra_core::{
    DnsFlagState, DnsPort, DnsQuery, DnsRecord, DnsRecordType, DnsRecursionObservation,
    DnsRecursionRequest, PortError, PortErrorKind,
};
use sugra_domain::{Target, TargetKind};
use thiserror::Error;
use tokio::net::UdpSocket;

/// DNS adapter construction failure.
#[derive(Debug, Error)]
pub enum DnsAdapterError {
    /// System resolver configuration could not be loaded.
    #[error("could not load system DNS configuration")]
    SystemConfiguration,
}

/// Hickory-backed asynchronous DNS boundary.
#[derive(Clone)]
pub struct HickoryDns {
    resolver: TokioResolver,
}

impl HickoryDns {
    /// Builds a resolver from the operating-system DNS configuration.
    ///
    /// # Errors
    ///
    /// Returns `DnsAdapterError::SystemConfiguration` when the operating
    /// system resolver configuration cannot be loaded.
    pub fn system() -> Result<Self, DnsAdapterError> {
        let builder =
            TokioResolver::builder_tokio().map_err(|_| DnsAdapterError::SystemConfiguration)?;
        let resolver = builder
            .build()
            .map_err(|_| DnsAdapterError::SystemConfiguration)?;
        Ok(Self { resolver })
    }
}

#[async_trait]
impl DnsPort for HickoryDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        let mut records = Vec::new();
        for requested_type in query.record_types {
            let lookup = tokio::time::timeout(
                query.budget.timeout(),
                self.resolver
                    .lookup(query.name.clone(), record_type(requested_type)),
            )
            .await
            .map_err(|_| PortError::new(PortErrorKind::Timeout, "DNS query timed out"))?
            .map_err(|_| PortError::new(PortErrorKind::Transport, "DNS query failed"))?;
            records.extend(lookup.answers().iter().map(|record| DnsRecord {
                name: record.name.to_utf8(),
                record_type: requested_type,
                value: record.data.to_string(),
                ttl: Some(record.ttl),
            }));
        }
        records.sort_by(|left, right| {
            (left.record_type, &left.name, &left.value).cmp(&(
                right.record_type,
                &right.name,
                &right.value,
            ))
        });
        records.dedup();
        Ok(records)
    }

    async fn probe_recursion(
        &self,
        request: DnsRecursionRequest,
    ) -> Result<DnsRecursionObservation, PortError> {
        let target = request
            .resolver
            .parse::<IpAddr>()
            .map(Target::Ip)
            .or_else(|_| Target::parse(TargetKind::Domain, &request.resolver))
            .map_err(|_| {
                PortError::new(
                    PortErrorKind::InvalidResponse,
                    "DNS resolver target is invalid",
                )
            })?;
        if !request.scope.allows(&target) {
            return Err(PortError::new(
                PortErrorKind::OutOfScope,
                "DNS resolver target is outside the declared scope",
            ));
        }
        tokio::time::timeout(request.budget.timeout(), execute_recursion_probe(request))
            .await
            .map_err(|_| PortError::new(PortErrorKind::Timeout, "DNS recursion probe timed out"))?
    }
}

async fn execute_recursion_probe(
    request: DnsRecursionRequest,
) -> Result<DnsRecursionObservation, PortError> {
    if request.budget.max_response_bytes < 12 {
        return Err(PortError::new(
            PortErrorKind::TooLarge,
            "DNS response budget is smaller than a protocol header",
        ));
    }
    let endpoint = resolver_endpoint(&request).await?;
    let bind = if endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| PortError::new(PortErrorKind::Transport, "DNS UDP socket failed"))?;
    socket
        .connect(endpoint)
        .await
        .map_err(|_| PortError::new(PortErrorKind::Transport, "DNS UDP connect failed"))?;

    let name = Name::from_ascii(&request.query_name).map_err(|_| {
        PortError::new(
            PortErrorKind::InvalidResponse,
            "DNS recursion query name is invalid",
        )
    })?;
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.queries.push(Query::query(name, RecordType::A));
    let transaction_id = query.metadata.id;
    let payload = query.to_vec().map_err(|_| {
        PortError::new(
            PortErrorKind::Internal,
            "DNS recursion query serialization failed",
        )
    })?;

    let started = Instant::now();
    socket
        .send(&payload)
        .await
        .map_err(|_| PortError::new(PortErrorKind::Transport, "DNS recursion query failed"))?;
    let capacity = request.budget.max_response_bytes.min(65_535);
    let mut bytes = vec![0_u8; capacity];
    let received = socket
        .recv(&mut bytes)
        .await
        .map_err(|_| PortError::new(PortErrorKind::Transport, "DNS recursion response failed"))?;
    if received == capacity && capacity < 65_535 {
        return Err(PortError::new(
            PortErrorKind::TooLarge,
            "DNS recursion response reached the byte budget",
        ));
    }
    let response = Message::from_vec(&bytes[..received]).map_err(|_| {
        PortError::new(
            PortErrorKind::InvalidResponse,
            "DNS recursion response is invalid",
        )
    })?;
    if response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.metadata.id != transaction_id
    {
        return Err(PortError::new(
            PortErrorKind::InvalidResponse,
            "DNS recursion response does not match the query",
        ));
    }
    Ok(DnsRecursionObservation {
        recursion_desired: DnsFlagState::from(response.metadata.recursion_desired),
        recursion_available: DnsFlagState::from(response.metadata.recursion_available),
        response_code: u16::from(response.metadata.response_code),
        authoritative: DnsFlagState::from(response.metadata.authoritative),
        truncated: DnsFlagState::from(response.metadata.truncation),
        answer_count: response.answers.len(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

async fn resolver_endpoint(request: &DnsRecursionRequest) -> Result<SocketAddr, PortError> {
    if let Ok(ip) = request.resolver.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, request.port));
    }
    tokio::net::lookup_host((request.resolver.as_str(), request.port))
        .await
        .map_err(|_| PortError::new(PortErrorKind::Transport, "DNS resolver lookup failed"))?
        .next()
        .ok_or_else(|| {
            PortError::new(
                PortErrorKind::Unavailable,
                "DNS resolver has no reachable address",
            )
        })
}

const fn record_type(value: DnsRecordType) -> RecordType {
    match value {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::Aaaa => RecordType::AAAA,
        DnsRecordType::Cname => RecordType::CNAME,
        DnsRecordType::Mx => RecordType::MX,
        DnsRecordType::Ns => RecordType::NS,
        DnsRecordType::Soa => RecordType::SOA,
        DnsRecordType::Txt => RecordType::TXT,
        DnsRecordType::Srv => RecordType::SRV,
        DnsRecordType::Caa => RecordType::CAA,
        DnsRecordType::Dnskey => RecordType::DNSKEY,
        DnsRecordType::Ds => RecordType::DS,
        DnsRecordType::Ptr => RecordType::PTR,
    }
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
    use sugra_core::{DnsRecursionRequest, PortErrorKind};
    use sugra_domain::{Budget, ScopeGrant, Target, TargetKind};
    use tokio::net::UdpSocket;

    use super::*;

    #[test]
    fn every_public_record_type_maps_to_the_resolver_equivalent() {
        let cases = [
            (DnsRecordType::A, RecordType::A),
            (DnsRecordType::Aaaa, RecordType::AAAA),
            (DnsRecordType::Cname, RecordType::CNAME),
            (DnsRecordType::Mx, RecordType::MX),
            (DnsRecordType::Ns, RecordType::NS),
            (DnsRecordType::Soa, RecordType::SOA),
            (DnsRecordType::Txt, RecordType::TXT),
            (DnsRecordType::Srv, RecordType::SRV),
            (DnsRecordType::Caa, RecordType::CAA),
            (DnsRecordType::Dnskey, RecordType::DNSKEY),
            (DnsRecordType::Ds, RecordType::DS),
            (DnsRecordType::Ptr, RecordType::PTR),
        ];

        for (input, expected) in cases {
            assert_eq!(record_type(input), expected);
        }
    }

    #[tokio::test]
    async fn an_empty_record_set_completes_without_a_lookup()
    -> Result<(), Box<dyn std::error::Error>> {
        let dns = HickoryDns::system()?;
        let records = dns
            .query(DnsQuery {
                name: "invalid name that must not be queried".into(),
                record_types: Vec::new(),
                budget: Budget::default(),
            })
            .await?;

        assert!(records.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn recursion_probe_targets_one_server_and_preserves_response_flags()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let endpoint = server.local_addr()?;
        let responder = tokio::spawn(async move {
            let mut bytes = [0_u8; 512];
            let (received, peer) = server.recv_from(&mut bytes).await?;
            let query = Message::from_vec(&bytes[..received])?;
            assert_eq!(query.metadata.message_type, MessageType::Query);
            assert!(query.metadata.recursion_desired);
            let mut response =
                Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;
            response.metadata.response_code = ResponseCode::NXDomain;
            server.send_to(&response.to_vec()?, peer).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let target = Target::parse(TargetKind::Ip, "127.0.0.1")?;
        let dns = HickoryDns::system()?;
        let observation = dns
            .probe_recursion(DnsRecursionRequest {
                resolver: "127.0.0.1".into(),
                port: endpoint.port(),
                query_name: "recursion-check.invalid".into(),
                budget: Budget::default(),
                scope: ScopeGrant::exact(&target, true, time::OffsetDateTime::UNIX_EPOCH),
            })
            .await?;
        responder.await??;

        assert_eq!(observation.recursion_desired, DnsFlagState::Set);
        assert_eq!(observation.recursion_available, DnsFlagState::Set);
        assert_eq!(observation.response_code, 3);
        assert_eq!(observation.authoritative, DnsFlagState::Unset);
        assert_eq!(observation.truncated, DnsFlagState::Unset);
        assert_eq!(observation.answer_count, 0);
        assert!(observation.duration_ms <= Budget::DEFAULT.timeout_ms);

        let outside = Target::parse(TargetKind::Ip, "127.0.0.2")?;
        let Err(error) = dns
            .probe_recursion(DnsRecursionRequest {
                resolver: "127.0.0.1".into(),
                port: endpoint.port(),
                query_name: "recursion-check.invalid".into(),
                budget: Budget::default(),
                scope: ScopeGrant::exact(&outside, true, time::OffsetDateTime::UNIX_EPOCH),
            })
            .await
        else {
            return Err("out-of-scope resolver was accepted".into());
        };
        assert_eq!(error.kind, PortErrorKind::OutOfScope);
        Ok(())
    }
}
