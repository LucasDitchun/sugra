//! DNS resolution through the operating-system resolver configuration.

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;
use sugra_core::{DnsPort, DnsQuery, DnsRecord, DnsRecordType, PortError, PortErrorKind};
use thiserror::Error;

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
