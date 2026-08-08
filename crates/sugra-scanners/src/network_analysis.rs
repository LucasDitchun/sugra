//! Pure analysis and protocol-safe probes for bounded network observations.

use std::net::{IpAddr, SocketAddr};

use serde::Serialize;
use sugra_domain::{Confidence, Finding, Severity, Target};
use thiserror::Error;

const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;
const TRANSACTION_ID: [u8; 2] = [0x53, 0x55];
const SNMP_REQUEST_ID: [u8; 4] = [0x53, 0x55, 0x47, 0x52];
const NTP_TRANSMIT_TIMESTAMP: [u8; 8] = [0xe9, 0x5d, 0x7a, 0x00, 0, 0, 0, 1];
const NETBIOS_TRANSACTION_ID: [u8; 2] = [0x13, 0x37];

/// A protocol-specific, allowlisted UDP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UdpProbe {
    DnsRootNameserver,
    NtpClient,
    NetbiosNodeStatus,
    SnmpPublicGet,
    SnmpPublicBulk,
}

impl UdpProbe {
    /// Returns the only destination port accepted for this probe.
    pub(crate) const fn port(self) -> u16 {
        match self {
            Self::DnsRootNameserver => 53,
            Self::NtpClient => 123,
            Self::NetbiosNodeStatus => 137,
            Self::SnmpPublicGet | Self::SnmpPublicBulk => 161,
        }
    }
}

/// Bounded protocol metadata that never retains response bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "protocol", rename_all = "kebab-case")]
pub(crate) enum UdpClassification {
    Dns {
        transaction_matches: bool,
        response: bool,
        truncated: bool,
        response_code: u8,
        answers: u16,
    },
    Ntp {
        transaction_matches: bool,
        version: u8,
        mode: u8,
        stratum: u8,
        leap_indicator: u8,
    },
    Netbios {
        transaction_matches: bool,
        response: bool,
        answers: u16,
    },
    Snmp {
        error_status: u8,
    },
}

/// Safe projection and findings derived from one bounded datagram.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UdpAnalysis {
    pub(crate) classification: UdpClassification,
    pub(crate) findings: Vec<Finding>,
}

/// Typed analysis failures without raw endpoint or response material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum NetworkAnalysisError {
    #[error("IPv4 is not accepted by the IPv6 reachability contract")]
    Ipv4Target,
    #[error("target kind is not supported by the IPv6 reachability contract")]
    UnsupportedTarget,
    #[error("the connected endpoint is not IPv6")]
    Ipv4Connection,
    #[error("the connected IPv6 endpoint was not present in resolution results")]
    ConnectedAddressNotResolved,
    #[error("the connected IPv6 endpoint differs from the literal target")]
    ConnectedAddressDoesNotMatchTarget,
    #[error("UDP probe is not allowlisted for destination port {actual}; expected {expected}")]
    PortMismatch { expected: u16, actual: u16 },
    #[error("UDP response budget must be between 1 and 65507 bytes")]
    InvalidResponseBudget,
    #[error("UDP response exceeds the declared byte budget")]
    ResponseTooLarge,
    #[error("UDP response is truncated for the selected protocol")]
    TruncatedResponse,
    #[error("UDP response violates the selected protocol contract")]
    InvalidProtocolResponse,
}

/// Reports IPv6 reachability only for a resolved IPv6 endpoint that connected.
pub(crate) fn ipv6_reachability_finding(
    target: &Target,
    resolved: &[IpAddr],
    connected: Option<SocketAddr>,
    evidence: usize,
) -> Result<Option<Finding>, NetworkAnalysisError> {
    let literal_target = match target {
        Target::Ip(IpAddr::V4(_)) => return Err(NetworkAnalysisError::Ipv4Target),
        Target::Ip(IpAddr::V6(address)) => Some(*address),
        Target::Domain(_) => None,
        _ => return Err(NetworkAnalysisError::UnsupportedTarget),
    };

    let resolved_ipv6: Vec<_> = resolved
        .iter()
        .filter_map(|address| match address {
            IpAddr::V6(address) => Some(*address),
            IpAddr::V4(_) => None,
        })
        .collect();
    let Some(connected) = connected else {
        return Ok(None);
    };
    let IpAddr::V6(connected_ip) = connected.ip() else {
        return Err(NetworkAnalysisError::Ipv4Connection);
    };
    if !resolved_ipv6.contains(&connected_ip) {
        return Err(NetworkAnalysisError::ConnectedAddressNotResolved);
    }
    if literal_target.is_some_and(|target| target != connected_ip) {
        return Err(NetworkAnalysisError::ConnectedAddressDoesNotMatchTarget);
    }

    Ok(Some(finding(
        "ipv6-service-reachable",
        "A resolved IPv6 endpoint accepted a connection",
        Severity::Info,
        Confidence::Confirmed,
        evidence,
    )))
}

/// Constructs bytes only for an allowlisted protocol and its assigned port.
pub(crate) fn udp_payload(
    probe: UdpProbe,
    destination_port: u16,
) -> Result<Vec<u8>, NetworkAnalysisError> {
    let expected = probe.port();
    if destination_port != expected {
        return Err(NetworkAnalysisError::PortMismatch {
            expected,
            actual: destination_port,
        });
    }
    Ok(match probe {
        UdpProbe::DnsRootNameserver => dns_root_ns_query(),
        UdpProbe::NtpClient => ntp_client_request(),
        UdpProbe::NetbiosNodeStatus => netbios_node_status_query(),
        UdpProbe::SnmpPublicGet => snmp_request(false),
        UdpProbe::SnmpPublicBulk => snmp_request(true),
    })
}

/// Classifies a bounded response and emits only protocol-proven findings.
pub(crate) fn analyze_udp_response(
    probe: UdpProbe,
    response: &[u8],
    max_response_bytes: usize,
    evidence: usize,
) -> Result<UdpAnalysis, NetworkAnalysisError> {
    if max_response_bytes == 0 || max_response_bytes > MAX_UDP_DATAGRAM_BYTES {
        return Err(NetworkAnalysisError::InvalidResponseBudget);
    }
    if response.len() > max_response_bytes {
        return Err(NetworkAnalysisError::ResponseTooLarge);
    }

    let classification = match probe {
        UdpProbe::DnsRootNameserver => classify_dns(response)?,
        UdpProbe::NtpClient => classify_ntp(response)?,
        UdpProbe::NetbiosNodeStatus => classify_netbios(response)?,
        UdpProbe::SnmpPublicGet | UdpProbe::SnmpPublicBulk => UdpClassification::Snmp {
            error_status: parse_snmp_response(response)?,
        },
    };
    let findings = classification_finding(&classification, evidence)
        .into_iter()
        .collect();
    Ok(UdpAnalysis {
        classification,
        findings,
    })
}

fn classification_finding(classification: &UdpClassification, evidence: usize) -> Option<Finding> {
    match classification {
        UdpClassification::Dns {
            transaction_matches: true,
            response: true,
            response_code: 0,
            answers,
            ..
        } if *answers > 0 => Some(finding(
            "udp-dns-service-observed",
            "A DNS service returned an answer to an allowlisted query",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )),
        UdpClassification::Ntp {
            transaction_matches: true,
            version: 3 | 4,
            mode: 4,
            ..
        } => Some(finding(
            "ntp-service-observed",
            "An NTP server returned protocol metadata",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )),
        UdpClassification::Netbios {
            transaction_matches: true,
            response: true,
            answers,
        } if *answers > 0 => Some(finding(
            "netbios-name-service-observed",
            "A NetBIOS name service returned node-status data",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )),
        UdpClassification::Snmp { error_status: 0 } => Some(finding(
            "snmp-public-community-accepted",
            "The SNMP service responded to the public community",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        )),
        _ => None,
    }
}

fn dns_root_ns_query() -> Vec<u8> {
    vec![
        TRANSACTION_ID[0],
        TRANSACTION_ID[1],
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        2,
        0,
        1,
    ]
}

fn ntp_client_request() -> Vec<u8> {
    let mut request = vec![0_u8; 48];
    request[0] = 0x23;
    request[40..48].copy_from_slice(&NTP_TRANSMIT_TIMESTAMP);
    request
}

fn netbios_node_status_query() -> Vec<u8> {
    let mut query = vec![
        NETBIOS_TRANSACTION_ID[0],
        NETBIOS_TRANSACTION_ID[1],
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x20,
    ];
    let mut encoded_wildcard = [b'A'; 32];
    encoded_wildcard[..2].copy_from_slice(b"CK");
    query.extend_from_slice(&encoded_wildcard);
    query.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);
    query
}

fn snmp_request(bulk: bool) -> Vec<u8> {
    let oid = ber_tlv(0x06, &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    let mut variable = oid;
    variable.extend(ber_tlv(0x05, &[]));
    let binding = ber_tlv(0x30, &variable);
    let bindings = ber_tlv(0x30, &binding);
    let mut pdu = ber_tlv(0x02, &SNMP_REQUEST_ID);
    pdu.extend(ber_tlv(0x02, &[0]));
    pdu.extend(ber_tlv(0x02, &[if bulk { 10 } else { 0 }]));
    pdu.extend(bindings);
    let pdu = ber_tlv(if bulk { 0xa5 } else { 0xa0 }, &pdu);
    let mut message = ber_tlv(0x02, &[1]);
    message.extend(ber_tlv(0x04, b"public"));
    message.extend(pdu);
    ber_tlv(0x30, &message)
}

fn classify_dns(response: &[u8]) -> Result<UdpClassification, NetworkAnalysisError> {
    if response.len() < 12 {
        return Err(NetworkAnalysisError::TruncatedResponse);
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    Ok(UdpClassification::Dns {
        transaction_matches: response[..2] == TRANSACTION_ID,
        response: flags & 0x8000 != 0,
        truncated: flags & 0x0200 != 0,
        response_code: u8::try_from(flags & 0x000f).unwrap_or_default(),
        answers: u16::from_be_bytes([response[6], response[7]]),
    })
}

fn classify_ntp(response: &[u8]) -> Result<UdpClassification, NetworkAnalysisError> {
    if response.len() < 48 {
        return Err(NetworkAnalysisError::TruncatedResponse);
    }
    Ok(UdpClassification::Ntp {
        transaction_matches: response[24..32] == NTP_TRANSMIT_TIMESTAMP,
        version: (response[0] >> 3) & 0x07,
        mode: response[0] & 0x07,
        stratum: response[1],
        leap_indicator: response[0] >> 6,
    })
}

fn classify_netbios(response: &[u8]) -> Result<UdpClassification, NetworkAnalysisError> {
    if response.len() < 12 {
        return Err(NetworkAnalysisError::TruncatedResponse);
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    Ok(UdpClassification::Netbios {
        transaction_matches: response[..2] == NETBIOS_TRANSACTION_ID,
        response: flags & 0x8000 != 0,
        answers: u16::from_be_bytes([response[6], response[7]]),
    })
}

fn parse_snmp_response(response: &[u8]) -> Result<u8, NetworkAnalysisError> {
    let mut outer_offset = 0;
    let (outer_tag, message) = ber_element(response, &mut outer_offset)?;
    if outer_tag != 0x30 || outer_offset != response.len() {
        return Err(NetworkAnalysisError::InvalidProtocolResponse);
    }
    let mut message_offset = 0;
    let (version_tag, version) = ber_element(message, &mut message_offset)?;
    let (community_tag, community) = ber_element(message, &mut message_offset)?;
    let (pdu_tag, pdu) = ber_element(message, &mut message_offset)?;
    if version_tag != 0x02
        || version != [1]
        || community_tag != 0x04
        || community != b"public"
        || pdu_tag != 0xa2
        || message_offset != message.len()
    {
        return Err(NetworkAnalysisError::InvalidProtocolResponse);
    }
    let mut pdu_offset = 0;
    let (request_tag, request_id) = ber_element(pdu, &mut pdu_offset)?;
    let (status_tag, status) = ber_element(pdu, &mut pdu_offset)?;
    let (index_tag, _) = ber_element(pdu, &mut pdu_offset)?;
    let (bindings_tag, _) = ber_element(pdu, &mut pdu_offset)?;
    if request_tag != 0x02
        || request_id != SNMP_REQUEST_ID
        || status_tag != 0x02
        || status.len() != 1
        || index_tag != 0x02
        || bindings_tag != 0x30
        || pdu_offset != pdu.len()
    {
        return Err(NetworkAnalysisError::InvalidProtocolResponse);
    }
    status
        .first()
        .copied()
        .ok_or(NetworkAnalysisError::InvalidProtocolResponse)
}

fn ber_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    if body.len() < 128 {
        encoded.push(u8::try_from(body.len()).unwrap_or(127));
    } else {
        encoded.extend_from_slice(&[
            0x82,
            u8::try_from((body.len() >> 8) & 0xff).unwrap_or(0xff),
            u8::try_from(body.len() & 0xff).unwrap_or(0xff),
        ]);
    }
    encoded.extend_from_slice(body);
    encoded
}

fn ber_element<'a>(
    input: &'a [u8],
    offset: &mut usize,
) -> Result<(u8, &'a [u8]), NetworkAnalysisError> {
    let tag = *input
        .get(*offset)
        .ok_or(NetworkAnalysisError::TruncatedResponse)?;
    *offset += 1;
    let first_length = *input
        .get(*offset)
        .ok_or(NetworkAnalysisError::TruncatedResponse)?;
    *offset += 1;
    let length = if first_length & 0x80 == 0 {
        usize::from(first_length)
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > 2 {
            return Err(NetworkAnalysisError::InvalidProtocolResponse);
        }
        let end = (*offset)
            .checked_add(length_bytes)
            .ok_or(NetworkAnalysisError::InvalidProtocolResponse)?;
        let mut length = 0_usize;
        for byte in input
            .get(*offset..end)
            .ok_or(NetworkAnalysisError::TruncatedResponse)?
        {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(NetworkAnalysisError::InvalidProtocolResponse)?;
        }
        *offset = end;
        length
    };
    let end = (*offset)
        .checked_add(length)
        .ok_or(NetworkAnalysisError::InvalidProtocolResponse)?;
    let body = input
        .get(*offset..end)
        .ok_or(NetworkAnalysisError::TruncatedResponse)?;
    *offset = end;
    Ok((tag, body))
}

fn finding(
    key: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    evidence: usize,
) -> Finding {
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence,
        evidence: vec![evidence],
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use sugra_domain::TargetKind;

    use super::*;

    fn snmp_response(status: u8) -> Vec<u8> {
        let mut pdu = ber_tlv(0x02, &SNMP_REQUEST_ID);
        pdu.extend(ber_tlv(0x02, &[status]));
        pdu.extend(ber_tlv(0x02, &[0]));
        pdu.extend(ber_tlv(0x30, &[]));
        let mut message = ber_tlv(0x02, &[1]);
        message.extend(ber_tlv(0x04, b"public"));
        message.extend(ber_tlv(0xa2, &pdu));
        ber_tlv(0x30, &message)
    }

    #[test]
    fn ipv6_reachability_requires_a_resolved_connected_ipv6_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let finding = ipv6_reachability_finding(
            &target,
            &[IpAddr::V6(address)],
            Some(SocketAddr::new(IpAddr::V6(address), 443)),
            7,
        )?
        .ok_or("connected IPv6 endpoint did not produce a finding")?;

        assert_eq!(finding.key, "ipv6-service-reachable");
        assert_eq!(finding.evidence, vec![7]);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        Ok(())
    }

    #[test]
    fn ipv6_reachability_rejects_ipv4_targets_and_connections()
    -> Result<(), Box<dyn std::error::Error>> {
        let ipv4 = Target::parse(TargetKind::Ip, "192.0.2.1")?;
        assert_eq!(
            ipv6_reachability_finding(&ipv4, &[], None, 0),
            Err(NetworkAnalysisError::Ipv4Target)
        );

        let domain = Target::parse(TargetKind::Domain, "example.com")?;
        let resolved = IpAddr::V6("2001:db8::1".parse()?);
        assert_eq!(
            ipv6_reachability_finding(
                &domain,
                &[resolved],
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)),
                0,
            ),
            Err(NetworkAnalysisError::Ipv4Connection)
        );
        Ok(())
    }

    #[test]
    fn ipv6_reachability_does_not_infer_success_without_a_matching_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let resolved = IpAddr::V6("2001:db8::1".parse()?);
        assert!(ipv6_reachability_finding(&target, &[resolved], None, 0)?.is_none());

        let other = "2001:db8::2".parse()?;
        assert_eq!(
            ipv6_reachability_finding(
                &target,
                &[resolved],
                Some(SocketAddr::new(IpAddr::V6(other), 443)),
                0,
            ),
            Err(NetworkAnalysisError::ConnectedAddressNotResolved)
        );

        let literal = Target::parse(TargetKind::Ip, "2001:db8::1")?;
        assert_eq!(
            ipv6_reachability_finding(
                &literal,
                &[resolved, IpAddr::V6(other)],
                Some(SocketAddr::new(IpAddr::V6(other), 443)),
                0,
            ),
            Err(NetworkAnalysisError::ConnectedAddressDoesNotMatchTarget)
        );
        Ok(())
    }

    #[test]
    fn udp_payloads_are_allowlisted_by_protocol_and_port() -> Result<(), Box<dyn std::error::Error>>
    {
        let cases = [
            (UdpProbe::DnsRootNameserver, 53, 17),
            (UdpProbe::NtpClient, 123, 48),
            (UdpProbe::NetbiosNodeStatus, 137, 50),
            (UdpProbe::SnmpPublicGet, 161, 43),
            (UdpProbe::SnmpPublicBulk, 161, 43),
        ];
        for (probe, port, expected_len) in cases {
            let payload = udp_payload(probe, port)?;
            assert_eq!(payload.len(), expected_len, "{probe:?}");
            assert!(!payload.is_empty());
        }
        assert_eq!(
            udp_payload(UdpProbe::DnsRootNameserver, 9999),
            Err(NetworkAnalysisError::PortMismatch {
                expected: 53,
                actual: 9999,
            })
        );
        Ok(())
    }

    #[test]
    fn dns_sampler_classifies_answer_refusal_and_truncation()
    -> Result<(), Box<dyn std::error::Error>> {
        let answered = [0x53, 0x55, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        let analysis = analyze_udp_response(UdpProbe::DnsRootNameserver, &answered, 512, 2)?;
        assert_eq!(analysis.findings[0].key, "udp-dns-service-observed");

        let refused = [0x53, 0x55, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(
            analyze_udp_response(UdpProbe::DnsRootNameserver, &refused, 512, 2)?
                .findings
                .is_empty()
        );
        assert_eq!(
            analyze_udp_response(UdpProbe::DnsRootNameserver, &[0; 11], 512, 2),
            Err(NetworkAnalysisError::TruncatedResponse)
        );
        Ok(())
    }

    #[test]
    fn ntp_analysis_requires_a_matching_server_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut response = vec![0_u8; 48];
        response[0] = 0x24;
        response[1] = 2;
        response[24..32].copy_from_slice(&NTP_TRANSMIT_TIMESTAMP);
        let analysis = analyze_udp_response(UdpProbe::NtpClient, &response, 48, 3)?;
        assert_eq!(analysis.findings[0].key, "ntp-service-observed");

        response[24] ^= 0xff;
        assert!(
            analyze_udp_response(UdpProbe::NtpClient, &response, 48, 3)?
                .findings
                .is_empty()
        );
        assert_eq!(
            analyze_udp_response(UdpProbe::NtpClient, &[0; 47], 48, 3),
            Err(NetworkAnalysisError::TruncatedResponse)
        );
        Ok(())
    }

    #[test]
    fn snmp_analysis_distinguishes_accepted_error_and_invalid_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let accepted = snmp_response(0);
        let analysis = analyze_udp_response(UdpProbe::SnmpPublicGet, &accepted, 512, 4)?;
        assert_eq!(analysis.findings[0].key, "snmp-public-community-accepted");

        let error = snmp_response(2);
        assert!(
            analyze_udp_response(UdpProbe::SnmpPublicBulk, &error, 512, 4)?
                .findings
                .is_empty()
        );
        let mut invalid = accepted;
        let request_id = invalid
            .windows(SNMP_REQUEST_ID.len())
            .position(|window| window == SNMP_REQUEST_ID)
            .ok_or("SNMP fixture request ID is missing")?;
        invalid[request_id] = 0;
        assert_eq!(
            analyze_udp_response(UdpProbe::SnmpPublicGet, &invalid, 512, 4),
            Err(NetworkAnalysisError::InvalidProtocolResponse)
        );
        Ok(())
    }

    #[test]
    fn netbios_analysis_requires_transaction_response_and_answers()
    -> Result<(), Box<dyn std::error::Error>> {
        let answered = [0x13, 0x37, 0x85, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        let analysis = analyze_udp_response(UdpProbe::NetbiosNodeStatus, &answered, 512, 5)?;
        assert_eq!(analysis.findings[0].key, "netbios-name-service-observed");

        let wrong_transaction = [0, 1, 0x85, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        assert!(
            analyze_udp_response(UdpProbe::NetbiosNodeStatus, &wrong_transaction, 512, 5,)?
                .findings
                .is_empty()
        );
        assert_eq!(
            analyze_udp_response(UdpProbe::NetbiosNodeStatus, &[0; 8], 512, 5),
            Err(NetworkAnalysisError::TruncatedResponse)
        );
        Ok(())
    }

    #[test]
    fn udp_classification_enforces_declared_and_protocol_maximums() {
        assert_eq!(
            analyze_udp_response(UdpProbe::NtpClient, &[0; 48], 47, 0),
            Err(NetworkAnalysisError::ResponseTooLarge)
        );
        assert_eq!(
            analyze_udp_response(UdpProbe::NtpClient, &[0; 48], 0, 0),
            Err(NetworkAnalysisError::InvalidResponseBudget)
        );
        assert_eq!(
            analyze_udp_response(UdpProbe::NtpClient, &[0; 48], MAX_UDP_DATAGRAM_BYTES + 1, 0,),
            Err(NetworkAnalysisError::InvalidResponseBudget)
        );
    }
}
