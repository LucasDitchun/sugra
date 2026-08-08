//! Scope and capability policy evaluated before any boundary is opened.

use sugra_domain::{Capability, ScanRequest, ScannerDescriptor};
use thiserror::Error;

/// Policy rejection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// Request target kind is unsupported by the scanner.
    #[error("scanner does not accept target kind {0}")]
    UnsupportedTarget(&'static str),
    /// Target is outside the declared scope.
    #[error("target is outside the declared scope")]
    OutOfScope,
    /// An active capability lacks explicit authorization.
    #[error("capability {0:?} requires explicit authorization")]
    AuthorizationRequired(Capability),
}

/// Successful policy decision recorded before scanner execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Capabilities allowed for the request.
    pub capabilities: Vec<Capability>,
    /// Whether the request contains any active capability.
    pub active: bool,
}

/// Validates target type, scope, and active authorization.
///
/// # Errors
///
/// Returns a policy error when the target kind is unsupported, the target is
/// outside scope, or an active capability lacks explicit authorization.
pub fn evaluate_policy(
    descriptor: &ScannerDescriptor,
    request: &ScanRequest,
) -> Result<PolicyDecision, PolicyError> {
    if !descriptor.target_kinds.contains(&request.target.kind()) {
        return Err(PolicyError::UnsupportedTarget(
            request.target.kind().as_str(),
        ));
    }
    if !request.scope.allows(&request.target) {
        return Err(PolicyError::OutOfScope);
    }
    if let Some(capability) =
        descriptor.capabilities.iter().copied().find(|capability| {
            capability.requires_authorization() && !request.scope.active_authorized
        })
    {
        return Err(PolicyError::AuthorizationRequired(capability));
    }
    Ok(PolicyDecision {
        active: descriptor
            .capabilities
            .iter()
            .copied()
            .any(Capability::requires_authorization),
        capabilities: descriptor.capabilities.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sugra_domain::{Budget, LegacyId, ScanRequest, ScannerId, ScopeGrant, Target, TargetKind};
    use time::OffsetDateTime;

    use super::*;

    fn descriptor(
        target_kinds: Vec<TargetKind>,
        capabilities: Vec<Capability>,
    ) -> Result<ScannerDescriptor, Box<dyn std::error::Error>> {
        Ok(ScannerDescriptor {
            id: ScannerId::new("active-test")?,
            legacy_id: Some(LegacyId::Catalog(1)),
            name: "Active test".into(),
            description: "test".into(),
            track: "test".into(),
            target_kinds,
            capabilities,
            options: Vec::new(),
            version: "1".into(),
        })
    }

    fn request(target: Target, scope_target: &Target, active_authorized: bool) -> ScanRequest {
        ScanRequest {
            scanner_id: ScannerId::new("active-test")
                .unwrap_or_else(|error| unreachable!("valid test ID: {error}")),
            scope: ScopeGrant::exact(scope_target, active_authorized, OffsetDateTime::UNIX_EPOCH),
            target,
            options: BTreeMap::new(),
            budget: Budget::default(),
        }
    }

    #[test]
    fn active_boundary_is_denied_without_authorization() -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let descriptor = descriptor(vec![TargetKind::Domain], vec![Capability::ActiveProtocol])?;
        let request = request(target.clone(), &target, false);
        assert!(matches!(
            evaluate_policy(&descriptor, &request),
            Err(PolicyError::AuthorizationRequired(_))
        ));
        Ok(())
    }

    #[test]
    fn passive_and_authorized_active_requests_return_explicit_decisions()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let passive_descriptor = descriptor(
            vec![TargetKind::Domain],
            vec![Capability::PassiveNetwork, Capability::SensitiveOutput],
        )?;
        let passive = evaluate_policy(
            &passive_descriptor,
            &request(target.clone(), &target, false),
        )?;
        assert!(!passive.active);
        assert_eq!(passive.capabilities, passive_descriptor.capabilities);

        let active_descriptor = descriptor(
            vec![TargetKind::Domain],
            vec![Capability::PassiveNetwork, Capability::ActiveHttpSafe],
        )?;
        let active = evaluate_policy(&active_descriptor, &request(target.clone(), &target, true))?;
        assert!(active.active);
        assert_eq!(active.capabilities, active_descriptor.capabilities);
        Ok(())
    }

    #[test]
    fn unsupported_and_out_of_scope_targets_are_rejected_before_authorization()
    -> Result<(), Box<dyn std::error::Error>> {
        let domain = Target::parse(TargetKind::Domain, "example.com")?;
        let ip = Target::parse(TargetKind::Ip, "192.0.2.10")?;
        let descriptor = descriptor(vec![TargetKind::Domain], vec![Capability::ActiveProtocol])?;

        assert_eq!(
            evaluate_policy(&descriptor, &request(ip, &domain, false)),
            Err(PolicyError::UnsupportedTarget("ip"))
        );

        let outside = Target::parse(TargetKind::Domain, "outside.example")?;
        assert_eq!(
            evaluate_policy(&descriptor, &request(outside, &domain, false)),
            Err(PolicyError::OutOfScope)
        );
        Ok(())
    }
}
