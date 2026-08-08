//! Compiled catalog validation and lookup.

use std::collections::{BTreeMap, BTreeSet};

use sugra_domain::{LegacyId, ScannerDescriptor, ScannerId};
use thiserror::Error;

/// Catalog invariant failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CatalogError {
    /// Canonical scanner ID is duplicated.
    #[error("duplicate scanner ID: {0}")]
    DuplicateId(ScannerId),
    /// Compatibility ID is duplicated.
    #[error("duplicate compatibility ID: {0}")]
    DuplicateLegacyId(LegacyId),
    /// Descriptor omits a required list or value.
    #[error("invalid descriptor {id}: {message}")]
    InvalidDescriptor {
        /// Affected scanner.
        id: ScannerId,
        /// Safe reason.
        message: String,
    },
    /// Catalog does not have an expected release count.
    #[error("catalog contains {actual} scanners, expected {expected}")]
    UnexpectedCount {
        /// Expected count.
        expected: usize,
        /// Actual count.
        actual: usize,
    },
}

/// Immutable validated scanner catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    entries: BTreeMap<ScannerId, ScannerDescriptor>,
    compatibility: BTreeMap<LegacyId, ScannerId>,
}

impl Catalog {
    /// Validates and constructs a catalog.
    ///
    /// # Errors
    ///
    /// Returns a catalog invariant error for duplicate identities or incomplete
    /// descriptors.
    pub fn new(descriptors: Vec<ScannerDescriptor>) -> Result<Self, CatalogError> {
        let mut entries = BTreeMap::new();
        let mut compatibility = BTreeMap::new();
        for descriptor in descriptors {
            validate_descriptor(&descriptor)?;
            if entries.contains_key(&descriptor.id) {
                return Err(CatalogError::DuplicateId(descriptor.id));
            }
            if let Some(legacy_id) = descriptor.legacy_id {
                if compatibility.contains_key(&legacy_id) {
                    return Err(CatalogError::DuplicateLegacyId(legacy_id));
                }
                compatibility.insert(legacy_id, descriptor.id.clone());
            }
            entries.insert(descriptor.id.clone(), descriptor);
        }
        Ok(Self {
            entries,
            compatibility,
        })
    }

    /// Verifies the release catalog contains an exact number of scanners.
    ///
    /// # Errors
    ///
    /// Returns `CatalogError::UnexpectedCount` when the validated catalog does
    /// not contain exactly `expected` entries.
    pub fn require_count(self, expected: usize) -> Result<Self, CatalogError> {
        let actual = self.entries.len();
        if actual == expected {
            Ok(self)
        } else {
            Err(CatalogError::UnexpectedCount { expected, actual })
        }
    }

    /// Returns a descriptor by canonical identity.
    #[must_use]
    pub fn get(&self, id: &ScannerId) -> Option<&ScannerDescriptor> {
        self.entries.get(id)
    }

    /// Resolves a compatibility identity.
    #[must_use]
    pub fn resolve_legacy(&self, id: LegacyId) -> Option<&ScannerDescriptor> {
        self.compatibility
            .get(&id)
            .and_then(|canonical| self.entries.get(canonical))
    }

    /// Iterates in canonical identity order.
    pub fn iter(&self) -> impl Iterator<Item = &ScannerDescriptor> {
        self.entries.values()
    }

    /// Returns the number of descriptors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no descriptors are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn validate_descriptor(descriptor: &ScannerDescriptor) -> Result<(), CatalogError> {
    let invalid = |message: &str| CatalogError::InvalidDescriptor {
        id: descriptor.id.clone(),
        message: message.into(),
    };
    if descriptor.name.trim().is_empty() || descriptor.description.trim().is_empty() {
        return Err(invalid("name and description are required"));
    }
    if descriptor.track.trim().is_empty() || descriptor.version.trim().is_empty() {
        return Err(invalid("track and version are required"));
    }
    if descriptor.target_kinds.is_empty() || descriptor.capabilities.is_empty() {
        return Err(invalid("target kinds and capabilities are required"));
    }
    let mut keys = BTreeSet::new();
    if descriptor
        .options
        .iter()
        .any(|option| !keys.insert(&option.key))
    {
        return Err(invalid("option keys must be unique"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sugra_domain::{Capability, TargetKind};

    use super::*;

    fn descriptor(
        id: &str,
        legacy_id: LegacyId,
    ) -> Result<ScannerDescriptor, Box<dyn std::error::Error>> {
        Ok(ScannerDescriptor {
            id: ScannerId::new(id)?,
            legacy_id: Some(legacy_id),
            name: id.into(),
            description: "test descriptor".into(),
            track: "test".into(),
            target_kinds: vec![TargetKind::Domain],
            capabilities: vec![Capability::PassiveNetwork],
            options: Vec::new(),
            version: "1".into(),
        })
    }

    #[test]
    fn duplicate_compatibility_identity_fails() -> Result<(), Box<dyn std::error::Error>> {
        let result = Catalog::new(vec![
            descriptor("one", LegacyId::Catalog(1))?,
            descriptor("two", LegacyId::Catalog(1))?,
        ]);
        assert!(matches!(result, Err(CatalogError::DuplicateLegacyId(_))));
        Ok(())
    }
}
