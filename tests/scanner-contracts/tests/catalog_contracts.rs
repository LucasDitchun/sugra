//! Cross-crate offline contracts for the complete built-in scanner set.

use std::collections::BTreeSet;

use sugra_domain::{ExecutionStatus, ScanResult};
use sugra_scanner_contracts::{Boundary, MissingFixture, contracts, semantic_gaps};
use sugra_scanners::build_builtins;

mod support;

#[test]
fn matrix_matches_the_complete_catalog_identity_set() -> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;
    let catalog_ids = builtins
        .catalog
        .iter()
        .map(|descriptor| descriptor.id.as_str())
        .collect::<BTreeSet<_>>();
    let matrix_ids = contracts()
        .iter()
        .map(|contract| contract.id)
        .collect::<BTreeSet<_>>();

    assert_eq!(contracts().len(), 147, "matrix must contain 147 rows");
    assert_eq!(matrix_ids.len(), 147, "matrix IDs must be unique");
    assert_eq!(matrix_ids, catalog_ids);
    Ok(())
}

#[test]
fn scanner_specific_semantic_gaps_are_complete_and_explicit() {
    let contract_ids = contracts()
        .into_iter()
        .map(|contract| contract.id)
        .collect::<BTreeSet<_>>();
    let gaps = semantic_gaps();
    let gap_ids = gaps.iter().map(|gap| gap.id).collect::<BTreeSet<_>>();

    assert_eq!(gap_ids, contract_ids);
    assert_eq!(gaps.len(), 147);
    for gap in gaps {
        assert!(gap.missing.contains(&MissingFixture::PositiveSignal));
        assert!(gap.missing.contains(&MissingFixture::NegativeControl));
        assert!(gap.missing.contains(&MissingFixture::EdgeCase));
    }
}

#[test]
fn catalog_descriptors_expose_complete_non_ambiguous_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;
    let mut legacy_ids = BTreeSet::new();

    for descriptor in builtins.catalog.iter() {
        assert!(!descriptor.name.trim().is_empty(), "{} name", descriptor.id);
        assert!(
            !descriptor.description.trim().is_empty(),
            "{} description",
            descriptor.id
        );
        assert!(
            !descriptor.track.trim().is_empty(),
            "{} track",
            descriptor.id
        );
        assert!(
            !descriptor.version.trim().is_empty(),
            "{} version",
            descriptor.id
        );
        assert!(
            !descriptor.target_kinds.is_empty(),
            "{} target kinds",
            descriptor.id
        );
        assert!(
            !descriptor.capabilities.is_empty(),
            "{} capabilities",
            descriptor.id
        );
        assert_eq!(
            descriptor
                .target_kinds
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            descriptor.target_kinds.len(),
            "{} duplicate target kind",
            descriptor.id
        );
        assert_eq!(
            descriptor
                .options
                .iter()
                .map(|option| option.key.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            descriptor.options.len(),
            "{} duplicate option key",
            descriptor.id
        );
        let legacy = serde_json::to_string(&descriptor.legacy_id)?;
        assert!(
            legacy_ids.insert(legacy),
            "{} duplicate legacy ID",
            descriptor.id
        );
        assert!(
            builtins.registry.get(&descriptor.id).is_some(),
            "{} missing implementation",
            descriptor.id
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_scanner_obeys_its_offline_runtime_contract() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;

    for contract in contracts() {
        harness.reset();
        let scanner_id = sugra_domain::ScannerId::new(contract.id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("matrix scanner is missing from the registry")?;
        let request = support::request_for(scanner.descriptor())?;
        let result = scanner.scan(&request, &support::context(false)).await?;
        let calls = harness.observed_boundaries();
        assert_success_contract(&contract, &result, &calls, request.budget.max_requests)?;
    }
    Ok(())
}

fn assert_success_contract(
    contract: &sugra_scanner_contracts::ScannerContract,
    result: &ScanResult,
    calls: &std::collections::BTreeMap<Boundary, usize>,
    max_requests: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let total_calls: usize = calls.values().sum();
    assert_eq!(
        result.status,
        ExecutionStatus::Completed,
        "{} did not complete against a successful fixture",
        contract.id
    );
    assert!(
        !result.evidence.is_empty(),
        "{} returned no observation",
        contract.id
    );
    assert!(
        total_calls <= max_requests,
        "{} exceeded its request budget: {calls:?}",
        contract.id
    );
    for (boundary, count) in calls {
        let expected =
            usize::from(contract.boundary == *boundary || contract.supplements.contains(boundary));
        assert_eq!(
            usize::from(*count > 0),
            expected,
            "{} used an unexpected boundary: {calls:?}",
            contract.id
        );
    }
    if contract.boundary == Boundary::Local {
        assert_eq!(total_calls, 0, "{} performed external I/O", contract.id);
    } else {
        assert!(
            total_calls > 0,
            "{} did not exercise its boundary",
            contract.id
        );
    }
    for evidence in &result.evidence {
        assert!(
            evidence.kind.starts_with(&format!("{}-", contract.id)),
            "{} emitted unowned evidence kind {}",
            contract.id,
            evidence.kind
        );
        assert!(!evidence.source.trim().is_empty(), "{} source", contract.id);
        assert_eq!(evidence.observed_at, time::OffsetDateTime::UNIX_EPOCH);
        assert_eq!(
            evidence.observation["scanner_id"].as_str(),
            Some(contract.id),
            "{} evidence identity",
            contract.id
        );
        for field in ["analysis", "purpose"] {
            assert!(
                evidence.observation[field]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "{} evidence {field}",
                contract.id
            );
        }
        assert!(
            evidence.observation.get("observation").is_some(),
            "{} missing structured observation",
            contract.id
        );
    }
    for finding in &result.findings {
        assert!(
            !finding.key.trim().is_empty(),
            "{} finding key",
            contract.id
        );
        assert!(
            !finding.evidence.is_empty()
                && finding
                    .evidence
                    .iter()
                    .all(|index| *index < result.evidence.len()),
            "{} finding {} has invalid evidence references",
            contract.id,
            finding.key
        );
    }
    assert!(
        !serde_json::to_string(result)?.contains(support::SECRET_MARKER),
        "{} leaked sensitive fixture material",
        contract.id
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_prevents_all_scanner_boundary_calls() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;

    for descriptor in builtins.catalog.iter() {
        harness.reset();
        let scanner = builtins
            .registry
            .get(&descriptor.id)
            .ok_or("catalog scanner is missing from the registry")?;
        let request = support::request_for(descriptor)?;
        let Err(error) = scanner.scan(&request, &support::context(true)).await else {
            return Err(std::io::Error::other(format!(
                "{} completed after pre-cancellation",
                descriptor.id
            ))
            .into());
        };
        assert_eq!(error.kind, sugra_core::ScanErrorKind::Cancelled);
        assert_eq!(
            harness.observed_boundaries().values().sum::<usize>(),
            0,
            "{} contacted a boundary after cancellation",
            descriptor.id
        );
    }
    Ok(())
}

#[tokio::test]
async fn boundary_failures_are_typed_and_never_become_empty_successes()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::failing();
    let builtins = build_builtins(&harness.services())?;

    for contract in contracts() {
        if contract.boundary == Boundary::Local {
            continue;
        }
        harness.reset();
        let scanner_id = sugra_domain::ScannerId::new(contract.id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("matrix scanner is missing from the registry")?;
        let request = support::request_for(scanner.descriptor())?;
        let outcome = scanner.scan(&request, &support::context(false)).await;

        match outcome {
            Err(error) => {
                assert_ne!(
                    error.kind,
                    sugra_core::ScanErrorKind::Internal,
                    "{}",
                    contract.id
                );
                assert!(
                    !error.message.trim().is_empty(),
                    "{} error message",
                    contract.id
                );
                assert!(!error.message.contains(support::SECRET_MARKER));
            }
            Ok(result) => {
                assert!(
                    !result.evidence.is_empty() || !result.diagnostics.is_empty(),
                    "{} converted a boundary failure into an empty result",
                    contract.id
                );
                assert!(
                    result.status != ExecutionStatus::Completed || !result.evidence.is_empty(),
                    "{} converted a boundary failure into empty success",
                    contract.id
                );
                assert!(!serde_json::to_string(&result)?.contains(support::SECRET_MARKER));
            }
        }
        let calls = harness.observed_boundaries();
        for expected in std::iter::once(&contract.boundary).chain(contract.supplements) {
            assert!(
                calls.get(expected).copied().unwrap_or_default() > 0,
                "{} did not exercise failure boundary {expected:?}: {calls:?}",
                contract.id
            );
        }
        assert!(
            calls.iter().all(|(boundary, count)| {
                *boundary == contract.boundary
                    || contract.supplements.contains(boundary)
                    || *count == 0
            }),
            "{} used an unexpected failure boundary: {calls:?}",
            contract.id
        );
    }
    Ok(())
}
