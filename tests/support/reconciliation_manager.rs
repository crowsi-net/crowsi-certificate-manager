use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crowsi_certificate_manager::*;

use super::*;

pub fn reconciliation_manager(
    query: &ReconciliationQueryV2,
    authority: Arc<Mutex<AuthorityState>>,
    state: Arc<Mutex<StoreData>>,
) -> TestManager {
    let (integrity_sink, _) = integrity_sink();
    reconciliation_manager_with_sink(query, authority, state, integrity_sink)
}

pub fn reconciliation_manager_with_sink(
    query: &ReconciliationQueryV2,
    authority: Arc<Mutex<AuthorityState>>,
    state: Arc<Mutex<StoreData>>,
    integrity_sink: IntegritySink,
) -> TestManager {
    reconciliation_manager_with_config(
        query,
        authority,
        state,
        integrity_sink,
        config(),
        readiness(12),
        vec![NOW + 3, NOW + 4, NOW + 5],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reconciliation_manager_with_config(
    query: &ReconciliationQueryV2,
    authority: Arc<Mutex<AuthorityState>>,
    state: Arc<Mutex<StoreData>>,
    integrity_sink: IntegritySink,
    manager_config: CertificateManagerConfig,
    readiness_lease: AuthorityReadinessV2,
    times: Vec<u64>,
) -> TestManager {
    let verified = reconciliation_authorization(query);
    CertificateManager::new(
        manager_config,
        Authority { state: authority },
        ReadinessVerifier(VecDeque::from([readiness_lease])),
        WorkloadVerifier::stable(workload()),
        AuthorizationVerifier(VecDeque::from([Ok(verified.clone()), Ok(verified)])),
        EnrollmentVerifier(enrollment()),
        CustodyVerifier(VecDeque::new()),
        CertificateVerifier,
        OutcomeVerifier { use_ca_key: false },
        StateStore(state),
        Box::new(integrity_sink),
        SequenceClock(times.into_iter().map(Ok).collect()),
    )
}

fn reconciliation_authorization(
    query: &ReconciliationQueryV2,
) -> VerifiedCertificateExecutionAuthorizationV2 {
    authorization(
        query.digest_sha256(),
        CertificateAuthorizedActionV2::ReconcileUnknown,
        &query.query_id,
        Some(
            CertificateAuthorizationOperationBindingV2::ReconcileUnknown {
                original_action: query.original_action,
                target_operation_id: query.target_request_id.clone(),
                lifecycle_reservation_id: query.expected_lifecycle_reservation_id.clone(),
                authority_command_digest_sha256: query
                    .expected_authority_command_digest_sha256
                    .clone(),
                unknown_evidence_digest_sha256: query
                    .expected_unknown_evidence_digest_sha256
                    .clone(),
                locked_previous_fence: query.expected_previous_fence,
                locked_current_fence: query.expected_current_fence,
                locked_previous_lifecycle_revocation_epoch: query
                    .locked_previous_lifecycle_revocation_epoch,
                locked_lifecycle_revocation_epoch: query.locked_lifecycle_revocation_epoch,
            },
        ),
        &query.resource_id,
        query.expected_resource_version,
        query.locked_previous_lifecycle_revocation_epoch,
        query.locked_lifecycle_revocation_epoch,
    )
}

pub fn reconciliation_query(
    command: &CertificateCommandV2,
    authority_command_digest_sha256: String,
) -> ReconciliationQueryV2 {
    ReconciliationQueryV2 {
        query_id: "query.reconciliation.0001".into(),
        nonce: "nonce.reconciliation.0001".into(),
        original_action: match command.operation {
            CertificateOperation::Issue => CertificateLifecycleActionV2::Issue,
            CertificateOperation::Renew => CertificateLifecycleActionV2::Renew,
            CertificateOperation::Revoke => CertificateLifecycleActionV2::Revoke,
            CertificateOperation::Status => panic!("status is not reconciled"),
        },
        target_request_id: command.request_id.clone(),
        resource_id: command.resource_id.clone(),
        owner_subject: "subject.pairwise.nerp".into(),
        owner_profile: "profile.workload.operator".into(),
        expected_resource_version: command.expected_resource_version,
        expected_authority_command_digest_sha256: authority_command_digest_sha256,
        expected_unknown_evidence_digest_sha256: "45".repeat(32),
        expected_lifecycle_reservation_id: format!(
            "reservation.pa.{}.0001",
            command.operation.as_str()
        ),
        expected_previous_fence: 4,
        expected_current_fence: 5,
        locked_previous_lifecycle_revocation_epoch: command.previous_lifecycle_revocation_epoch,
        locked_lifecycle_revocation_epoch: command.lifecycle_revocation_epoch,
    }
}
