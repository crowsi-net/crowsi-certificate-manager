use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crowsi_certificate_manager::*;

use super::*;

pub fn operation_status_query(command: &CertificateCommandV2) -> OperationStatusQueryV2 {
    OperationStatusQueryV2 {
        query_id: "query.operation-status.0001".into(),
        nonce: "nonce.operation-status.0001".into(),
        target_request_id: command.request_id.clone(),
        resource_id: command.resource_id.clone(),
        owner_subject: "subject.pairwise.nerp".into(),
        owner_profile: "profile.workload.operator".into(),
        expected_resource_version: command.expected_resource_version,
        expected_lifecycle_revocation_epoch: command.lifecycle_revocation_epoch,
    }
}

pub fn operation_status_manager(
    query: &OperationStatusQueryV2,
    authority: Arc<Mutex<AuthorityState>>,
    state: Arc<Mutex<StoreData>>,
) -> TestManager {
    let verified = authorization(
        query.digest_sha256(),
        CertificateAuthorizedActionV2::OperationStatus,
        &query.query_id,
        Some(
            CertificateAuthorizationOperationBindingV2::OperationStatus {
                target_operation_id: query.target_request_id.clone(),
            },
        ),
        &query.resource_id,
        query.expected_resource_version,
        query.expected_lifecycle_revocation_epoch,
        query.expected_lifecycle_revocation_epoch,
    );
    operation_status_manager_with_authorization(query, authority, state, verified)
}

pub fn operation_status_manager_with_authorization(
    _query: &OperationStatusQueryV2,
    authority: Arc<Mutex<AuthorityState>>,
    state: Arc<Mutex<StoreData>>,
    verified: VerifiedCertificateExecutionAuthorizationV2,
) -> TestManager {
    let (integrity_sink, _) = integrity_sink();
    CertificateManager::new(
        config(),
        Authority { state: authority },
        ReadinessVerifier(VecDeque::new()),
        WorkloadVerifier::stable(workload()),
        AuthorizationVerifier(VecDeque::from([Ok(verified)])),
        EnrollmentVerifier(enrollment()),
        CustodyVerifier(VecDeque::new()),
        CertificateVerifier,
        OutcomeVerifier { use_ca_key: false },
        StateStore(state),
        Box::new(integrity_sink),
        SequenceClock(VecDeque::from([Ok(NOW + 3)])),
    )
}
