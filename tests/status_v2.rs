use crate::support;

use crowsi_certificate_manager::{
    CertificateApprovalAssuranceV2, CertificateApprovalMethodV2,
    CertificateAuthorizationOperationBindingV2, CertificateAuthorizedActionV2,
    CertificateOperation, ManagerError,
};
use support::*;

#[test]
fn operation_status_is_owner_scoped_and_never_calls_authority() {
    let command = command(CertificateOperation::Issue);
    let mut initial = harness(&command);
    initial
        .manager
        .execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        )
        .expect("initial issue");
    let query = operation_status_query(&command);
    let mut manager =
        operation_status_manager(&query, initial.authority.clone(), initial.state.clone());

    let status = manager
        .operation_status(&evidence(), &query, &signed_status_authorization())
        .expect("status");

    assert_eq!(status.request_id, command.request_id);
    assert_eq!(status.resource_id, command.resource_id);
    assert_eq!(status.operation_lifecycle_revocation_epoch, 0);
    assert_eq!(
        initial.authority.lock().expect("authority").executed.len(),
        1
    );
    assert!(
        initial
            .authority
            .lock()
            .expect("authority")
            .reconciled
            .is_empty()
    );
}

#[test]
fn operation_status_replay_survives_manager_restart() {
    let command = command(CertificateOperation::Issue);
    let mut initial = harness(&command);
    initial
        .manager
        .execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        )
        .expect("initial issue");
    let query = operation_status_query(&command);
    let mut first =
        operation_status_manager(&query, initial.authority.clone(), initial.state.clone());
    first
        .operation_status(&evidence(), &query, &signed_status_authorization())
        .expect("first read");
    let mut restarted = operation_status_manager(&query, initial.authority, initial.state);

    assert!(matches!(
        restarted.operation_status(&evidence(), &query, &signed_status_authorization(),),
        Err(ManagerError::ReconciliationRejected)
    ));
}

#[test]
fn stored_identity_is_not_echo_from_the_query() {
    let command = command(CertificateOperation::Issue);
    let mut initial = harness(&command);
    initial
        .manager
        .execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        )
        .expect("initial issue");
    let mut query = operation_status_query(&command);
    query.resource_id = "resource.certificate.foreign".into();
    let mut manager = operation_status_manager(&query, initial.authority, initial.state);

    assert!(matches!(
        manager.operation_status(&evidence(), &query, &signed_status_authorization(),),
        Err(ManagerError::ReconciliationRejected)
    ));
}

#[test]
fn read_only_status_rejects_any_operator_approval_fields() {
    let command = command(CertificateOperation::Issue);
    let query = operation_status_query(&command);
    let (_, authority) = authority();
    let (_, state) = state_store();
    let mut verified = authorization(
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
    verified.approval_id = Some("approval.unexpected.0001".into());
    verified.approval_evidence_digest_sha256 = Some("90".repeat(32));
    verified.approval_method = Some(CertificateApprovalMethodV2::HardwareBackedUserPresence);
    verified.approval_assurance = Some(CertificateApprovalAssuranceV2::Aal3);
    verified.approval_verified_at_epoch_s = Some(NOW - 1);
    verified.approval_issued_at_epoch_s = Some(NOW - 2);
    verified.approval_expires_at_epoch_s = Some(NOW + 30);
    let mut manager =
        operation_status_manager_with_authorization(&query, authority, state, verified);

    assert!(matches!(
        manager.operation_status(&evidence(), &query, &signed_status_authorization()),
        Err(ManagerError::ReconciliationRejected)
    ));
}
