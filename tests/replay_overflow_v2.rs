use crate::support;

use crowsi_certificate_manager::{
    AuditOperationState, CertificateAuthorizedActionV2, CertificateOperation, ManagerError,
    SignedCertificateExecutionAuthorizationV2,
};
use support::*;

#[test]
fn resource_version_overflow_is_rejected_before_reservation() {
    let mut command = command(CertificateOperation::Renew);
    command.expected_resource_version = u64::MAX;
    let mut harness = harness(&command);

    assert!(matches!(
        harness.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::InvalidCommand)
    ));
    assert!(harness.state.lock().expect("state").begin.is_none());
}

#[test]
fn a_replay_key_cannot_be_reused_by_a_different_action() {
    let issue = command(CertificateOperation::Issue);
    let mut initial = harness(&issue);
    initial
        .manager
        .execute_mutation(
            &evidence(),
            &issue,
            &signed_authorization(),
            Some(&signed_custody()),
        )
        .expect("issue");
    {
        let mut state = initial.state.lock().expect("state");
        state.phase = None;
        state.begin = None;
        state.reservation = None;
        state.authority_command = None;
    }
    let renew = command(CertificateOperation::Renew);
    let mut verified = authorization(
        renew.digest_sha256(),
        CertificateAuthorizedActionV2::Renew,
        &renew.request_id,
        None,
        &renew.resource_id,
        renew.expected_resource_version,
        renew.previous_lifecycle_revocation_epoch,
        renew.lifecycle_revocation_epoch,
    );
    verified.jti = "authorization.jti.issue.0001".into();
    verified.lease_digest_sha256 = "14".repeat(32);
    let signed = SignedCertificateExecutionAuthorizationV2::new(
        "key.policy.administrator",
        "cGEtcGVwLWxlYXNlLXYy",
        "14".repeat(32),
        "c2lnbmF0dXJl",
    );
    let (sink, _) = integrity_sink();
    let authority = Authority {
        state: initial.authority.clone(),
    };
    let store = StateStore(initial.state.clone());
    let mut manager = build_manager_with_authorization(
        &renew,
        authority,
        store,
        vec![NOW + 10, NOW + 11],
        false,
        sink,
        config(),
        verified,
    );

    assert!(matches!(
        manager.execute_mutation(&evidence(), &renew, &signed, Some(&signed_custody())),
        Err(ManagerError::Replay)
    ));
    assert_eq!(
        initial.authority.lock().expect("authority").executed.len(),
        1
    );
    assert!(initial.state.lock().expect("state").begin.is_none());
}

#[test]
fn reconciliation_revision_overflow_is_atomic_and_fails_closed() {
    let command = command(CertificateOperation::Issue);
    let initial = make_unknown(&command);
    initial.state.lock().expect("state").state_revision = u64::MAX;
    let query = reconciliation_query_for(&command, &initial.state);
    let mut manager = reconciliation_manager(&query, initial.authority, initial.state.clone());

    assert!(matches!(
        manager.reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization()),
        Err(ManagerError::ReconciliationRejected)
    ));
    let state = initial.state.lock().expect("state");
    assert_eq!(state.phase, Some(AuditOperationState::ResultUnknown));
    assert_eq!(state.state_revision, u64::MAX);
    assert!(state.reconciliation_receipt_digest_sha256.is_none());
}
