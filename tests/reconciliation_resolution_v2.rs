use crate::support;

use crowsi_certificate_manager::{
    AuditOperationState, AuthorityError, AuthorityReconciliationDispositionV2,
    CertificateOperation, ManagerError,
};
use support::*;

#[test]
fn completed_reconciliation_atomically_recovers_outcome_and_proofs() {
    let command = command(CertificateOperation::Issue);
    let initial = make_unknown(&command);
    initial.authority.lock().expect("authority").reconciliation =
        AuthorityReconciliationDispositionV2::Completed;
    let query = reconciliation_query_for(&command, &initial.state);
    let mut manager = reconciliation_manager(&query, initial.authority, initial.state.clone());

    let result = manager
        .reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization())
        .expect("reconcile");

    assert_eq!(result.status.state, AuditOperationState::Finalized);
    assert!(result.recovered_outcome.is_some());
    let state = initial.state.lock().expect("state");
    assert_eq!(state.phase, Some(AuditOperationState::Finalized));
    assert!(state.reconciliation_receipt_digest_sha256.is_some());
    assert!(state.reconciliation_authorization_digest_sha256.is_some());
    assert!(state.reconciliation_query_digest_sha256.is_some());
}

#[test]
fn not_executed_is_distinct_from_pre_invocation_abandonment() {
    let command = command(CertificateOperation::Issue);
    let mut initial = harness(&command);
    initial.authority.lock().expect("authority").execute_error =
        Some(AuthorityError::ResultUnknown);
    assert_eq!(
        initial.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuthorityResultUnknown)
    );
    initial.authority.lock().expect("authority").reconciliation =
        AuthorityReconciliationDispositionV2::NotExecuted;
    let query = reconciliation_query_for(&command, &initial.state);
    let mut manager = reconciliation_manager(&query, initial.authority, initial.state);

    let result = manager
        .reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization())
        .expect("not executed");

    assert_eq!(
        result.status.state,
        AuditOperationState::ReconciledNotExecuted
    );
    assert!(result.status.abandon_reason.is_none());
    assert!(result.status.reconciliation_receipt_digest_sha256.is_some());
}

#[test]
fn still_unknown_retains_lock_and_records_fresh_proof() {
    let command = command(CertificateOperation::Issue);
    let initial = make_unknown(&command);
    let query = reconciliation_query_for(&command, &initial.state);
    let mut manager = reconciliation_manager(&query, initial.authority, initial.state);

    let result = manager
        .reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization())
        .expect("still unknown");

    assert_eq!(result.status.state, AuditOperationState::ResultUnknown);
    assert!(result.status.reconciliation_receipt_digest_sha256.is_some());
    assert!(result.recovered_outcome.is_none());
}

#[test]
fn finalize_ack_loss_recovers_public_result_without_reissuing() {
    let command = command(CertificateOperation::Issue);
    let mut initial = harness(&command);
    initial.state.lock().expect("state").lose_finalize_ack = true;
    assert_eq!(
        initial.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuthorityResultUnknown)
    );
    initial.state.lock().expect("state").lose_finalize_ack = false;
    initial.authority.lock().expect("authority").reconciliation =
        AuthorityReconciliationDispositionV2::Completed;
    let query = reconciliation_query_for(&command, &initial.state);
    let authority = initial.authority.clone();
    let mut manager = reconciliation_manager(&query, authority.clone(), initial.state);

    let result = manager
        .reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization())
        .expect("recover finalized");

    assert!(result.recovered_outcome.is_some());
    assert_eq!(authority.lock().expect("authority").executed.len(), 1);
}
