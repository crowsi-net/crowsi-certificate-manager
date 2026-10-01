use crate::support;

use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};
use support::*;

#[test]
fn corrupted_reconciliation_projection_is_alerted_and_rejected() {
    let command = command(CertificateOperation::Issue);
    let initial = make_unknown(&command);
    initial
        .state
        .lock()
        .expect("state")
        .corrupt_reconciliation_projection = true;
    let query = reconciliation_query_for(&command, &initial.state);
    let (sink, integrity) = integrity_sink();
    let mut manager =
        reconciliation_manager_with_sink(&query, initial.authority, initial.state, sink);

    assert!(matches!(
        manager.reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization()),
        Err(ManagerError::ReconciliationRejected)
    ));
    assert_eq!(integrity.lock().expect("integrity").events.len(), 1);
}

#[test]
fn reconciliation_projection_alert_failure_fails_closed() {
    let command = command(CertificateOperation::Issue);
    let initial = make_unknown(&command);
    initial
        .state
        .lock()
        .expect("state")
        .corrupt_reconciliation_projection = true;
    let query = reconciliation_query_for(&command, &initial.state);
    let (sink, integrity) = integrity_sink();
    integrity.lock().expect("integrity").fail = true;
    let mut manager =
        reconciliation_manager_with_sink(&query, initial.authority, initial.state, sink);

    assert!(matches!(
        manager.reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization()),
        Err(ManagerError::AuditUnavailable)
    ));
}

#[test]
fn reconciliation_rejects_cross_era_signing_and_receipt_role_swap() {
    let command = command(CertificateOperation::Issue);
    let initial = make_unknown(&command);
    let query = reconciliation_query_for(&command, &initial.state);
    let mut manager_config = config();
    let old_ca_key = manager_config.authority_key_id.clone();
    let old_receipt_key = manager_config.authority_receipt_verifier_key_id.clone();
    manager_config.authority_key_id = old_receipt_key.clone();
    manager_config.authority_receipt_verifier_key_id = old_ca_key.clone();
    let mut current = readiness(12);
    current.lease.key_id = old_receipt_key;
    current.lease.authority_receipt_key_id = old_ca_key;
    let (sink, _) = integrity_sink();
    let authority = initial.authority.clone();
    let mut manager = reconciliation_manager_with_config(
        &query,
        authority.clone(),
        initial.state,
        sink,
        manager_config,
        current,
        vec![NOW + 3, NOW + 4, NOW + 5],
    );

    assert!(matches!(
        manager.reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization()),
        Err(ManagerError::ReconciliationRejected)
    ));
    assert!(authority.lock().expect("authority").reconciled.is_empty());
}

#[test]
fn reconciliation_rejects_post_authority_clock_rollback() {
    let command = command(CertificateOperation::Issue);
    let initial = make_unknown(&command);
    let query = reconciliation_query_for(&command, &initial.state);
    let (sink, _) = integrity_sink();
    let authority = initial.authority.clone();
    let mut manager = reconciliation_manager_with_config(
        &query,
        authority.clone(),
        initial.state.clone(),
        sink,
        config(),
        readiness(12),
        vec![NOW + 3, NOW + 4, NOW + 3],
    );

    assert!(matches!(
        manager.reconcile_unknown(&evidence(), &query, &signed_reconciliation_authorization()),
        Err(ManagerError::TrustedTimeRejected)
    ));
    assert_eq!(authority.lock().expect("authority").reconciled.len(), 1);
    assert_eq!(
        initial.state.lock().expect("state").phase,
        Some(AuditOperationState::ResultUnknown)
    );
}
