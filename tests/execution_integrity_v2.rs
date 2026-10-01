use crate::support;

use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};
use support::*;

#[test]
fn commit_projection_corruption_uses_independent_alert_sink() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness
        .state
        .lock()
        .expect("state")
        .corrupt_commit_projection = true;

    let result = harness.manager.execute_mutation(
        &evidence(),
        &command,
        &signed_authorization(),
        Some(&signed_custody()),
    );

    assert_eq!(result, Err(ManagerError::AuthorityResultUnknown));
    let integrity = harness.integrity.lock().expect("integrity");
    assert_eq!(integrity.events.len(), 1);
    assert_eq!(
        integrity.events[0].kind,
        crowsi_certificate_manager::IntegrityViolationKindV2::CommitProjectionMismatch
    );
}

#[test]
fn integrity_sink_failure_is_not_hidden_by_operation_state() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness
        .state
        .lock()
        .expect("state")
        .corrupt_commit_projection = true;
    harness.integrity.lock().expect("integrity").fail = true;

    assert_eq!(
        harness.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuditUnavailable)
    );
}

#[test]
fn invoked_unknown_requires_a_durable_unknown_transition() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness.authority.lock().expect("authority").execute_error =
        Some(crowsi_certificate_manager::AuthorityError::ResultUnknown);
    harness.state.lock().expect("state").fail_mark_unknown = true;

    assert_eq!(
        harness.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuditUnavailable)
    );
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Invoked)
    );
}

#[test]
fn unknown_conflict_requires_exact_terminal_readback() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness.authority.lock().expect("authority").execute_error =
        Some(crowsi_certificate_manager::AuthorityError::ResultUnknown);
    harness.state.lock().expect("state").conflict_mark_unknown = true;

    assert_eq!(
        harness.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuditUnavailable)
    );
    let integrity = harness.integrity.lock().expect("integrity");
    assert_eq!(integrity.events.len(), 1);
    assert_eq!(
        integrity.events[0].kind,
        crowsi_certificate_manager::IntegrityViolationKindV2::UnknownTransitionMismatch
    );
}
