use crate::support;

use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};
use support::*;

#[test]
fn signed_execution_time_must_follow_the_durable_invocation() {
    assert_invalid_execution_time(CertificateOperation::Issue, NOW + 3);
}

#[test]
fn signed_execution_time_cannot_reach_the_original_custody_deadline() {
    assert_invalid_execution_time(CertificateOperation::Issue, NOW + 60);
}

#[test]
fn signed_execution_time_cannot_reach_the_original_authority_deadline() {
    assert_invalid_execution_time(CertificateOperation::Revoke, NOW + 71);
}

fn assert_invalid_execution_time(operation: CertificateOperation, executed_at: u64) {
    let command = command(operation);
    let mut harness = harness(&command);
    harness
        .authority
        .lock()
        .expect("authority")
        .executed_at_override = Some(executed_at);
    let custody = operation.requires_key_enrollment().then(signed_custody);
    assert_eq!(
        harness.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            custody.as_ref(),
        ),
        Err(ManagerError::AuthorityResultUnknown)
    );
    assert_eq!(
        harness.authority.lock().expect("authority").executed.len(),
        1
    );
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::ResultUnknown)
    );
}
