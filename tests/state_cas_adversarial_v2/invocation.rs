use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};

use super::{common::*, support::*};

#[test]
fn corrupt_invocation_revision_never_reaches_ca() {
    assert_projection_rejected(|state| state.corrupt_invocation_projection = true);
}

#[test]
fn corrupt_invocation_phase_never_reaches_ca() {
    assert_projection_rejected(|state| state.corrupt_invocation_phase = true);
}

#[test]
fn corrupt_invocation_digest_never_reaches_ca() {
    assert_projection_rejected(|state| state.corrupt_invocation_digest = true);
}

#[test]
fn changed_durable_acceptance_readback_never_reaches_ca() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness
        .state
        .lock()
        .expect("state")
        .corrupt_handoff_accept_projection = true;
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    assert!(
        harness
            .authority
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Reserved)
    );
}

#[test]
fn invocation_ack_loss_never_reinvokes_ca_on_retry() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness.state.lock().expect("state").lose_invocation_ack = true;
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::AuditUnavailable)
    );
    assert!(
        harness
            .authority
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
    harness.state.lock().expect("state").lose_invocation_ack = false;
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::AuthorityResultUnknown)
    );
    assert!(
        harness
            .authority
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
}

fn assert_projection_rejected(configure: impl FnOnce(&mut StoreData)) {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    configure(&mut harness.state.lock().expect("state"));
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::AuditUnavailable)
    );
    assert!(
        harness
            .authority
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Invoked)
    );
}
