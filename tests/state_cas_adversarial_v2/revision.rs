use crowsi_certificate_manager::{
    AuditOperationState, CertificateOperation, ManagerError, OperationStateError,
    OperationStateStorePort,
};

use super::{common::*, support::*};

#[test]
fn finalize_requires_the_exact_next_revision() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness.state.lock().expect("state").corrupt_commit_revision = true;

    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::AuthorityResultUnknown)
    );
    assert_eq!(
        harness.authority.lock().expect("authority").executed.len(),
        1
    );
    assert_eq!(harness.integrity.lock().expect("integrity").events.len(), 1);
}

#[test]
fn successful_mutation_advances_every_durable_transition() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    execute(&mut harness, &command).expect("mutation");
    let state = harness.state.lock().expect("state");
    assert_eq!(state.state_revision, 5);
    assert_eq!(
        state
            .reservation
            .as_ref()
            .expect("reservation")
            .state_revision,
        5
    );
}

#[test]
fn stale_or_overflowed_invocation_revision_is_atomic() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness.state.lock().expect("state").lose_handoff_accept_ack = true;
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    let (mut reservation, invocation) = invocation(&harness);
    reservation.state_revision -= 1;
    assert!(matches!(
        store(&harness).mark_invoked(&reservation, &invocation),
        Err(OperationStateError::Conflict)
    ));
    {
        let mut state = harness.state.lock().expect("state");
        state.state_revision = u64::MAX;
        state
            .reservation
            .as_mut()
            .expect("reservation")
            .state_revision = u64::MAX;
        reservation = state.reservation.clone().expect("reservation");
    }
    assert!(matches!(
        store(&harness).mark_invoked(&reservation, &invocation),
        Err(OperationStateError::Conflict)
    ));
    let state = harness.state.lock().expect("state");
    assert_eq!(state.state_revision, u64::MAX);
    assert_eq!(state.phase, Some(AuditOperationState::Reserved));
}
