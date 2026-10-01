use crowsi_certificate_manager::{
    AuditOperationState, CertificateManagerHandoffPort, CertificateOperation,
    HandoffResumeContextV2, ManagerError, OperationStateError, OperationStateStorePort,
};

use super::{common::*, support::*};

#[test]
fn handoff_pending_rejects_generic_abandon() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    let (handoff, _) = configured_handoff(true, false);
    harness.manager = harness.manager.with_handoff(Box::new(handoff));
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );

    let reservation = harness
        .state
        .lock()
        .expect("state")
        .reservation
        .clone()
        .expect("reservation");
    let result = store(&harness).abandon_pre_handoff(&reservation, &abandon(&reservation));
    assert!(matches!(result, Err(OperationStateError::Conflict)));
    let state = harness.state.lock().expect("state");
    assert_eq!(state.phase, Some(AuditOperationState::Reserved));
    assert!(state.handoff_pending.is_some());
}

#[test]
fn accepted_handoff_rejects_every_abandon_path() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness.state.lock().expect("state").lose_handoff_accept_ack = true;
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );

    let (context, accepted) = {
        let state = harness.state.lock().expect("state");
        let accepted = state.handoff_accepted.clone().expect("accepted");
        (
            HandoffResumeContextV2 {
                reservation: state.reservation.clone().expect("reservation"),
                pending: state.handoff_pending.clone().expect("pending"),
                accepted: Some(accepted.clone()),
            },
            accepted,
        )
    };
    let generic =
        store(&harness).abandon_pre_handoff(&context.reservation, &abandon(&context.reservation));
    assert!(matches!(generic, Err(OperationStateError::Conflict)));
    let signed = store(&harness).commit_handoff_not_accepted(&context, &accepted);
    assert!(matches!(signed, Err(OperationStateError::Conflict)));
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Reserved)
    );
}

#[test]
fn not_accepted_commit_rejects_an_altered_ack() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    let (handoff, _) = configured_handoff(true, false);
    harness.manager = harness.manager.with_handoff(Box::new(handoff));
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    let context = {
        let state = harness.state.lock().expect("state");
        HandoffResumeContextV2 {
            reservation: state.reservation.clone().expect("reservation"),
            pending: state.handoff_pending.clone().expect("pending"),
            accepted: None,
        }
    };
    let (mut rejection, _) = configured_handoff(false, true);
    let mut rejected = rejection
        .accept(&context.pending.readback)
        .expect("not accepted");
    rejected.acknowledgement.receipt_id.push_str(".altered");
    assert!(matches!(
        store(&harness).commit_handoff_not_accepted(&context, &rejected),
        Err(OperationStateError::Conflict)
    ));
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Reserved)
    );
}
