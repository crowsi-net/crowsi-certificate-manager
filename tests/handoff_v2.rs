#[path = "handoff_v2/readiness_transition.rs"]
mod readiness_transition;
#[path = "handoff_v2/recovery.rs"]
mod recovery;
#[path = "handoff_v2/recovery_binding.rs"]
mod recovery_binding;
#[path = "handoff_v2/recovery_custody.rs"]
mod recovery_custody;
#[path = "handoff_v2/recovery_deadline.rs"]
mod recovery_deadline;
#[path = "handoff_v2/recovery_invoked.rs"]
mod recovery_invoked;
#[path = "handoff_v2/recovery_readback.rs"]
mod recovery_readback;
#[path = "handoff_v2/recovery_reservation.rs"]
mod recovery_reservation;
#[path = "handoff_v2/recovery_revision.rs"]
mod recovery_revision;
#[path = "handoff_v2/recovery_support.rs"]
mod recovery_support;
#[path = "handoff_v2/recovery_timing.rs"]
mod recovery_timing;
#[path = "handoff_v2/recovery_workload.rs"]
mod recovery_workload;
use crate::support;

use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};
use support::*;

#[test]
fn handoff_ack_loss_retries_exact_reservation_before_any_ca_call() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    let (handoff, handoff_state) = configured_handoff(true, false);
    harness.manager = harness.manager.with_handoff(Box::new(handoff));

    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Reserved)
    );
    assert!(
        harness
            .authority
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );

    execute(&mut harness, &command).expect("exact ACK replay");

    assert_eq!(handoff_state.lock().expect("handoff").calls, 2);
    assert_eq!(
        harness.authority.lock().expect("authority").executed.len(),
        1
    );
}

#[test]
fn expired_uncommitted_handoff_is_abandoned_without_ca_invocation() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    let (handoff, _) = configured_handoff(false, true);
    harness.manager = harness.manager.with_handoff(Box::new(handoff));

    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffRejected)
    );
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Abandoned)
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

#[test]
fn failed_security_refresh_never_promotes_pa_handoff() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    let (sink, _) = integrity_sink();
    let (handoff, handoff_state) = configured_handoff(false, false);
    let verified = mutation_authorization(&command);
    let initial = readiness(10);
    let mut substituted = readiness(11);
    substituted.lease.authority_public_key_spki_sha256 = "43".repeat(32);
    let mut manager = build_manager_with_readiness(
        &command,
        authority,
        store,
        vec![NOW, NOW + 1],
        false,
        sink,
        config(),
        verified,
        vec![initial, substituted],
    )
    .with_handoff(Box::new(handoff));

    assert_eq!(
        manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuthorityUnavailable)
    );
    assert_eq!(handoff_state.lock().expect("handoff").calls, 0);
    assert_eq!(
        state.lock().expect("state").phase,
        Some(AuditOperationState::Abandoned)
    );
    assert!(
        authority_state
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
}

fn execute(
    harness: &mut Harness,
    command: &crowsi_certificate_manager::CertificateCommandV2,
) -> Result<crowsi_certificate_manager::CertificateResponseV2, ManagerError> {
    harness.manager.execute_mutation(
        &evidence(),
        command,
        &signed_authorization(),
        Some(&signed_custody()),
    )
}
