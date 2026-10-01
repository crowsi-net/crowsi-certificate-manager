use crowsi_certificate_manager::{CertificateOperation, ManagerError};
use crowsi_control_contracts::CertificateActionV2;

use super::{recovery_support, support::*};

#[test]
fn staged_resume_rejects_coherent_operation_and_pa_readback_rewrite() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    let (handoff, _) = configured_handoff(true, false);
    harness.manager = harness.manager.with_handoff(Box::new(handoff));
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    {
        let mut state = harness.state.lock().expect("state");
        state
            .reservation
            .as_mut()
            .expect("reservation")
            .lifecycle
            .intent
            .operation = CertificateOperation::Renew;
        state
            .handoff_pending
            .as_mut()
            .expect("pending")
            .readback
            .action = CertificateActionV2::Renew;
    }

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
}

#[test]
fn accepted_resume_rejects_coherent_owner_and_audit_rewrite() {
    let command = command(CertificateOperation::Issue);
    let mut harness = recovery_support::resume_harness(
        CertificateOperation::Issue,
        workload(),
        recovery_support::refreshed_workload(),
        Some(custody(command.digest_sha256())),
        Some(recovery_support::refreshed_custody(&command)),
    );
    recovery_support::begin_accepted_ack_loss(&mut harness);
    {
        let mut state = harness.state.lock().expect("state");
        let reservation = state.reservation.as_mut().expect("reservation");
        reservation.lifecycle.intent.owner_profile = "profile.changed".into();
        reservation.audit.intent_digest_sha256 = "aa".repeat(32);
    }

    assert_eq!(
        recovery_support::call(&mut harness, &evidence(), Some(&signed_custody()),),
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
