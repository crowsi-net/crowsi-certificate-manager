use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};

use super::support::*;

#[test]
fn recovery_deadline_is_exclusive_and_never_invokes_ca() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    let (sink, _) = integrity_sink();
    let (handoff, _) = configured_handoff(true, false);
    let mut verified = mutation_authorization(&command);
    verified.expires_at_epoch_s = NOW + 2;
    let mut manager = build_manager_with_authorization(
        &command,
        authority,
        store,
        vec![NOW, NOW + 1, NOW + 2, NOW + 2, NOW + 62],
        false,
        sink,
        config(),
        verified,
    )
    .with_handoff(Box::new(handoff));

    assert_eq!(
        execute(&mut manager, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    assert_eq!(
        execute(&mut manager, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    assert!(
        authority_state
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
    assert_eq!(
        state.lock().expect("state").phase,
        Some(AuditOperationState::Reserved)
    );
}

fn execute(
    manager: &mut TestManager,
    command: &crowsi_certificate_manager::CertificateCommandV2,
) -> Result<crowsi_certificate_manager::CertificateResponseV2, ManagerError> {
    manager.execute_mutation(
        &evidence(),
        command,
        &signed_authorization(),
        Some(&signed_custody()),
    )
}
