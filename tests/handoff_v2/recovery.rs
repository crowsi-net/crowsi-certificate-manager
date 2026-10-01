use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};

use super::support::*;

#[test]
fn accepted_ack_is_recovered_after_original_authorization_expiry() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    let (sink, _) = integrity_sink();
    let (handoff, handoff_state) = configured_handoff(true, false);
    let mut verified = mutation_authorization(&command);
    verified.expires_at_epoch_s = NOW + 2;
    let mut manager = build_manager_with_authorization(
        &command,
        authority,
        store,
        vec![
            NOW,
            NOW + 1,
            NOW + 2,
            NOW + 2,
            NOW + 3,
            NOW + 3,
            NOW + 3,
            NOW + 4,
        ],
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
    execute(&mut manager, &command).expect("durable handoff resume");

    assert_eq!(handoff_state.lock().expect("handoff").calls, 2);
    assert_eq!(authority_state.lock().expect("authority").executed.len(), 1);
    assert_eq!(
        state.lock().expect("state").phase,
        Some(AuditOperationState::Finalized)
    );
}

#[test]
fn accepted_state_survives_readiness_failure_without_abandon_or_second_ca() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    state.lock().expect("state").lose_handoff_accept_ack = true;
    let (sink, _) = integrity_sink();
    let (handoff, _) = configured_handoff(false, false);
    let verified = mutation_authorization(&command);
    let mut changed_trust = readiness(12);
    changed_trust.lease.authority_public_key_spki_sha256 = "43".repeat(32);
    let readiness_values = vec![
        readiness(10),
        readiness(11),
        readiness(12),
        changed_trust,
        readiness(13),
    ];
    let mut manager = build_manager_with_readiness(
        &command,
        authority,
        store,
        vec![
            NOW,
            NOW + 1,
            NOW + 2,
            NOW + 2,
            NOW + 2,
            NOW + 3,
            NOW + 3,
            NOW + 3,
            NOW + 4,
        ],
        false,
        sink,
        config(),
        verified,
        readiness_values,
    )
    .with_handoff(Box::new(handoff));

    assert_eq!(
        execute(&mut manager, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    assert_eq!(
        execute(&mut manager, &command),
        Err(ManagerError::AuthorityUnavailable)
    );
    {
        let data = state.lock().expect("state");
        assert_eq!(data.phase, Some(AuditOperationState::Reserved));
        assert!(data.handoff_accepted.is_some());
        assert!(data.abandon_reason.is_none());
    }
    execute(&mut manager, &command).expect("trusted recovery");
    assert_eq!(authority_state.lock().expect("authority").executed.len(), 1);
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
