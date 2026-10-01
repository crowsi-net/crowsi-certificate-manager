use crowsi_certificate_manager::CertificateOperation;

use super::support::*;

#[test]
fn shorter_initial_readiness_expiry_remains_bound_after_refresh() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    let (sink, _) = integrity_sink();
    let mut initial = readiness(10);
    initial.lease.expires_at_epoch_s = NOW + 5;
    let mut manager = build_manager_with_readiness(
        &command,
        authority,
        store,
        vec![NOW, NOW + 1],
        false,
        sink,
        config(),
        mutation_authorization(&command),
        vec![initial, readiness(11), readiness(12)],
    );

    manager
        .execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        )
        .expect("initial expiry is preserved");
    assert_eq!(authority_state.lock().expect("authority").executed.len(), 1);
    let state = state.lock().expect("state");
    assert_eq!(
        state
            .handoff_pending
            .as_ref()
            .expect("pending")
            .readback
            .expires_at_epoch_s,
        NOW + 5
    );
}
