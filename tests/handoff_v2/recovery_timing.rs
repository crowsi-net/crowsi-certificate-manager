use crowsi_certificate_manager::{CertificateOperation, ManagerError};

use super::{recovery_support::refreshed_workload, support::*};

#[test]
fn delayed_handoff_cannot_invoke_after_the_stored_authority_lease_expires() {
    assert_delayed_guard(vec![NOW, NOW + 1, NOW + 2, NOW + 2, NOW + 72], true);
}

#[test]
fn final_clock_closes_the_verifier_to_invocation_expiry_race() {
    assert_delayed_guard(vec![NOW, NOW + 1, NOW + 2, NOW + 72], false);
}

#[test]
fn resumed_pa_replay_is_followed_by_a_new_final_time_guard() {
    assert_delayed_resume_guard();
}

fn assert_delayed_guard(times: Vec<u64>, pa_accepted: bool) {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    let verified = mutation_authorization(&command);
    let mut long_custody = custody(command.digest_sha256());
    long_custody.expires_at_epoch_s = NOW + 200;
    let mut manager = build_recovery_security_manager(
        &command,
        authority,
        store,
        times,
        verified,
        vec![workload(), refreshed_workload()],
        vec![long_custody.clone(), long_custody.clone(), long_custody],
    );

    assert_eq!(
        manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuthorityUnavailable)
    );
    assert_eq!(
        state.lock().expect("state").handoff_accepted.is_some(),
        pa_accepted
    );
    assert!(state.lock().expect("state").abandon_reason.is_none());
    assert!(
        authority_state
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
}

fn assert_delayed_resume_guard() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    state.lock().expect("state").lose_handoff_accept_ack = true;
    let verified = mutation_authorization(&command);
    let mut long_custody = custody(command.digest_sha256());
    long_custody.expires_at_epoch_s = NOW + 200;
    let mut manager = build_recovery_security_manager(
        &command,
        authority,
        store,
        vec![NOW, NOW + 1, NOW + 2, NOW + 2, NOW + 3, NOW + 3, NOW + 72],
        verified,
        vec![workload(), workload(), refreshed_workload()],
        vec![
            long_custody.clone(),
            long_custody.clone(),
            long_custody.clone(),
            long_custody,
        ],
    );
    assert_eq!(
        manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::HandoffResultUnknown)
    );
    assert_eq!(
        manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuthorityUnavailable)
    );
    assert!(state.lock().expect("state").handoff_accepted.is_some());
    assert!(
        authority_state
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
}
