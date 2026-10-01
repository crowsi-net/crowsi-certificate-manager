use crate::support;

use crowsi_certificate_manager::{
    AuditOperationState, CertificateOperation, CertificateState, ManagerError,
};
use support::*;

#[test]
fn issue_keeps_private_key_outside_manager_and_commits_atomically() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);

    let result = harness.manager.execute_mutation(
        &evidence(),
        &command,
        &signed_authorization(),
        Some(&signed_custody()),
    );
    let state_guard = harness.state.lock().expect("state");
    let state_at_result = state_guard.phase;
    let finalized = state_guard.finalized_receipt.is_some();
    drop(state_guard);
    let response = result.unwrap_or_else(|error| {
        panic!("issue: {error:?}, state: {state_at_result:?}, finalized: {finalized}")
    });

    assert_eq!(response.state, CertificateState::Active);
    assert!(!response.receipt.event.private_key_received);
    assert!(!response.receipt.event.private_key_returned);
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::Finalized)
    );
    let authority = harness.authority.lock().expect("authority");
    assert_eq!(authority.executed.len(), 1);
    assert_eq!(
        authority.executed[0].public_key_algorithm.as_deref(),
        Some("ed25519")
    );
    assert_ne!(
        authority.executed[0].authority_key_id,
        authority.executed[0].authority_receipt_key_id
    );
}

#[test]
fn entrypoints_do_not_upgrade_status_or_mutation_authority() {
    let issue = command(CertificateOperation::Issue);
    let status = command(CertificateOperation::Status);
    let mut issue_harness = harness(&issue);
    let mut status_harness = harness(&status);

    assert_eq!(
        issue_harness
            .manager
            .certificate_status(&evidence(), &issue, &signed_authorization()),
        Err(ManagerError::InvalidCommand)
    );
    assert_eq!(
        status_harness.manager.execute_mutation(
            &evidence(),
            &status,
            &signed_authorization(),
            None,
        ),
        Err(ManagerError::InvalidCommand)
    );
}

#[test]
fn receipt_signed_with_certificate_authority_key_is_rejected() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    let mut manager = build_manager(&command, authority, store, vec![NOW, NOW + 1], true);

    let result = manager.execute_mutation(
        &evidence(),
        &command,
        &signed_authorization(),
        Some(&signed_custody()),
    );

    assert_eq!(result, Err(ManagerError::AuthorityResultUnknown));
    assert_eq!(authority_state.lock().expect("authority").executed.len(), 1);
    assert_eq!(
        state.lock().expect("state").phase,
        Some(AuditOperationState::ResultUnknown)
    );
}

#[test]
fn active_certificate_must_be_valid_at_execution_time() {
    for (not_before, expires) in [(NOW, NOW), (NOW - 1, NOW), (NOW - 301, NOW + 60)] {
        let command = command(CertificateOperation::Issue);
        let mut harness = harness(&command);
        {
            let mut authority = harness.authority.lock().expect("authority");
            authority.not_before_override = Some(not_before);
            authority.expires_override = Some(expires);
        }
        assert_eq!(
            harness.manager.execute_mutation(
                &evidence(),
                &command,
                &signed_authorization(),
                Some(&signed_custody()),
            ),
            Err(ManagerError::AuthorityResultUnknown)
        );
    }
}

#[test]
fn delayed_or_rolled_back_post_authority_time_never_commits() {
    for completion_time in [NOW, NOW + 62] {
        let command = command(CertificateOperation::Issue);
        let (authority, authority_state) = authority();
        let (store, state) = state_store();
        let mut manager = build_manager(
            &command,
            authority,
            store,
            vec![NOW, NOW + 1, NOW + 2, NOW + 2, NOW + 2, completion_time],
            false,
        );

        let result = manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        );

        assert_eq!(result, Err(ManagerError::AuthorityResultUnknown));
        assert_eq!(authority_state.lock().expect("authority").executed.len(), 1);
        assert_eq!(
            state.lock().expect("state").phase,
            Some(AuditOperationState::ResultUnknown)
        );
    }
}
