use crate::support;

use crowsi_certificate_manager::{CertificateApprovalMethodV2, CertificateOperation, ManagerError};
use support::*;

#[test]
fn privileged_mutation_requires_complete_fresh_user_presence_evidence() {
    let command = command(CertificateOperation::Issue);
    for (method, verified_at, issued_at, expires_at) in [
        (
            Some(CertificateApprovalMethodV2::AuthenticatedSession),
            Some(NOW - 1),
            Some(NOW - 10),
            Some(NOW + 60),
        ),
        (
            Some(CertificateApprovalMethodV2::HardwareBackedUserPresence),
            Some(NOW - 61),
            Some(NOW - 70),
            Some(NOW + 60),
        ),
        (
            Some(CertificateApprovalMethodV2::HardwareBackedUserPresence),
            Some(NOW - 1),
            Some(NOW - 10),
            Some(NOW),
        ),
        (None, None, None, None),
    ] {
        let (authority, _) = authority();
        let (store, _) = state_store();
        let (sink, _) = integrity_sink();
        let mut verified = mutation_authorization(&command);
        verified.approval_method = method;
        verified.approval_verified_at_epoch_s = verified_at;
        verified.approval_issued_at_epoch_s = issued_at;
        verified.approval_expires_at_epoch_s = expires_at;
        if method.is_none() {
            verified.approval_id = None;
            verified.approval_evidence_digest_sha256 = None;
            verified.approval_assurance = None;
        }
        let mut manager = build_manager_with_authorization(
            &command,
            authority,
            store,
            vec![NOW, NOW + 1],
            false,
            sink,
            config(),
            verified,
        );

        assert_eq!(
            manager.execute_mutation(
                &evidence(),
                &command,
                &signed_authorization(),
                Some(&signed_custody()),
            ),
            Err(ManagerError::AuthorizationBindingRejected)
        );
    }
}

#[test]
fn same_key_id_cannot_hide_a_refresh_key_substitution() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, _) = state_store();
    let (sink, _) = integrity_sink();
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
    assert!(
        authority_state
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
}
