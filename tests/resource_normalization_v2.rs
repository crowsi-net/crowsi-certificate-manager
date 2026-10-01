use crate::support;

use crowsi_certificate_manager::{CertificateOperation, ManagerError};
use support::*;

#[test]
fn raw_resource_aliases_are_rejected_before_fence_reservation() {
    for alias in [
        "resource.certificate/NERP-worker",
        "resource.certificate/../nerp-worker",
    ] {
        let mut command = command(CertificateOperation::Issue);
        command.resource_id = alias.into();
        let mut harness = harness(&command);
        assert_eq!(
            harness.manager.execute_mutation(
                &evidence(),
                &command,
                &signed_authorization(),
                Some(&signed_custody()),
            ),
            Err(ManagerError::InvalidCommand)
        );
        assert!(harness.state.lock().expect("state").begin.is_none());
    }
}

#[test]
fn normalization_must_be_independently_verified_with_the_pinned_version() {
    let command = command(CertificateOperation::Issue);
    let mut unverified = mutation_authorization(&command);
    unverified.target_resource_normalization_verified = false;
    let mut wrong_version = mutation_authorization(&command);
    wrong_version.target_resource_normalizer_version = "normalizer.version.9999".into();
    for authorization in [unverified, wrong_version] {
        let (authority, authority_state) = authority();
        let (store, _) = state_store();
        let (sink, _) = integrity_sink();
        let mut manager = build_manager_with_authorization(
            &command,
            authority,
            store,
            vec![NOW, NOW + 1],
            false,
            sink,
            config(),
            authorization,
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
        assert!(
            authority_state
                .lock()
                .expect("authority")
                .executed
                .is_empty()
        );
    }
}
