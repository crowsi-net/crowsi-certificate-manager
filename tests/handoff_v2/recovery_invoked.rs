use crowsi_certificate_manager::{
    AuditOperationState, CertificateOperation, ManagerError, WorkloadEvidenceV2,
};

use super::support::*;

#[test]
fn invoked_retry_requires_the_current_exact_workload_before_unknown_transition() {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    state.lock().expect("state").lose_invocation_ack = true;
    let verified = authorization(
        command.digest_sha256(),
        CertificateOperation::Issue.into(),
        &command.request_id,
        None,
        &command.resource_id,
        0,
        0,
        0,
    );
    let mut current = workload();
    current.authenticated_at_epoch_s = NOW + 1;
    current.expires_at_epoch_s = NOW + 100;
    current.evidence_sha256 = "55".repeat(32);
    let mut foreign = current.clone();
    foreign.device = "device.local.attacker".into();
    let original_custody = custody(command.digest_sha256());
    let mut manager = build_recovery_security_manager(
        &command,
        authority,
        store,
        vec![NOW, NOW + 1, NOW + 2, NOW + 2, NOW + 2, NOW + 3, NOW + 4],
        verified,
        vec![workload(), current, foreign],
        vec![
            original_custody.clone(),
            original_custody.clone(),
            original_custody,
        ],
    );
    assert_eq!(
        manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuditUnavailable)
    );
    let revision = state.lock().expect("state").state_revision;
    state.lock().expect("state").lose_invocation_ack = false;

    assert_eq!(
        manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::WorkloadClaimsRejected)
    );
    let malformed = WorkloadEvidenceV2::from_native_ipc("%%%");
    assert_eq!(
        manager.execute_mutation(
            &malformed,
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::InvalidWorkloadEvidence)
    );
    let current = state.lock().expect("state");
    assert_eq!(current.phase, Some(AuditOperationState::Invoked));
    assert_eq!(current.state_revision, revision);
    assert!(
        authority_state
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
}
