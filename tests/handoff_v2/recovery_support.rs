use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::support::*;

pub struct ResumeHarness {
    pub manager: TestManager,
    pub command: CertificateCommandV2,
    pub authority: Arc<Mutex<AuthorityState>>,
    pub state: Arc<Mutex<StoreData>>,
}

pub fn resume_harness(
    operation: CertificateOperation,
    initial_workload: VerifiedWorkloadV2,
    current_workload: VerifiedWorkloadV2,
    initial_custody: Option<VerifiedKeyCustodyAttestationV2>,
    current_custody: Option<VerifiedKeyCustodyAttestationV2>,
) -> ResumeHarness {
    let command = command(operation);
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    state.lock().expect("state").lose_handoff_accept_ack = true;
    let mut verified = authorization(
        command.digest_sha256(),
        CertificateAuthorizedActionV2::from(operation),
        &command.request_id,
        None,
        &command.resource_id,
        command.expected_resource_version,
        command.previous_lifecycle_revocation_epoch,
        command.lifecycle_revocation_epoch,
    );
    verified.expires_at_epoch_s = NOW + 2;
    let custodies = initial_custody.map_or_else(Vec::new, |initial| {
        vec![
            initial.clone(),
            initial.clone(),
            initial,
            current_custody.expect("current custody"),
        ]
    });
    let manager = build_recovery_security_manager(
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
        verified,
        vec![initial_workload.clone(), initial_workload, current_workload],
        custodies,
    );
    ResumeHarness {
        manager,
        command,
        authority: authority_state,
        state,
    }
}

pub fn call(
    harness: &mut ResumeHarness,
    evidence: &WorkloadEvidenceV2,
    custody: Option<&SignedKeyCustodyAttestationV2>,
) -> Result<CertificateResponseV2, ManagerError> {
    if harness.command.operation == CertificateOperation::Status {
        harness
            .manager
            .certificate_status(evidence, &harness.command, &signed_authorization())
    } else {
        harness.manager.execute_mutation(
            evidence,
            &harness.command,
            &signed_authorization(),
            custody,
        )
    }
}

pub fn begin_accepted_ack_loss(harness: &mut ResumeHarness) {
    let custody = harness
        .command
        .operation
        .requires_key_enrollment()
        .then(signed_custody);
    assert_eq!(
        call(harness, &evidence(), custody.as_ref()),
        Err(ManagerError::HandoffResultUnknown)
    );
    assert!(
        harness
            .state
            .lock()
            .expect("state")
            .handoff_accepted
            .is_some()
    );
}

pub fn refreshed_workload() -> VerifiedWorkloadV2 {
    let mut value = workload();
    value.authenticated_at_epoch_s = NOW + 2;
    value.expires_at_epoch_s = NOW + 100;
    value.evidence_sha256 = "55".repeat(32);
    value
}

pub fn refreshed_custody(command: &CertificateCommandV2) -> VerifiedKeyCustodyAttestationV2 {
    let mut value = custody(command.digest_sha256());
    value.attestation_id = "attestation.custody.0002".into();
    value.attestation_digest_sha256 = "56".repeat(32);
    value.issued_at_epoch_s = NOW + 2;
    value.expires_at_epoch_s = NOW + 50;
    value
}
