use crowsi_certificate_manager::{CertificateOperation, ManagerError, WorkloadEvidenceV2};

use super::{recovery_support::*, support::*};

#[test]
fn refreshed_same_workload_resumes_after_pa_expiry_and_invokes_ca_once() {
    let command = command(CertificateOperation::Issue);
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        refreshed_workload(),
        Some(custody(command.digest_sha256())),
        Some(refreshed_custody(&command)),
    );
    begin_accepted_ack_loss(&mut harness);

    call(&mut harness, &evidence(), Some(&signed_custody())).expect("authenticated recovery");

    assert_eq!(
        harness.authority.lock().expect("authority").executed.len(),
        1
    );
}

#[test]
fn different_device_cannot_resume_an_accepted_handoff() {
    let command = command(CertificateOperation::Issue);
    let mut different = refreshed_workload();
    different.device = "device.local.attacker".into();
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        different,
        Some(custody(command.digest_sha256())),
        Some(refreshed_custody(&command)),
    );
    begin_accepted_ack_loss(&mut harness);

    assert_eq!(
        call(&mut harness, &evidence(), Some(&signed_custody())),
        Err(ManagerError::WorkloadClaimsRejected)
    );
    assert!(
        harness
            .authority
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
    assert!(
        harness
            .state
            .lock()
            .expect("state")
            .abandon_reason
            .is_none()
    );
}

#[test]
fn expired_current_workload_cannot_resume_an_accepted_handoff() {
    let command = command(CertificateOperation::Issue);
    let mut expired = workload();
    expired.expires_at_epoch_s = NOW + 3;
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        expired,
        Some(custody(command.digest_sha256())),
        Some(refreshed_custody(&command)),
    );
    begin_accepted_ack_loss(&mut harness);

    assert_eq!(
        call(&mut harness, &evidence(), Some(&signed_custody())),
        Err(ManagerError::WorkloadClaimsRejected)
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
fn malformed_current_transport_evidence_is_rejected_before_ca() {
    let command = command(CertificateOperation::Issue);
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        refreshed_workload(),
        Some(custody(command.digest_sha256())),
        Some(refreshed_custody(&command)),
    );
    begin_accepted_ack_loss(&mut harness);
    let malformed = WorkloadEvidenceV2::from_native_ipc("%%%");

    assert_eq!(
        call(&mut harness, &malformed, Some(&signed_custody())),
        Err(ManagerError::InvalidWorkloadEvidence)
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
