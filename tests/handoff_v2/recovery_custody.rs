use crowsi_certificate_manager::{CertificateOperation, ManagerError};

use super::{recovery_support::*, support::*};

#[test]
fn different_current_custody_binding_cannot_resume() {
    let command = command(CertificateOperation::Issue);
    let mut changed = refreshed_custody(&command);
    changed.device_id = "device.local.attacker".into();
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        refreshed_workload(),
        Some(custody(command.digest_sha256())),
        Some(changed),
    );
    begin_accepted_ack_loss(&mut harness);

    assert_eq!(
        call(&mut harness, &evidence(), Some(&signed_custody())),
        Err(ManagerError::KeyCustodyRejected)
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
fn expired_current_custody_cannot_resume() {
    let command = command(CertificateOperation::Issue);
    let mut expired = refreshed_custody(&command);
    expired.expires_at_epoch_s = NOW + 3;
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        refreshed_workload(),
        Some(custody(command.digest_sha256())),
        Some(expired),
    );
    begin_accepted_ack_loss(&mut harness);

    assert_eq!(
        call(&mut harness, &evidence(), Some(&signed_custody())),
        Err(ManagerError::KeyCustodyRejected)
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
fn refreshed_custody_cannot_revive_the_stored_expired_attestation() {
    let command = command(CertificateOperation::Issue);
    let mut original = custody(command.digest_sha256());
    original.expires_at_epoch_s = NOW + 3;
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        refreshed_workload(),
        Some(original),
        Some(refreshed_custody(&command)),
    );
    begin_accepted_ack_loss(&mut harness);

    assert_eq!(
        call(&mut harness, &evidence(), Some(&signed_custody())),
        Err(ManagerError::KeyCustodyRejected)
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
fn issue_resume_requires_current_custody_input() {
    let command = command(CertificateOperation::Issue);
    let mut harness = resume_harness(
        CertificateOperation::Issue,
        workload(),
        refreshed_workload(),
        Some(custody(command.digest_sha256())),
        Some(refreshed_custody(&command)),
    );
    begin_accepted_ack_loss(&mut harness);

    assert_eq!(
        call(&mut harness, &evidence(), None),
        Err(ManagerError::InvalidCommand)
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
fn revoke_resume_forbids_custody_and_accepts_absence() {
    let mut rejected = resume_harness(
        CertificateOperation::Revoke,
        workload(),
        refreshed_workload(),
        None,
        None,
    );
    begin_accepted_ack_loss(&mut rejected);
    assert_eq!(
        call(&mut rejected, &evidence(), Some(&signed_custody())),
        Err(ManagerError::InvalidCommand)
    );
    assert!(
        rejected
            .authority
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );

    let mut valid = resume_harness(
        CertificateOperation::Revoke,
        workload(),
        refreshed_workload(),
        None,
        None,
    );
    begin_accepted_ack_loss(&mut valid);
    call(&mut valid, &evidence(), None).expect("custody-free revoke");
    assert_eq!(valid.authority.lock().expect("authority").executed.len(), 1);
}
