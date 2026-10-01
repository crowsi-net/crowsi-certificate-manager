use crowsi_certificate_manager::{AuthorityCommandV2, CertificateOperation, ManagerError};

use super::{recovery_support::*, support::*};

type Corrupt = fn(&mut AuthorityCommandV2);

#[test]
fn every_authority_command_category_is_rederived_before_resume() {
    let corruptions: [(&str, Corrupt); 13] = [
        ("operation", |value| {
            value.operation = CertificateOperation::Renew;
        }),
        ("profile", |value| {
            value.profile_id = "profile.changed".into();
        }),
        ("purpose", |value| {
            value.purpose = "purpose.changed".into();
        }),
        ("subject", |value| {
            value.subject = "spiffe://changed/subject".into();
        }),
        ("audience", |value| {
            value.audience = "service://changed".into();
        }),
        ("scopes", |value| {
            value.scopes.push("changed.read".into());
        }),
        ("target", |value| {
            value.target_certificate_id = Some("changed".into());
        }),
        ("public-key", |value| {
            value.public_key_sha256 = Some("99".repeat(32));
        }),
        ("custody", |value| {
            value.custody_attestation_digest_sha256 = Some("98".repeat(32));
        }),
        ("authority-lease", |value| {
            value.authority_lease_id = "lease.changed".into();
        }),
        ("authority-key", |value| {
            value.authority_key_id = "key.changed".into();
        }),
        ("receipt-key", |value| {
            value.authority_receipt_key_id = "key.changed".into();
        }),
        ("execution-time", |value| {
            value.execution_time_epoch_s += 1;
        }),
    ];
    for (name, corrupt) in corruptions {
        let command = command(CertificateOperation::Issue);
        let mut harness = resume_harness(
            CertificateOperation::Issue,
            workload(),
            refreshed_workload(),
            Some(custody(command.digest_sha256())),
            Some(refreshed_custody(&command)),
        );
        begin_accepted_ack_loss(&mut harness);
        corrupt(
            &mut harness
                .state
                .lock()
                .expect("state")
                .handoff_pending
                .as_mut()
                .expect("pending")
                .authority_command,
        );

        assert_eq!(
            call(&mut harness, &evidence(), Some(&signed_custody())),
            Err(ManagerError::HandoffResultUnknown),
            "{name}"
        );
        assert!(
            harness
                .authority
                .lock()
                .expect("authority")
                .executed
                .is_empty(),
            "{name}"
        );
    }
}
