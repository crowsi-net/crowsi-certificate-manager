use crowsi_certificate_manager::{CertificateOperation, ManagerError, OperationHandoffPendingV2};
use crowsi_control_contracts::CertificateActionV2;

use super::support::*;

type Corrupt = fn(&mut OperationHandoffPendingV2);

#[test]
fn pa_readback_is_fully_rederived_before_staged_resume() {
    let corruptions: [(&str, Corrupt); 7] = [
        ("receipt", |pending| {
            pending.readback.receipt_id = "handoff.changed".into();
        }),
        ("action", |pending| {
            pending.readback.action = CertificateActionV2::Renew;
        }),
        ("security-domain", |pending| {
            pending.readback.security_domain = "security.changed".into();
        }),
        ("deployment", |pending| {
            pending.readback.deployment_id = "deployment.changed".into();
        }),
        ("trust-revision", |pending| {
            pending.readback.trust_revision += 1;
        }),
        ("reserved-at", |pending| {
            pending.readback.reserved_at_epoch_s += 1;
        }),
        ("expires-at", |pending| {
            pending.readback.expires_at_epoch_s += 10;
            pending.recovery_deadline_epoch_s += 10;
        }),
    ];
    for (name, corrupt) in corruptions {
        assert_corruption_rejected(name, corrupt);
    }
}

fn assert_corruption_rejected(name: &str, corrupt: Corrupt) {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    let (handoff, _) = configured_handoff(true, false);
    harness.manager = harness.manager.with_handoff(Box::new(handoff));
    assert_eq!(
        execute(&mut harness, &command),
        Err(ManagerError::HandoffResultUnknown)
    );
    corrupt(
        harness
            .state
            .lock()
            .expect("state")
            .handoff_pending
            .as_mut()
            .expect("pending"),
    );

    assert_eq!(
        execute(&mut harness, &command),
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

fn execute(
    harness: &mut Harness,
    command: &crowsi_certificate_manager::CertificateCommandV2,
) -> Result<crowsi_certificate_manager::CertificateResponseV2, ManagerError> {
    harness.manager.execute_mutation(
        &evidence(),
        command,
        &signed_authorization(),
        Some(&signed_custody()),
    )
}
