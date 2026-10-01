use crowsi_certificate_manager::{CertificateOperation, ManagerError};

use super::{recovery_support, support::*};

#[test]
fn staged_restart_rejects_missing_or_skipped_revision() {
    for offset in [0_u64, 2] {
        let command = command(CertificateOperation::Issue);
        let mut harness = harness(&command);
        let (handoff, _) = configured_handoff(true, false);
        harness.manager = harness.manager.with_handoff(Box::new(handoff));
        assert_eq!(
            execute(&mut harness, &command),
            Err(ManagerError::HandoffResultUnknown)
        );
        {
            let mut state = harness.state.lock().expect("state");
            let source = state
                .handoff_pending
                .as_ref()
                .expect("pending")
                .source_state_revision;
            state
                .reservation
                .as_mut()
                .expect("reservation")
                .state_revision = source + offset;
        }
        assert_eq!(
            execute(&mut harness, &command),
            Err(ManagerError::HandoffResultUnknown)
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
}

#[test]
fn accepted_restart_rejects_missing_skipped_or_overflowed_revision() {
    for revision in [
        RevisionCorruption::Missing,
        RevisionCorruption::Skipped,
        RevisionCorruption::Overflow,
    ] {
        let command = command(CertificateOperation::Issue);
        let mut harness = recovery_support::resume_harness(
            CertificateOperation::Issue,
            workload(),
            recovery_support::refreshed_workload(),
            Some(custody(command.digest_sha256())),
            Some(recovery_support::refreshed_custody(&command)),
        );
        recovery_support::begin_accepted_ack_loss(&mut harness);
        {
            let mut state = harness.state.lock().expect("state");
            let pending = state.handoff_pending.as_mut().expect("pending");
            let value = match revision {
                RevisionCorruption::Missing => pending.source_state_revision + 1,
                RevisionCorruption::Skipped => pending.source_state_revision + 3,
                RevisionCorruption::Overflow => {
                    pending.source_state_revision = u64::MAX;
                    u64::MAX
                }
            };
            state
                .reservation
                .as_mut()
                .expect("reservation")
                .state_revision = value;
        }
        assert_eq!(
            recovery_support::call(&mut harness, &evidence(), Some(&signed_custody()),),
            Err(ManagerError::HandoffResultUnknown)
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
}

#[derive(Clone, Copy)]
enum RevisionCorruption {
    Missing,
    Skipped,
    Overflow,
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
