use std::sync::Arc;

use crowsi_certificate_manager::{
    AbandonReasonV2, AuditInvocationV2, ManagerError, OperationAbandonV2, OperationInvocationV2,
};

use super::support::*;

pub fn execute(
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

pub fn store(harness: &Harness) -> StateStore {
    StateStore(Arc::clone(&harness.state))
}

pub fn abandon(
    reservation: &crowsi_certificate_manager::OperationReservationV2,
) -> OperationAbandonV2 {
    OperationAbandonV2 {
        reservation_id: reservation.lifecycle.reservation_id.clone(),
        reason: AbandonReasonV2::AuthorizationExpired,
    }
}

pub fn invocation(
    harness: &Harness,
) -> (
    crowsi_certificate_manager::OperationReservationV2,
    OperationInvocationV2,
) {
    let state = harness.state.lock().expect("state");
    let reservation = state.reservation.clone().expect("reservation");
    let authority_command = state
        .handoff_pending
        .as_ref()
        .expect("pending")
        .authority_command
        .clone();
    let digest = authority_command.digest_sha256();
    (
        reservation.clone(),
        OperationInvocationV2 {
            audit: AuditInvocationV2 {
                reservation_id: reservation.audit.reservation_id,
                authority_command_digest_sha256: digest,
                execution_time_epoch_s: authority_command.execution_time_epoch_s,
            },
            authority_command,
        },
    )
}
