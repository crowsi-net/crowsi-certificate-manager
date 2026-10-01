use crowsi_control_contracts::CertificateManagerHandoffDispositionV2;

use crate::{
    AbandonReasonV2, HandoffResumeContextV2, ManagerError, OperationAbandonV2,
    VerifiedManagerHandoffV2,
    validation::{validate_abandon_commit, validate_manager_handoff},
};

use super::CertificateManager;

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    S: crate::OperationStateStorePort,
{
    pub(crate) fn recover_or_accept_handoff(
        &mut self,
        context: &HandoffResumeContextV2,
    ) -> Result<VerifiedManagerHandoffV2, ManagerError> {
        let readback = &context.pending.readback;
        let verified = self
            .handoff
            .accept(readback)
            .map_err(|_| ManagerError::HandoffResultUnknown)?;
        validate_manager_handoff(&self.config, readback, &verified)?;
        if let Some(stored) = &context.accepted {
            return (stored == &verified)
                .then_some(verified)
                .ok_or(ManagerError::HandoffResultUnknown);
        }
        match verified.evidence.disposition {
            CertificateManagerHandoffDispositionV2::Accepted => Ok(verified),
            CertificateManagerHandoffDispositionV2::NotAccepted => {
                let abandon = OperationAbandonV2 {
                    reservation_id: context.reservation.lifecycle.reservation_id.clone(),
                    reason: AbandonReasonV2::AuthorizationExpired,
                };
                let committed = self
                    .state_store
                    .commit_handoff_not_accepted(context, &verified)
                    .map_err(|_| ManagerError::AuditUnavailable)?;
                validate_abandon_commit(&context.reservation, &abandon, &committed)?;
                Err(ManagerError::HandoffRejected)
            }
        }
    }
}

pub(crate) fn validate_durable_acceptance(
    context: &HandoffResumeContextV2,
    accepted: &VerifiedManagerHandoffV2,
) -> Result<(), ManagerError> {
    (context.accepted.as_ref() == Some(accepted))
        .then_some(())
        .ok_or(ManagerError::HandoffResultUnknown)
}
