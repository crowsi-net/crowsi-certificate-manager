use crate::{
    ManagerError, OperationReservationV2, OperationStateStorePort, TrustedClock, UnknownReasonV2,
    VerifiedAuthorityOutcomeReceiptV2, validation::validate_completion_evidence_fresh,
};

use super::CertificateManager;

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    S: OperationStateStorePort,
    T: TrustedClock,
{
    pub(crate) fn require_fresh_completion(
        &mut self,
        reservation: &OperationReservationV2,
        verified: &VerifiedAuthorityOutcomeReceiptV2,
        command_digest: String,
        execution_time_epoch_s: u64,
        invocation_time_epoch_s: u64,
    ) -> Result<(), ManagerError> {
        let now = self.clock.now_epoch_s();
        let valid = now.is_ok_and(|observed| {
            validate_completion_evidence_fresh(
                &verified.completion_evidence,
                execution_time_epoch_s,
                observed,
            )
            .is_ok()
        });
        if valid {
            return Ok(());
        }
        self.persist_unknown(
            reservation,
            command_digest,
            UnknownReasonV2::OutcomeVerificationFailed,
            invocation_time_epoch_s,
        )?;
        Err(ManagerError::AuthorityResultUnknown)
    }
}
