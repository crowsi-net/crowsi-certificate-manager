use crate::{
    AuthorityCommandV2, AuthorityOutcomeVerifierPort, AuthorityReadinessVerifierPort,
    CertificateAuthorityPort, CertificateCommandV2, CertificateExecutionAuthorizationVerifierPort,
    CertificateResponseV2, ManagerError, OperationReservationV2, OperationStateStorePort,
    PublicCertificateVerifierPort, TrustedClock, UnknownReasonV2,
    VerifiedCertificateExecutionAuthorizationV2, VerifiedWorkloadV2,
    validation::{validate_invocation_commit, validate_operation_commit},
};

use super::{
    CertificateManager, builders, failure::authority_reason, result::ResultVerificationError,
};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    A: CertificateAuthorityPort,
    R: AuthorityReadinessVerifierPort,
    P: CertificateExecutionAuthorizationVerifierPort,
    V: PublicCertificateVerifierPort,
    O: AuthorityOutcomeVerifierPort,
    S: OperationStateStorePort,
    T: TrustedClock,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn invoke_and_finalize(
        &mut self,
        command: &CertificateCommandV2,
        workload: &VerifiedWorkloadV2,
        authorization: &VerifiedCertificateExecutionAuthorizationV2,
        reservation: &OperationReservationV2,
        authority_command: &AuthorityCommandV2,
        invocation_time: u64,
    ) -> Result<CertificateResponseV2, ManagerError> {
        if invocation_time < authority_command.execution_time_epoch_s {
            return Err(ManagerError::TrustedTimeRejected);
        }
        let command_digest = authority_command.digest_sha256();
        let invocation =
            builders::operation_invocation(reservation, authority_command, invocation_time);
        let invoked = self
            .state_store
            .mark_invoked(reservation, &invocation)
            .map_err(|_| ManagerError::AuditUnavailable)?;
        validate_invocation_commit(reservation, &invocation, &invoked)?;
        let reservation = &invoked;
        let outcome = match self.authority.execute(authority_command, invocation_time) {
            Ok(value) => value,
            Err(error) => {
                self.persist_unknown(
                    reservation,
                    command_digest,
                    authority_reason(error),
                    invocation_time,
                )?;
                return Err(ManagerError::AuthorityResultUnknown);
            }
        };
        let verified = match self.verify_result(authority_command, reservation, &outcome) {
            Ok(value) => value,
            Err(error) => {
                let reason = match error {
                    ResultVerificationError::Outcome => UnknownReasonV2::OutcomeVerificationFailed,
                    ResultVerificationError::Certificate => {
                        UnknownReasonV2::CertificateVerificationFailed
                    }
                };
                self.persist_unknown(reservation, command_digest, reason, invocation_time)?;
                return Err(ManagerError::AuthorityResultUnknown);
            }
        };
        let executed_at = verified.executed_at_epoch_s;
        self.require_fresh_completion(
            reservation,
            &verified,
            command_digest.clone(),
            executed_at,
            invocation_time,
        )?;
        let receipt = builders::receipt(
            command,
            workload,
            authorization,
            reservation,
            authority_command,
            &outcome,
            &verified,
            executed_at,
        );
        let finalize = builders::operation_finalize(
            reservation,
            authority_command,
            &outcome,
            receipt.clone(),
            &verified.completion_evidence,
        );
        let Ok(commit) = self.state_store.finalize_operation(reservation, &finalize) else {
            self.persist_unknown(
                reservation,
                command_digest,
                UnknownReasonV2::LifecycleCommitFailed,
                invocation_time,
            )?;
            return Err(ManagerError::AuthorityResultUnknown);
        };
        if validate_operation_commit(reservation, &receipt, &commit).is_err() {
            self.report_commit_mismatch(reservation, &receipt, &commit, command_digest)?;
            return Err(ManagerError::AuthorityResultUnknown);
        }
        Ok(builders::response(command, outcome, commit, receipt))
    }
}
