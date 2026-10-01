use crate::{
    AuditOperationState, AuthorityOutcomeVerifierPort, AuthorityReadinessVerifierPort,
    CertificateAuthorityPort, CertificateCommandV2, CertificateExecutionAuthorizationVerifierPort,
    CertificateResponseV2, KeyCustodyAttestationVerifierPort, KeyEnrollmentVerifierPort,
    ManagerError, OperationStateStorePort, PublicCertificateVerifierPort,
    SignedCertificateExecutionAuthorizationV2, SignedKeyCustodyAttestationV2, TrustedClock,
    UnknownReasonV2, WorkloadEvidenceV2, WorkloadIdentityVerifierPort,
    validation::{validate_operation_reservation, validate_signed_authorization},
};

use super::{
    CertificateManager, builders, failure::abandon_reason, handoff::validate_durable_acceptance,
    mapping,
};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    A: CertificateAuthorityPort,
    R: AuthorityReadinessVerifierPort,
    W: WorkloadIdentityVerifierPort,
    P: CertificateExecutionAuthorizationVerifierPort,
    K: KeyEnrollmentVerifierPort,
    C: KeyCustodyAttestationVerifierPort,
    V: PublicCertificateVerifierPort,
    O: AuthorityOutcomeVerifierPort,
    S: OperationStateStorePort,
    T: TrustedClock,
{
    pub(crate) fn execute_authorized(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        command: &CertificateCommandV2,
        authorization: &SignedCertificateExecutionAuthorizationV2,
        custody: Option<&SignedKeyCustodyAttestationV2>,
    ) -> Result<CertificateResponseV2, ManagerError> {
        let query = builders::handoff_query(command, authorization);
        validate_signed_authorization(&self.config, authorization)?;
        if let Some(response) =
            self.resume_handoff(evidence, command, authorization, custody, &query)?
        {
            return Ok(response);
        }
        let mut prepared = self.preflight(evidence, command, authorization, custody)?;
        let begin = builders::operation_begin(command, &prepared, prepared.initial_time_epoch_s);
        let reservation = self
            .state_store
            .begin_operation(&begin)
            .map_err(mapping::begin)?;
        validate_operation_reservation(&begin, &reservation)?;
        if reservation.phase == AuditOperationState::Invoked {
            let digest = reservation
                .invoked_authority_command_digest_sha256
                .clone()
                .ok_or(ManagerError::AuthorityResultUnknown)?;
            self.persist_unknown(
                &reservation,
                digest,
                UnknownReasonV2::AuthorityAmbiguous,
                prepared.initial_time_epoch_s,
            )?;
            return Err(ManagerError::AuthorityResultUnknown);
        }
        let execution_time =
            match self.refresh_before_authority(&mut prepared, command, authorization, custody) {
                Ok(value) => value,
                Err(error) => {
                    self.abandon(
                        &reservation,
                        abandon_reason(error),
                        prepared.initial_time_epoch_s,
                    )?;
                    return Err(error);
                }
            };
        let authority_command =
            builders::authority_command(command, &prepared, &reservation, execution_time)?;
        let pending = builders::handoff_pending(
            &self.config,
            query,
            &begin,
            &reservation,
            authority_command,
            &prepared,
            execution_time,
        )?;
        let context = self
            .state_store
            .stage_handoff(&reservation, &pending)
            .map_err(|_| ManagerError::AuditUnavailable)?;
        self.validate_handoff_context(command, &pending.query, &context)?;
        let invocation =
            self.prepare_handoff_invocation(evidence, command, authorization, custody, &context)?;
        let accepted = self.recover_or_accept_handoff(&context)?;
        let context = self
            .state_store
            .mark_handoff_accepted(&context, &accepted)
            .map_err(|_| ManagerError::HandoffResultUnknown)?;
        self.validate_handoff_context(command, &pending.query, &context)?;
        validate_durable_acceptance(&context, &accepted)?;
        let invocation_time =
            self.complete_handoff_invocation(command, authorization, &context, &invocation)?;
        self.invoke_and_finalize(
            command,
            &pending.workload,
            &pending.authorization,
            &context.reservation,
            &pending.authority_command,
            invocation_time,
        )
    }
}
