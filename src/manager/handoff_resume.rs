use crate::{
    AuditOperationState, AuthorityOutcomeVerifierPort, AuthorityReadinessVerifierPort,
    CertificateAuthorityPort, CertificateCommandV2, CertificateExecutionAuthorizationVerifierPort,
    CertificateResponseV2, HandoffResumeQueryV2, KeyCustodyAttestationVerifierPort,
    KeyEnrollmentVerifierPort, ManagerError, OperationStateStorePort,
    PublicCertificateVerifierPort, SignedCertificateExecutionAuthorizationV2,
    SignedKeyCustodyAttestationV2, TrustedClock, UnknownReasonV2, WorkloadEvidenceV2,
    WorkloadIdentityVerifierPort,
    validation::{validate_command, validate_config},
};

use super::{CertificateManager, handoff::validate_durable_acceptance};

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
    pub(crate) fn resume_handoff(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        command: &CertificateCommandV2,
        signed: &SignedCertificateExecutionAuthorizationV2,
        signed_custody: Option<&SignedKeyCustodyAttestationV2>,
        query: &HandoffResumeQueryV2,
    ) -> Result<Option<CertificateResponseV2>, ManagerError> {
        validate_config(&self.config)?;
        validate_command(&self.config, command)?;
        let Some(mut context) = self
            .state_store
            .find_handoff_resume(query)
            .map_err(|_| ManagerError::AuditUnavailable)?
        else {
            return Ok(None);
        };
        self.validate_handoff_context(command, query, &context)?;
        if context.reservation.phase == AuditOperationState::Invoked {
            let now = self
                .clock
                .now_epoch_s()
                .map_err(|_| ManagerError::TrustedTimeRejected)?;
            self.revalidate_handoff_caller(evidence, &context, now)?;
            self.persist_unknown(
                &context.reservation,
                context.pending.authority_command.digest_sha256(),
                UnknownReasonV2::AuthorityAmbiguous,
                context
                    .reservation
                    .invoked_at_epoch_s
                    .unwrap_or(context.pending.staged_at_epoch_s),
            )?;
            return Err(ManagerError::AuthorityResultUnknown);
        }
        let invocation =
            self.prepare_handoff_invocation(evidence, command, signed, signed_custody, &context)?;
        let accepted = self.recover_or_accept_handoff(&context)?;
        if context.accepted.is_none() {
            context = self
                .state_store
                .mark_handoff_accepted(&context, &accepted)
                .map_err(|_| ManagerError::HandoffResultUnknown)?;
        }
        self.validate_handoff_context(command, query, &context)?;
        validate_durable_acceptance(&context, &accepted)?;
        let now = self.complete_handoff_invocation(command, signed, &context, &invocation)?;
        let pending = context.pending;
        self.invoke_and_finalize(
            command,
            &pending.workload,
            &pending.authorization,
            &context.reservation,
            &pending.authority_command,
            now,
        )
        .map(Some)
    }
}
