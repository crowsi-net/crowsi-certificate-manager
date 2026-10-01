use crate::{
    AuditOperationState, AuthorityOutcomeVerifierPort, AuthorityReadinessVerifierPort,
    AuthorityReconciliationDispositionV2, CertificateAuthorityPort,
    CertificateExecutionAuthorizationVerifierPort, ManagerError, OperationStateStorePort,
    PublicCertificateVerifierPort, ReconciliationBeginV2, ReconciliationContextV2,
    ReconciliationQueryV2, ReconciliationResultV2, ReconciliationStateResolutionV2,
    SignedCertificateExecutionAuthorizationV2, TrustedClock,
    VerifiedCertificateExecutionAuthorizationV2, VerifiedWorkloadV2,
    validation::{
        validate_authority_reconciliation, validate_reconcile_authorization,
        validate_reconciliation_context, validate_reconciliation_envelope,
        validate_reconciliation_status,
    },
};

use super::{CertificateManager, builders, mapping, preflight::validate_authorization_lease};

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
    pub(crate) fn resolve_reconciliation(
        &mut self,
        query: &ReconciliationQueryV2,
        begin: &ReconciliationBeginV2,
        workload: &VerifiedWorkloadV2,
        expected_authorization: &VerifiedCertificateExecutionAuthorizationV2,
        signed: &SignedCertificateExecutionAuthorizationV2,
        context: ReconciliationContextV2,
        initial_time: u64,
    ) -> Result<ReconciliationResultV2, ManagerError> {
        validate_reconciliation_context(&self.config, begin, &context)?;
        if !matches!(
            context.status.state,
            AuditOperationState::Invoked
                | AuditOperationState::ResultUnknown
                | AuditOperationState::Finalized
        ) {
            return Ok(ReconciliationResultV2 {
                status: context.status,
                recovered_outcome: None,
            });
        }
        let authority_time = self.current_reconciliation_time(initial_time)?;
        let current_authorization = self
            .authorization_verifier
            .verify(signed)
            .map_err(mapping::authorization)?;
        validate_authorization_lease(signed, &current_authorization)?;
        validate_reconcile_authorization(
            &self.config,
            workload,
            query,
            &current_authorization,
            authority_time,
        )?;
        if &current_authorization != expected_authorization {
            return Err(ManagerError::ReconciliationRejected);
        }
        let readiness = self.verify_readiness(authority_time)?;
        let command =
            builders::authority_reconciliation_command(query, &context, &readiness, authority_time)
                .ok_or(ManagerError::ReconciliationRejected)?;
        let result = self
            .authority
            .reconcile(&command)
            .map_err(|_| ManagerError::AuthorityResultUnknown)?;
        validate_reconciliation_envelope(&self.config, &result)?;
        let observed_time = self.current_reconciliation_time(authority_time)?;
        let verified = self
            .outcome_verifier
            .verify_reconciliation(&result, &command)
            .map_err(|_| ManagerError::ReconciliationRejected)?;
        validate_authority_reconciliation(
            &self.config,
            &command,
            &result,
            &verified,
            observed_time,
        )?;
        if context.status.state == AuditOperationState::Finalized {
            return self.recover_finalized(&context, &result, &verified);
        }
        if result.disposition != AuthorityReconciliationDispositionV2::Completed {
            let resolution = ReconciliationStateResolutionV2 {
                verified: verified.clone(),
            };
            let status = self
                .state_store
                .resolve_reconciliation(&context, &resolution)
                .map_err(|_| ManagerError::ReconciliationRejected)?;
            if validate_reconciliation_status(&context, &verified, &status).is_err() {
                self.report_reconciliation_mismatch(&context, &verified, &status)?;
                return Err(ManagerError::ReconciliationRejected);
            }
            return Ok(ReconciliationResultV2 {
                status,
                recovered_outcome: None,
            });
        }
        self.complete_reconciliation(
            &begin.status_query,
            &context,
            &result,
            &verified,
            observed_time,
        )
    }
}
