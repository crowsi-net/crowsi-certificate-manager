use crate::{
    AuditStatusQueryV2, AuthorityOutcomeVerifierPort, AuthorityReadinessVerifierPort,
    AuthorityReconciliationDispositionV2, CertificateAuthorityPort,
    CertificateExecutionAuthorizationVerifierPort, ManagerError, OperationStateStorePort,
    PublicCertificateVerifierPort, ReconciliationContextV2, ReconciliationResultV2,
    ReconciliationStateResolutionV2, TrustedClock,
    validation::{validate_operation_commit, validate_reconciliation_status},
};

use super::{CertificateManager, builders, reconcile_support::finalized_status};

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
    pub(super) fn recover_finalized(
        &mut self,
        context: &ReconciliationContextV2,
        result: &crate::AuthorityReconciliationOutcomeV2,
        verified: &crate::VerifiedAuthorityReconciliationV2,
    ) -> Result<ReconciliationResultV2, ManagerError> {
        if result.disposition != AuthorityReconciliationDispositionV2::Completed {
            return Err(ManagerError::ReconciliationRejected);
        }
        let outcome = builders::recovered_outcome(result)
            .ok_or(ManagerError::ReconciliationRejected)?
            .clone();
        let original = context
            .authority_command
            .as_ref()
            .ok_or(ManagerError::ReconciliationRejected)?;
        let authority = self
            .verify_result(original, &context.reservation, &outcome)
            .map_err(|_| ManagerError::AuthorityResultUnknown)?;
        let receipt = context
            .finalized_receipt
            .as_ref()
            .ok_or(ManagerError::ReconciliationRejected)?;
        let exact = receipt.authority_outcome_digest_sha256 == outcome.digest_sha256()
            && receipt.authority_receipt_digest_sha256 == authority.receipt_digest_sha256
            && receipt.result_metadata_digest_sha256 == outcome.metadata.digest_sha256();
        if !exact {
            return Err(ManagerError::ReconciliationRejected);
        }
        let resolution = ReconciliationStateResolutionV2 {
            verified: verified.clone(),
        };
        let status = self
            .state_store
            .resolve_reconciliation(context, &resolution)
            .map_err(|_| ManagerError::ReconciliationRejected)?;
        if validate_reconciliation_status(context, verified, &status).is_err() {
            self.report_reconciliation_mismatch(context, verified, &status)?;
            return Err(ManagerError::ReconciliationRejected);
        }
        Ok(ReconciliationResultV2 {
            status,
            recovered_outcome: Some(outcome),
        })
    }

    pub(super) fn complete_reconciliation(
        &mut self,
        status_query: &AuditStatusQueryV2,
        context: &ReconciliationContextV2,
        result: &crate::AuthorityReconciliationOutcomeV2,
        reconciliation: &crate::VerifiedAuthorityReconciliationV2,
        now: u64,
    ) -> Result<ReconciliationResultV2, ManagerError> {
        let outcome = builders::recovered_outcome(result)
            .ok_or(ManagerError::ReconciliationRejected)?
            .clone();
        let original = context
            .authority_command
            .as_ref()
            .ok_or(ManagerError::ReconciliationRejected)?;
        let authority = self
            .verify_result(original, &context.reservation, &outcome)
            .map_err(|_| ManagerError::AuthorityResultUnknown)?;
        let receipt =
            builders::recovered_receipt(context, &outcome, &authority, reconciliation, now);
        let finalize = builders::recovered_finalize(
            context,
            &outcome,
            receipt.clone(),
            &reconciliation.completion_evidence,
        );
        let expected_revision = context
            .status
            .state_revision
            .checked_add(1)
            .ok_or(ManagerError::ReconciliationRejected)?;
        let commit = self
            .state_store
            .finalize_operation(&context.reservation, &finalize)
            .map_err(|_| ManagerError::AuthorityResultUnknown)?;
        if validate_operation_commit(&context.reservation, &receipt, &commit).is_err()
            || commit.state_revision != expected_revision
        {
            self.report_commit_mismatch(
                &context.reservation,
                &receipt,
                &commit,
                original.digest_sha256(),
            )?;
            return Err(ManagerError::AuthorityResultUnknown);
        }
        Ok(ReconciliationResultV2 {
            status: finalized_status(status_query, context, &receipt, commit.state_revision),
            recovered_outcome: Some(outcome),
        })
    }
}
