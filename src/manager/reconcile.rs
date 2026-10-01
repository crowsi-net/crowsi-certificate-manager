use crate::{
    AuditStatusQueryV2, AuthorityReadinessVerifierPort, CertificateAuthorityPort,
    CertificateExecutionAuthorizationVerifierPort, ManagerError, OperationStateStorePort,
    ReconciliationBeginV2, ReconciliationQueryV2, ReconciliationResultV2,
    SignedCertificateExecutionAuthorizationV2, TrustedClock, WorkloadEvidenceV2,
    WorkloadIdentityVerifierPort,
    validation::{
        validate_config, validate_reconcile_authorization, validate_reconciliation_query,
        validate_signed_authorization, validate_workload, validate_workload_evidence,
    },
};

use super::{CertificateManager, mapping, preflight::validate_authorization_lease};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    A: CertificateAuthorityPort,
    R: AuthorityReadinessVerifierPort,
    W: WorkloadIdentityVerifierPort,
    P: CertificateExecutionAuthorizationVerifierPort,
    S: OperationStateStorePort,
    T: TrustedClock,
{
    /// Reconciles an owner-scoped operation with fresh one-use PA authorization.
    ///
    /// # Errors
    ///
    /// Cross-owner, replayed, stale, or unverifiable resolutions fail closed.
    pub fn reconcile_unknown(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        query: &ReconciliationQueryV2,
        signed: &SignedCertificateExecutionAuthorizationV2,
    ) -> Result<ReconciliationResultV2, ManagerError>
    where
        V: crate::PublicCertificateVerifierPort,
        O: crate::AuthorityOutcomeVerifierPort,
    {
        validate_config(&self.config)?;
        validate_workload_evidence(&self.config, evidence)?;
        validate_reconciliation_query(query)?;
        validate_signed_authorization(&self.config, signed)?;
        let workload = self
            .workload_verifier
            .verify(evidence)
            .map_err(mapping::workload)?;
        let now = self
            .clock
            .now_epoch_s()
            .map_err(|_| ManagerError::TrustedTimeRejected)?;
        validate_workload(&self.config, &workload, now)?;
        let authorization = self
            .authorization_verifier
            .verify(signed)
            .map_err(mapping::authorization)?;
        validate_authorization_lease(signed, &authorization)?;
        validate_reconcile_authorization(&self.config, &workload, query, &authorization, now)?;
        let status_query = AuditStatusQueryV2 {
            target_request_id: query.target_request_id.clone(),
            resource_id: query.resource_id.clone(),
            owner_service_id: workload.service_id.clone(),
            owner_workload_id: workload.workload_id.clone(),
            owner_subject: workload.pairwise_subject.clone(),
            owner_profile: workload.profile.clone(),
            operation_expected_resource_version: query.expected_resource_version,
            operation_lifecycle_revocation_epoch: query.locked_lifecycle_revocation_epoch,
        };
        let begin = ReconciliationBeginV2 {
            query_id: query.query_id.clone(),
            original_action: query.original_action,
            nonce: query.nonce.clone(),
            authorization_id: authorization.authorization_id.clone(),
            authorization_jti: authorization.jti.clone(),
            authorization: crate::CertificateAuthorizationAncestryV2::from_verified(
                &authorization,
                &workload,
            ),
            authorization_command_digest_sha256: authorization.command_digest_sha256.clone(),
            query_digest_sha256: query.digest_sha256(),
            expected_resource_version: query.expected_resource_version,
            expected_authority_command_digest_sha256: query
                .expected_authority_command_digest_sha256
                .clone(),
            expected_unknown_evidence_digest_sha256: query
                .expected_unknown_evidence_digest_sha256
                .clone(),
            expected_lifecycle_reservation_id: query.expected_lifecycle_reservation_id.clone(),
            expected_previous_fence: query.expected_previous_fence,
            expected_current_fence: query.expected_current_fence,
            locked_previous_lifecycle_revocation_epoch: query
                .locked_previous_lifecycle_revocation_epoch,
            locked_lifecycle_revocation_epoch: query.locked_lifecycle_revocation_epoch,
            status_query: status_query.clone(),
        };
        let context = self
            .state_store
            .begin_reconciliation(&begin)
            .map_err(mapping::reconcile)?;
        self.resolve_reconciliation(
            query,
            &begin,
            &workload,
            &authorization,
            signed,
            context,
            now,
        )
    }
}
