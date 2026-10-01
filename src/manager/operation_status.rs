use crate::{
    AuditOperationStatusV2, AuditStatusQueryV2, CertificateExecutionAuthorizationVerifierPort,
    ManagerError, OperationStateStorePort, OperationStatusBeginV2, OperationStatusQueryV2,
    SignedCertificateExecutionAuthorizationV2, TrustedClock, WorkloadEvidenceV2,
    WorkloadIdentityVerifierPort,
    validation::{
        validate_audit_status, validate_config, validate_operation_status_authorization,
        validate_operation_status_query, validate_signed_authorization, validate_workload,
        validate_workload_evidence,
    },
};

use super::{CertificateManager, mapping, preflight::validate_authorization_lease};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    W: WorkloadIdentityVerifierPort,
    P: CertificateExecutionAuthorizationVerifierPort,
    S: OperationStateStorePort,
    T: TrustedClock,
{
    /// Reads operation state without access to the authority reconciliation path.
    ///
    /// # Errors
    ///
    /// Requires a fresh one-use `operation-status` authorization for the exact owner.
    pub fn operation_status(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        query: &OperationStatusQueryV2,
        signed: &SignedCertificateExecutionAuthorizationV2,
    ) -> Result<AuditOperationStatusV2, ManagerError> {
        validate_config(&self.config)?;
        validate_workload_evidence(&self.config, evidence)?;
        validate_operation_status_query(query)?;
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
        validate_operation_status_authorization(
            &self.config,
            &workload,
            query,
            &authorization,
            now,
        )?;
        let status_query = AuditStatusQueryV2 {
            target_request_id: query.target_request_id.clone(),
            resource_id: query.resource_id.clone(),
            owner_service_id: workload.service_id,
            owner_workload_id: workload.workload_id,
            owner_subject: workload.pairwise_subject,
            owner_profile: workload.profile,
            operation_expected_resource_version: query.expected_resource_version,
            operation_lifecycle_revocation_epoch: query.expected_lifecycle_revocation_epoch,
        };
        let begin = OperationStatusBeginV2 {
            query_id: query.query_id.clone(),
            nonce: query.nonce.clone(),
            authorization_id: authorization.authorization_id,
            authorization_jti: authorization.jti,
            authorization_lease_digest_sha256: authorization.lease_digest_sha256,
            query_digest_sha256: query.digest_sha256(),
            expected_resource_version: query.expected_resource_version,
            expected_lifecycle_revocation_epoch: query.expected_lifecycle_revocation_epoch,
            status_query: status_query.clone(),
        };
        let status = self
            .state_store
            .operation_status(&begin)
            .map_err(mapping::reconcile)?;
        validate_audit_status(&status_query, &status)?;
        Ok(status)
    }
}
