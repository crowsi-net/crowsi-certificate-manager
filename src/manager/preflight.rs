use crate::{
    AuthorityReadinessVerifierPort, CertificateAuthorityPort, CertificateCommandV2,
    CertificateExecutionAuthorizationVerifierPort, KeyCustodyAttestationVerifierPort,
    KeyEnrollmentVerifierPort, ManagerError, SignedCertificateExecutionAuthorizationV2,
    SignedKeyCustodyAttestationV2, TrustedClock, WorkloadEvidenceV2, WorkloadIdentityVerifierPort,
    validation::{
        validate_command, validate_command_authorization, validate_config, validate_key_enrollment,
        validate_signed_authorization, validate_workload, validate_workload_evidence,
    },
};

use super::{CertificateManager, PreparedV2, mapping};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    A: CertificateAuthorityPort,
    R: AuthorityReadinessVerifierPort,
    W: WorkloadIdentityVerifierPort,
    P: CertificateExecutionAuthorizationVerifierPort,
    K: KeyEnrollmentVerifierPort,
    C: KeyCustodyAttestationVerifierPort,
    T: TrustedClock,
{
    pub(crate) fn preflight(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        command: &CertificateCommandV2,
        signed_authorization: &SignedCertificateExecutionAuthorizationV2,
        signed_custody: Option<&SignedKeyCustodyAttestationV2>,
    ) -> Result<PreparedV2, ManagerError> {
        validate_config(&self.config)?;
        validate_workload_evidence(&self.config, evidence)?;
        validate_command(&self.config, command)?;
        validate_signed_authorization(&self.config, signed_authorization)?;
        if command.operation.requires_key_enrollment() != signed_custody.is_some() {
            return Err(ManagerError::InvalidCommand);
        }
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
            .verify(signed_authorization)
            .map_err(mapping::authorization)?;
        validate_authorization_lease(signed_authorization, &authorization)?;
        validate_command_authorization(&self.config, &workload, command, &authorization, now)?;
        let enrollment = command
            .key_enrollment
            .as_ref()
            .map(|value| {
                self.enrollment_verifier
                    .verify(value)
                    .map_err(mapping::enrollment)
            })
            .transpose()?;
        if let Some(value) = &enrollment {
            validate_key_enrollment(&self.config, value)?;
        }
        let custody = self.verify_custody(
            signed_custody,
            enrollment.as_ref(),
            &workload,
            &command.digest_sha256(),
            now,
        )?;
        let readiness = self.verify_readiness(now)?;
        Ok(PreparedV2 {
            workload,
            authorization,
            enrollment,
            custody,
            initial_readiness: readiness.clone(),
            readiness,
            initial_time_epoch_s: now,
        })
    }
}

pub(crate) fn validate_authorization_lease(
    signed: &SignedCertificateExecutionAuthorizationV2,
    value: &crate::VerifiedCertificateExecutionAuthorizationV2,
) -> Result<(), ManagerError> {
    (signed.lease_digest_sha256() == value.lease_digest_sha256)
        .then_some(())
        .ok_or(ManagerError::AuthorizationBindingRejected)
}
