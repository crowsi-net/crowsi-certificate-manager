use crate::{
    AuthorityOutcomeVerifierPort, AuthorityReadinessVerifierPort, CertificateAuthorityPort,
    CertificateCommandV2, CertificateExecutionAuthorizationVerifierPort, CertificateOperation,
    CertificateResponseV2, KeyCustodyAttestationVerifierPort, KeyEnrollmentVerifierPort,
    ManagerError, OperationStateStorePort, PublicCertificateVerifierPort,
    SignedCertificateExecutionAuthorizationV2, SignedKeyCustodyAttestationV2, TrustedClock,
    WorkloadEvidenceV2, WorkloadIdentityVerifierPort,
};

use super::CertificateManager;

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
    /// Executes issue, renew, or revoke; certificate status has a distinct API.
    ///
    /// # Errors
    ///
    /// Rejects status and every unverified or ambiguous lifecycle transition.
    pub fn execute_mutation(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        command: &CertificateCommandV2,
        authorization: &SignedCertificateExecutionAuthorizationV2,
        custody: Option<&SignedKeyCustodyAttestationV2>,
    ) -> Result<CertificateResponseV2, ManagerError> {
        if command.operation == CertificateOperation::Status {
            return Err(ManagerError::InvalidCommand);
        }
        self.execute_authorized(evidence, command, authorization, custody)
    }

    /// Reads a certificate resource through a non-mutating CA status command.
    ///
    /// # Errors
    ///
    /// Requires the exact `certificate-status` authorization and forbids custody input.
    pub fn certificate_status(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        command: &CertificateCommandV2,
        authorization: &SignedCertificateExecutionAuthorizationV2,
    ) -> Result<CertificateResponseV2, ManagerError> {
        if command.operation != CertificateOperation::Status {
            return Err(ManagerError::InvalidCommand);
        }
        self.execute_authorized(evidence, command, authorization, None)
    }
}
