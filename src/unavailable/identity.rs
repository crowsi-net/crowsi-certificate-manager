use crate::{
    AuthorizationError, CertificateExecutionAuthorizationVerifierPort,
    KeyCustodyAttestationVerifierPort, KeyCustodyError, KeyEnrollmentError, KeyEnrollmentV2,
    KeyEnrollmentVerifierPort, SignedCertificateExecutionAuthorizationV2,
    SignedKeyCustodyAttestationV2, VerifiedCertificateExecutionAuthorizationV2,
    VerifiedKeyCustodyAttestationV2, VerifiedKeyEnrollmentV2, VerifiedWorkloadV2,
    WorkloadEvidenceV2, WorkloadIdentityError, WorkloadIdentityVerifierPort,
};

pub struct UnavailableWorkloadIdentityVerifier;
impl WorkloadIdentityVerifierPort for UnavailableWorkloadIdentityVerifier {
    fn verify(
        &mut self,
        _: &WorkloadEvidenceV2,
    ) -> Result<VerifiedWorkloadV2, WorkloadIdentityError> {
        Err(WorkloadIdentityError::Unavailable)
    }
}

pub struct UnavailableCertificateExecutionAuthorizationVerifier;
impl CertificateExecutionAuthorizationVerifierPort
    for UnavailableCertificateExecutionAuthorizationVerifier
{
    fn verify(
        &mut self,
        _: &SignedCertificateExecutionAuthorizationV2,
    ) -> Result<VerifiedCertificateExecutionAuthorizationV2, AuthorizationError> {
        Err(AuthorizationError::Unavailable)
    }
}

pub struct UnavailableKeyEnrollmentVerifier;
impl KeyEnrollmentVerifierPort for UnavailableKeyEnrollmentVerifier {
    fn verify(
        &mut self,
        _: &KeyEnrollmentV2,
    ) -> Result<VerifiedKeyEnrollmentV2, KeyEnrollmentError> {
        Err(KeyEnrollmentError::Unavailable)
    }
}

pub struct UnavailableKeyCustodyAttestationVerifier;
impl KeyCustodyAttestationVerifierPort for UnavailableKeyCustodyAttestationVerifier {
    fn verify(
        &mut self,
        _: &SignedKeyCustodyAttestationV2,
    ) -> Result<VerifiedKeyCustodyAttestationV2, KeyCustodyError> {
        Err(KeyCustodyError::Unavailable)
    }
}
