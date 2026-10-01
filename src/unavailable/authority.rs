use crate::{
    AuthorityCommandV2, AuthorityError, AuthorityOutcomeError, AuthorityOutcomeV2,
    AuthorityOutcomeVerifierPort, AuthorityReadinessV2, AuthorityReadinessVerifierPort,
    AuthorityReconciliationCommandV2, AuthorityReconciliationOutcomeV2, CertificateAuthorityPort,
    PublicCertificateError, PublicCertificateV2, PublicCertificateVerifierPort,
    SignedAuthorityReadinessAttestationV2, VerifiedAuthorityOutcomeReceiptV2,
    VerifiedAuthorityReconciliationV2, VerifiedPublicCertificateV2,
};

pub struct UnavailableAuthorityReadinessVerifier;
impl AuthorityReadinessVerifierPort for UnavailableAuthorityReadinessVerifier {
    fn verify(
        &mut self,
        _: &SignedAuthorityReadinessAttestationV2,
    ) -> Result<AuthorityReadinessV2, AuthorityOutcomeError> {
        Err(AuthorityOutcomeError::Unavailable)
    }
}

pub struct UnavailableAuthorityOutcomeVerifier;
impl AuthorityOutcomeVerifierPort for UnavailableAuthorityOutcomeVerifier {
    fn verify(
        &mut self,
        _: &AuthorityOutcomeV2,
        _: &AuthorityCommandV2,
    ) -> Result<VerifiedAuthorityOutcomeReceiptV2, AuthorityOutcomeError> {
        Err(AuthorityOutcomeError::Unavailable)
    }

    fn verify_reconciliation(
        &mut self,
        _: &AuthorityReconciliationOutcomeV2,
        _: &AuthorityReconciliationCommandV2,
    ) -> Result<VerifiedAuthorityReconciliationV2, AuthorityOutcomeError> {
        Err(AuthorityOutcomeError::Unavailable)
    }
}

pub struct UnavailablePublicCertificateVerifier;
impl PublicCertificateVerifierPort for UnavailablePublicCertificateVerifier {
    fn verify(
        &mut self,
        _: &PublicCertificateV2,
        _: &AuthorityCommandV2,
    ) -> Result<VerifiedPublicCertificateV2, PublicCertificateError> {
        Err(PublicCertificateError::Unavailable)
    }
}

pub struct UnavailableCertificateAuthority;
impl CertificateAuthorityPort for UnavailableCertificateAuthority {
    fn readiness(&mut self) -> Result<SignedAuthorityReadinessAttestationV2, AuthorityError> {
        Err(AuthorityError::Unavailable)
    }

    fn execute(
        &mut self,
        _: &AuthorityCommandV2,
        _: u64,
    ) -> Result<AuthorityOutcomeV2, AuthorityError> {
        Err(AuthorityError::Unavailable)
    }

    fn reconcile(
        &mut self,
        _: &AuthorityReconciliationCommandV2,
    ) -> Result<AuthorityReconciliationOutcomeV2, AuthorityError> {
        Err(AuthorityError::Unavailable)
    }
}
