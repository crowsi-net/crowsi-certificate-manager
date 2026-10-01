use crate::{
    AuthorityCommandV2, AuthorityError, AuthorityOutcomeError, AuthorityOutcomeV2,
    AuthorityReadinessV2, AuthorityReconciliationCommandV2, AuthorityReconciliationOutcomeV2,
    PublicCertificateError, PublicCertificateV2, SignedAuthorityReadinessAttestationV2,
    VerifiedAuthorityOutcomeReceiptV2, VerifiedAuthorityReconciliationV2,
    VerifiedPublicCertificateV2,
};

pub trait CertificateAuthorityPort {
    /// Returns a short-lived lease over the exact authority and signing key.
    ///
    /// # Errors
    ///
    /// Fails unless readiness and key attestation can be proven.
    fn readiness(&mut self) -> Result<SignedAuthorityReadinessAttestationV2, AuthorityError>;

    /// Executes an immutable command carrying the readiness and lifecycle fences.
    /// The adapter must use trusted time to reject an expired authority lease or
    /// custody attestation before journaling or invoking key hardware. Only the
    /// PA authorization expiry may be crossed by bounded manager recovery.
    /// The adapter accepts only the pinned 64-byte P1363 low-S provider profile,
    /// converts that verified signature to canonical X.509 DER ECDSA-Sig-Value,
    /// and preserves the exact TBS digest, signing SPKI, and opaque key version.
    ///
    /// # Errors
    ///
    /// Distinguishes a definite rejection from an ambiguous result.
    fn execute(
        &mut self,
        command: &AuthorityCommandV2,
        invoked_at_epoch_s: u64,
    ) -> Result<AuthorityOutcomeV2, AuthorityError>;

    /// Queries the authority journal without re-executing an operation.
    ///
    /// # Errors
    ///
    /// Fails closed when the authority cannot prove its recorded disposition.
    fn reconcile(
        &mut self,
        command: &AuthorityReconciliationCommandV2,
    ) -> Result<AuthorityReconciliationOutcomeV2, AuthorityError>;
}

pub trait AuthorityReadinessVerifierPort {
    /// Independently verifies the signed readiness lease against pinned trust.
    ///
    /// # Errors
    ///
    /// Rejects self-asserted or stale authority/key-provider readiness.
    fn verify(
        &mut self,
        signed: &SignedAuthorityReadinessAttestationV2,
    ) -> Result<AuthorityReadinessV2, AuthorityOutcomeError>;
}

pub trait AuthorityOutcomeVerifierPort {
    /// Independently verifies the signed authority receipt and all echoed bindings.
    ///
    /// # Errors
    ///
    /// Fails if an independent verifier or current trust material is unavailable.
    fn verify(
        &mut self,
        outcome: &AuthorityOutcomeV2,
        command: &AuthorityCommandV2,
    ) -> Result<VerifiedAuthorityOutcomeReceiptV2, AuthorityOutcomeError>;

    /// Independently verifies a signed non-executing reconciliation result.
    ///
    /// # Errors
    ///
    /// Rejects mismatched command, disposition, outcome digest, or signing key.
    fn verify_reconciliation(
        &mut self,
        outcome: &AuthorityReconciliationOutcomeV2,
        command: &AuthorityReconciliationCommandV2,
    ) -> Result<VerifiedAuthorityReconciliationV2, AuthorityOutcomeError>;
}

pub trait PublicCertificateVerifierPort {
    /// Parses and verifies a returned certificate chain against the requested profile.
    /// ECDSA certificates must use canonical DER and a low-S signature; variable
    /// length provider output, high-S values, and a changed TBS/key binding fail.
    ///
    /// # Errors
    ///
    /// Rejects invalid DER, fingerprint, chain, key, or profile bindings.
    fn verify(
        &mut self,
        certificate: &PublicCertificateV2,
        command: &AuthorityCommandV2,
    ) -> Result<VerifiedPublicCertificateV2, PublicCertificateError>;
}
