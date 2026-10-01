use crate::{
    AuthorityCommandV2, AuthorityOutcomeV2, AuthorityOutcomeVerifierPort, CertificateManagerConfig,
    ManagerError, OperationReservationV2, PublicCertificateVerifierPort,
    VerifiedAuthorityOutcomeReceiptV2,
    validation::{valid_public_bytes, validate_outcome, validate_outcome_envelope},
};

use super::CertificateManager;

#[derive(Clone, Copy)]
pub(crate) enum ResultVerificationError {
    Outcome,
    Certificate,
}

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    V: PublicCertificateVerifierPort,
    O: AuthorityOutcomeVerifierPort,
{
    pub(crate) fn verify_result(
        &mut self,
        command: &AuthorityCommandV2,
        reservation: &OperationReservationV2,
        outcome: &AuthorityOutcomeV2,
    ) -> Result<VerifiedAuthorityOutcomeReceiptV2, ResultVerificationError> {
        validate_outcome_envelope(&self.config, outcome)
            .map_err(|_| ResultVerificationError::Outcome)?;
        let receipt = self
            .outcome_verifier
            .verify(outcome, command)
            .map_err(|_| ResultVerificationError::Outcome)?;
        validate_outcome(&self.config, command, reservation, outcome, &receipt)
            .map_err(|_| ResultVerificationError::Outcome)?;
        if command.operation.requires_key_enrollment() {
            verify_public_certificate(
                &self.config,
                &mut self.certificate_verifier,
                command,
                outcome,
            )
            .map_err(|_| ResultVerificationError::Certificate)?;
        }
        Ok(receipt)
    }
}

fn verify_public_certificate<V: PublicCertificateVerifierPort>(
    config: &CertificateManagerConfig,
    verifier: &mut V,
    command: &AuthorityCommandV2,
    outcome: &AuthorityOutcomeV2,
) -> Result<(), ManagerError> {
    if !valid_public_bytes(config, outcome) {
        return Err(ManagerError::AuthorityResultUnknown);
    }
    let certificate = outcome
        .public_certificate
        .as_ref()
        .ok_or(ManagerError::AuthorityResultUnknown)?;
    let certificate_claims = verifier
        .verify(certificate, command)
        .map_err(|_| ManagerError::AuthorityResultUnknown)?;
    let exact = certificate_claims.chain_verified
        && certificate_claims.profile_verified
        && certificate_claims.fingerprint_verified
        && certificate_claims.signature_encoding == "x509-der-ecdsa-sig-value"
        && certificate_claims.signature_canonical
        && certificate_claims.high_s_rejected
        && crate::validation::valid_digest(&certificate_claims.tbs_certificate_digest_sha256)
        && certificate_claims.signing_key_version == command.authority_key_version
        && certificate_claims.signing_public_key_spki_sha256
            == command.authority_public_key_spki_sha256
        && certificate_claims.metadata_digest_sha256 == outcome.metadata.digest_sha256();
    exact
        .then_some(())
        .ok_or(ManagerError::AuthorityResultUnknown)
}
