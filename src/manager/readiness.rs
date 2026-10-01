use crate::{
    AuthorityReadinessVerifierPort, CertificateAuthorityPort, ManagerError,
    validation::{validate_readiness, validate_signed_readiness},
};

use super::{CertificateManager, mapping};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    A: CertificateAuthorityPort,
    R: AuthorityReadinessVerifierPort,
{
    pub(crate) fn verify_readiness(
        &mut self,
        now: u64,
    ) -> Result<crate::AuthorityReadinessV2, ManagerError> {
        let signed = self.authority.readiness().map_err(mapping::readiness)?;
        validate_signed_readiness(&self.config, &signed)?;
        let value = self
            .readiness_verifier
            .verify(&signed)
            .map_err(|_| ManagerError::AuthorityUnavailable)?;
        validate_readiness(&self.config, &value, now)?;
        Ok(value)
    }
}
