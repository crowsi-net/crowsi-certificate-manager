use crate::{CertificateManagerConfig, ManagerError, SignedCertificateExecutionAuthorizationV2};

use super::super::common::{valid_digest, valid_encoded};

pub fn validate_signed_authorization(
    config: &CertificateManagerConfig,
    signed: &SignedCertificateExecutionAuthorizationV2,
) -> Result<(), ManagerError> {
    let (schema, key, lease, lease_digest, signature) = signed.parts();
    let valid = schema == "crowsi://certificates/execution-authorization/v2"
        && key == config.authorization_verifier_key_id
        && valid_encoded(lease, 524_288)
        && valid_digest(lease_digest)
        && valid_encoded(signature, 16_384);
    valid
        .then_some(())
        .ok_or(ManagerError::AuthorizationBindingRejected)
}
