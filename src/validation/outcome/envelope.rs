use crate::{AuthorityOutcomeV2, CertificateManagerConfig, ManagerError};

use super::{
    super::common::{valid_encoded, valid_id},
    public::{encoded_certificate_within_limit, metadata_envelope},
};

pub fn validate_outcome_envelope(
    config: &CertificateManagerConfig,
    outcome: &AuthorityOutcomeV2,
) -> Result<(), ManagerError> {
    let signed = &outcome.signed_receipt;
    let signed_shape = valid_id(&signed.key_id)
        && valid_encoded(&signed.payload_base64, 262_144)
        && valid_encoded(&signed.signature_base64, 16_384);
    let metadata_shape = metadata_envelope(&outcome.metadata);
    let certificate_shape = outcome.public_certificate.as_ref().is_none_or(|value| {
        metadata_envelope(&value.metadata)
            && value.metadata == outcome.metadata
            && encoded_certificate_within_limit(config, value)
    });
    (signed_shape && metadata_shape && certificate_shape)
        .then_some(())
        .ok_or(ManagerError::AuthorityResultUnknown)
}
