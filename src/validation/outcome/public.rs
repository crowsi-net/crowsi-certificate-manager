use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{AuthorityOutcomeV2, CertificateManagerConfig};

use super::super::common::{valid_digest, valid_encoded, valid_id};

pub fn valid_public_bytes(config: &CertificateManagerConfig, outcome: &AuthorityOutcomeV2) -> bool {
    let Some(value) = &outcome.public_certificate else {
        return false;
    };
    let Some(leaf) = STANDARD.decode(&value.certificate_der_base64).ok() else {
        return false;
    };
    let chain = value
        .chain_der_base64
        .iter()
        .map(|item| STANDARD.decode(item).ok())
        .collect::<Option<Vec<_>>>();
    let Some(chain) = chain else {
        return false;
    };
    let size = chain
        .iter()
        .try_fold(leaf.len(), |size, item| size.checked_add(item.len()));
    !leaf.is_empty()
        && !chain.is_empty()
        && chain.len() <= 8
        && chain.iter().all(|item| !item.is_empty())
        && size.is_some_and(|value| value <= config.max_public_certificate_bytes)
        && crate::digest::sha256(&leaf) == value.metadata.fingerprint_sha256
        && value.metadata == outcome.metadata
}

pub fn encoded_certificate_within_limit(
    config: &CertificateManagerConfig,
    value: &crate::PublicCertificateV2,
) -> bool {
    if value.chain_der_base64.is_empty() || value.chain_der_base64.len() > 8 {
        return false;
    }
    let encoded_limit = config.max_public_certificate_bytes.saturating_mul(2);
    std::iter::once(&value.certificate_der_base64)
        .chain(value.chain_der_base64.iter())
        .try_fold(0_usize, |size, item| {
            valid_encoded(item, encoded_limit)
                .then(|| size.checked_add(item.len()))
                .flatten()
        })
        .is_some_and(|size| size <= encoded_limit)
}

pub fn metadata_envelope(value: &crate::CertificateMetadataV2) -> bool {
    valid_id(&value.certificate_id)
        && (1..=128).contains(&value.serial_number.len())
        && valid_digest(&value.fingerprint_sha256)
        && valid_digest(&value.public_key_sha256)
        && (1..=64).contains(&value.public_key_algorithm.len())
}
