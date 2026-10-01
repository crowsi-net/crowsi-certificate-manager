use crate::digest::DigestBuilder;

use super::CertificateOperation;

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityCommandV2 {
    pub request_id: String,
    pub management_command_digest_sha256: String,
    pub authorization_id: String,
    pub authorization_jti: String,
    pub authorization_operation_id: String,
    pub authorization_lease_digest_sha256: String,
    pub operation: CertificateOperation,
    pub security_domain: String,
    pub deployment_id: String,
    pub service_id: String,
    pub workload_id: String,
    pub device_id: String,
    pub profile_id: String,
    pub purpose: String,
    pub subject: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub resource_id: String,
    pub target_certificate_id: Option<String>,
    pub prior_metadata_digest_sha256: Option<String>,
    pub public_key_spki_der: Option<Vec<u8>>,
    pub public_key_sha256: Option<String>,
    pub public_key_algorithm: Option<String>,
    pub custody_attestation_digest_sha256: Option<String>,
    pub expected_resource_version: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub identity_revocation_epoch: u64,
    pub lifecycle_reservation_id: String,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub authority_lease_id: String,
    pub authority_attestation_digest_sha256: String,
    pub authority_fence: u64,
    pub authority_id: String,
    pub authority_key_id: String,
    pub authority_key_version: String,
    pub authority_public_key_spki_sha256: String,
    pub authority_signature_algorithm: String,
    pub authority_key_provider_signature_profile: String,
    pub authority_key_purpose: String,
    pub authority_receipt_key_id: String,
    pub authority_receipt_key_version: String,
    pub authority_receipt_public_key_spki_sha256: String,
    pub authority_receipt_signature_algorithm: String,
    pub authority_receipt_key_purpose: String,
    pub authority_trust_revision: u64,
    pub authorization_expires_at_epoch_s: u64,
    pub custody_expires_at_epoch_s: Option<u64>,
    pub authority_lease_expires_at_epoch_s: u64,
    pub execution_time_epoch_s: u64,
    pub certificate_expires_at_epoch_s: u64,
}

impl AuthorityCommandV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-authority-command-v2");
        for value in [
            &self.request_id,
            &self.management_command_digest_sha256,
            &self.authorization_id,
            &self.authorization_jti,
            &self.authorization_operation_id,
            &self.authorization_lease_digest_sha256,
            self.operation.as_str(),
            &self.security_domain,
            &self.deployment_id,
            &self.service_id,
            &self.workload_id,
            &self.device_id,
            &self.profile_id,
            &self.purpose,
            &self.subject,
            &self.audience,
            &self.resource_id,
        ] {
            digest.text(value);
        }
        digest.number(u64::try_from(self.scopes.len()).unwrap_or(u64::MAX));
        for scope in &self.scopes {
            digest.text(scope);
        }
        digest.optional(self.target_certificate_id.as_deref());
        digest.optional(self.prior_metadata_digest_sha256.as_deref());
        digest.bytes(self.public_key_spki_der.as_deref().unwrap_or_default());
        digest.optional(self.public_key_sha256.as_deref());
        digest.optional(self.public_key_algorithm.as_deref());
        digest.optional(self.custody_attestation_digest_sha256.as_deref());
        digest.number(self.expected_resource_version);
        digest.number(self.previous_lifecycle_revocation_epoch);
        digest.number(self.lifecycle_revocation_epoch);
        digest.number(self.identity_revocation_epoch);
        for value in [
            &self.lifecycle_reservation_id,
            &self.authority_lease_id,
            &self.authority_attestation_digest_sha256,
            &self.authority_id,
            &self.authority_key_id,
            &self.authority_key_version,
            &self.authority_public_key_spki_sha256,
            &self.authority_signature_algorithm,
            &self.authority_key_provider_signature_profile,
            &self.authority_key_purpose,
            &self.authority_receipt_key_id,
            &self.authority_receipt_key_version,
            &self.authority_receipt_public_key_spki_sha256,
            &self.authority_receipt_signature_algorithm,
            &self.authority_receipt_key_purpose,
        ] {
            digest.text(value);
        }
        for value in [
            self.previous_fence,
            self.current_fence,
            self.authority_fence,
            self.authority_trust_revision,
            self.authorization_expires_at_epoch_s,
            self.custody_expires_at_epoch_s.unwrap_or(0),
            self.authority_lease_expires_at_epoch_s,
            self.execution_time_epoch_s,
            self.certificate_expires_at_epoch_s,
        ] {
            digest.number(value);
        }
        digest.finish()
    }
}
