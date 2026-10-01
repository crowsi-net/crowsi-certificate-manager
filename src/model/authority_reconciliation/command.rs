use crate::digest::DigestBuilder;

use super::{OriginalAuthorityExecutionBindingV2, ReconciliationAuthorityBindingV2};

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityReconciliationCommandV2 {
    pub query_id: String,
    pub authorization_jti: String,
    pub authorization_operation_id: String,
    pub authorization_lease_digest_sha256: String,
    pub authorization_command_digest_sha256: String,
    pub original_action: super::super::CertificateLifecycleActionV2,
    pub original_authorization_jti: String,
    pub original_authorization_operation_id: String,
    pub original_authorization_lease_digest_sha256: String,
    pub target_request_id: String,
    pub resource_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub authority_command_digest_sha256: String,
    pub unknown_evidence_digest_sha256: String,
    pub reconciliation_authorization_ancestry_digest_sha256: String,
    pub reconciliation_query_digest_sha256: String,
    pub expected_resource_version: u64,
    pub authorization_previous_fence: u64,
    pub authorization_current_fence: u64,
    pub authorization_previous_lifecycle_revocation_epoch: u64,
    pub authorization_lifecycle_revocation_epoch: u64,
    pub original_execution: OriginalAuthorityExecutionBindingV2,
    pub current_reconciliation: ReconciliationAuthorityBindingV2,
    pub lifecycle_reservation_id: String,
    pub lifecycle_previous_fence: u64,
    pub lifecycle_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub requested_at_epoch_s: u64,
}

impl AuthorityReconciliationCommandV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-authority-reconciliation-command-v2");
        for value in [
            &self.query_id,
            &self.authorization_jti,
            &self.authorization_operation_id,
            &self.authorization_lease_digest_sha256,
            &self.authorization_command_digest_sha256,
            self.original_action.as_str(),
            &self.original_authorization_jti,
            &self.original_authorization_operation_id,
            &self.original_authorization_lease_digest_sha256,
            &self.target_request_id,
            &self.resource_id,
            &self.security_domain,
            &self.deployment_id,
            &self.authority_command_digest_sha256,
            &self.unknown_evidence_digest_sha256,
            &self.reconciliation_authorization_ancestry_digest_sha256,
            &self.reconciliation_query_digest_sha256,
            &self.lifecycle_reservation_id,
        ] {
            digest.text(value);
        }
        add_original(&mut digest, &self.original_execution);
        add_current(&mut digest, &self.current_reconciliation);
        for value in [
            self.lifecycle_previous_fence,
            self.lifecycle_fence,
            self.authorization_previous_fence,
            self.authorization_current_fence,
            self.authorization_previous_lifecycle_revocation_epoch,
            self.authorization_lifecycle_revocation_epoch,
            self.previous_lifecycle_revocation_epoch,
            self.lifecycle_revocation_epoch,
            self.expected_resource_version,
            self.requested_at_epoch_s,
        ] {
            digest.number(value);
        }
        digest.finish()
    }
}

fn add_original(digest: &mut DigestBuilder, value: &OriginalAuthorityExecutionBindingV2) {
    for item in [
        &value.authority_id,
        &value.certificate_signing_key_id,
        &value.certificate_signing_key_version,
        &value.certificate_signing_public_key_spki_sha256,
        &value.receipt_signing_key_id,
        &value.receipt_signing_key_version,
        &value.receipt_signing_public_key_spki_sha256,
        &value.lease_id,
        &value.attestation_digest_sha256,
    ] {
        digest.text(item);
    }
    digest.number(value.trust_revision);
    digest.number(value.fence);
}

fn add_current(digest: &mut DigestBuilder, value: &ReconciliationAuthorityBindingV2) {
    for item in [
        &value.authority_id,
        &value.certificate_signing_key_id,
        &value.certificate_signing_key_version,
        &value.certificate_signing_public_key_spki_sha256,
        &value.receipt_signing_key_id,
        &value.receipt_signing_key_version,
        &value.receipt_signing_public_key_spki_sha256,
        &value.receipt_signature_algorithm,
        &value.receipt_key_purpose,
        &value.lease_id,
        &value.attestation_digest_sha256,
    ] {
        digest.text(item);
    }
    digest.number(value.trust_revision);
    digest.number(value.fence);
    digest.number(value.expires_at_epoch_s);
}
