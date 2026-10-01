use super::CertificateAuthorizationAncestryV2;
use crate::digest::DigestBuilder;

impl CertificateAuthorizationAncestryV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-authorization-ancestry-v2");
        for value in [
            &self.operation_id,
            &self.authorization_command_digest_sha256,
            &self.lease_digest_sha256,
            &self.signature_key_version,
            &self.signature_public_key_spki_sha256,
            &self.signature_key_purpose,
            &self.security_domain,
            &self.deployment_id,
            &self.release_id,
            &self.release_digest_sha256,
            &self.checkpoint_id,
            &self.checkpoint_digest_sha256,
            &self.deployment_provenance_ref,
            &self.pa_reservation_id,
            &self.policy_id,
            &self.policy_digest_sha256,
            &self.decision_id,
            &self.decision_digest_sha256,
            &self.grant_id,
            &self.grant_digest_sha256,
            &self.identity_revocation_snapshot_id,
            &self.identity_revocation_snapshot_digest_sha256,
            &self.requester_pairwise_subject,
            &self.requester_profile,
            &self.requester_device,
            &self.requester_actor,
            &self.requester_proof_key_ref,
            &self.workload_evidence_sha256,
            &self.target_resource_normalizer_id,
            &self.target_resource_normalizer_version,
            &self.target_resource_normalization_digest_sha256,
        ] {
            digest.text(value);
        }
        for value in [
            self.approver_pairwise_subject.as_deref(),
            self.approver_profile.as_deref(),
            self.approver_device.as_deref(),
            self.approver_actor.as_deref(),
            self.approver_proof_key_ref.as_deref(),
        ] {
            digest.optional(value);
        }
        digest.optional(self.operation_binding_digest_sha256.as_deref());
        digest.optional(self.approval_id.as_deref());
        digest.optional(self.approval_evidence_digest_sha256.as_deref());
        digest.optional(
            self.approval_method
                .map(crate::CertificateApprovalMethodV2::as_str),
        );
        digest.optional(
            self.approval_assurance
                .map(crate::CertificateApprovalAssuranceV2::as_str),
        );
        match self.approval_verified_at_epoch_s {
            Some(value) => {
                digest.text("approval-time");
                digest.number(value);
            }
            None => digest.text("no-approval-time"),
        }
        for (label, value) in [
            ("approval-issued", self.approval_issued_at_epoch_s),
            ("approval-expires", self.approval_expires_at_epoch_s),
        ] {
            match value {
                Some(value) => {
                    digest.text(label);
                    digest.number(value);
                }
                None => digest.text("no-approval-window"),
            }
        }
        digest.number(u64::from(self.target_resource_normalization_verified));
        for value in [
            self.trust_revision,
            self.checkpoint_sequence,
            self.previous_identity_revocation_epoch,
            self.identity_revocation_epoch,
            self.previous_lifecycle_revocation_epoch,
            self.lifecycle_revocation_epoch,
            self.previous_fence,
            self.current_fence,
        ] {
            digest.number(value);
        }
        digest.finish()
    }
}
