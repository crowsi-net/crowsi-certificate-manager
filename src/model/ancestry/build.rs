use super::CertificateAuthorizationAncestryV2;
use crate::{VerifiedCertificateExecutionAuthorizationV2, VerifiedWorkloadV2};

impl CertificateAuthorizationAncestryV2 {
    #[must_use]
    pub fn from_verified(
        value: &VerifiedCertificateExecutionAuthorizationV2,
        workload: &VerifiedWorkloadV2,
    ) -> Self {
        Self {
            operation_id: value.operation_id.clone(),
            authorization_command_digest_sha256: value.command_digest_sha256.clone(),
            operation_binding_digest_sha256: value
                .operation_binding
                .as_ref()
                .map(crate::CertificateAuthorizationOperationBindingV2::digest_sha256),
            lease_digest_sha256: value.lease_digest_sha256.clone(),
            signature_key_version: value.signature_key_version.clone(),
            signature_public_key_spki_sha256: value.signature_public_key_spki_sha256.clone(),
            signature_key_purpose: value.signature_key_purpose.clone(),
            trust_revision: value.trust_revision,
            security_domain: value.security_domain.clone(),
            deployment_id: value.deployment_id.clone(),
            release_id: value.release_id.clone(),
            release_digest_sha256: value.release_digest_sha256.clone(),
            checkpoint_id: value.checkpoint_id.clone(),
            checkpoint_digest_sha256: value.checkpoint_digest_sha256.clone(),
            checkpoint_sequence: value.checkpoint_sequence,
            deployment_provenance_ref: value.deployment_provenance_ref.clone(),
            pa_reservation_id: value.pa_reservation_id.clone(),
            policy_id: value.policy_id.clone(),
            policy_digest_sha256: value.policy_digest_sha256.clone(),
            decision_id: value.decision_id.clone(),
            decision_digest_sha256: value.decision_digest_sha256.clone(),
            grant_id: value.grant_id.clone(),
            grant_digest_sha256: value.grant_digest_sha256.clone(),
            approval_id: value.approval_id.clone(),
            approval_evidence_digest_sha256: value.approval_evidence_digest_sha256.clone(),
            approval_method: value.approval_method,
            approval_assurance: value.approval_assurance,
            approval_verified_at_epoch_s: value.approval_verified_at_epoch_s,
            approval_issued_at_epoch_s: value.approval_issued_at_epoch_s,
            approval_expires_at_epoch_s: value.approval_expires_at_epoch_s,
            identity_revocation_snapshot_id: value.identity_revocation_snapshot_id.clone(),
            identity_revocation_snapshot_digest_sha256: value
                .identity_revocation_snapshot_digest_sha256
                .clone(),
            previous_identity_revocation_epoch: value.previous_identity_revocation_epoch,
            identity_revocation_epoch: value.identity_revocation_epoch,
            previous_lifecycle_revocation_epoch: value.previous_lifecycle_revocation_epoch,
            lifecycle_revocation_epoch: value.lifecycle_revocation_epoch,
            previous_fence: value.previous_fence,
            current_fence: value.current_fence,
            requester_pairwise_subject: value.requester_pairwise_subject.clone(),
            approver_pairwise_subject: value.approver_pairwise_subject.clone(),
            requester_profile: value.requester_profile.clone(),
            requester_device: value.requester_device.clone(),
            requester_actor: value.requester_actor.clone(),
            requester_proof_key_ref: value.requester_proof_key_ref.clone(),
            approver_profile: value.approver_profile.clone(),
            approver_device: value.approver_device.clone(),
            approver_actor: value.approver_actor.clone(),
            approver_proof_key_ref: value.approver_proof_key_ref.clone(),
            workload_evidence_sha256: workload.evidence_sha256.clone(),
            target_resource_normalizer_id: value.target_resource_normalizer_id.clone(),
            target_resource_normalizer_version: value.target_resource_normalizer_version.clone(),
            target_resource_normalization_digest_sha256: value
                .target_resource_normalization_digest_sha256
                .clone(),
            target_resource_normalization_verified: value.target_resource_normalization_verified,
        }
    }
}
