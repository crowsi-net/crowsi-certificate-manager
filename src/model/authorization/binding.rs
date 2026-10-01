use crate::digest::DigestBuilder;

use super::CertificateLifecycleActionV2;

#[derive(Clone, Eq, PartialEq)]
pub enum CertificateAuthorizationOperationBindingV2 {
    OperationStatus {
        target_operation_id: String,
    },
    ReconcileUnknown {
        original_action: CertificateLifecycleActionV2,
        target_operation_id: String,
        lifecycle_reservation_id: String,
        authority_command_digest_sha256: String,
        unknown_evidence_digest_sha256: String,
        locked_previous_fence: u64,
        locked_current_fence: u64,
        locked_previous_lifecycle_revocation_epoch: u64,
        locked_lifecycle_revocation_epoch: u64,
    },
}

impl CertificateAuthorizationOperationBindingV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-operation-binding-v2");
        match self {
            Self::OperationStatus {
                target_operation_id,
            } => {
                digest.text("operation-status");
                digest.text(target_operation_id);
            }
            Self::ReconcileUnknown {
                original_action,
                target_operation_id,
                lifecycle_reservation_id,
                authority_command_digest_sha256,
                unknown_evidence_digest_sha256,
                locked_previous_fence,
                locked_current_fence,
                locked_previous_lifecycle_revocation_epoch,
                locked_lifecycle_revocation_epoch,
            } => {
                digest.text("reconcile-unknown");
                digest.text(original_action.as_str());
                digest.text(target_operation_id);
                digest.text(lifecycle_reservation_id);
                digest.text(authority_command_digest_sha256);
                digest.text(unknown_evidence_digest_sha256);
                digest.number(*locked_previous_fence);
                digest.number(*locked_current_fence);
                digest.number(*locked_previous_lifecycle_revocation_epoch);
                digest.number(*locked_lifecycle_revocation_epoch);
            }
        }
        digest.finish()
    }
}
