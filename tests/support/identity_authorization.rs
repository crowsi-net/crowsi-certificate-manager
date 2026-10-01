use crowsi_certificate_manager::*;

use super::{NOW, config};

#[allow(clippy::too_many_arguments)]
pub fn authorization(
    digest: String,
    action: CertificateAuthorizedActionV2,
    operation_id: &str,
    operation_binding: Option<CertificateAuthorizationOperationBindingV2>,
    resource: &str,
    version: u64,
    previous_lifecycle_revocation_epoch: u64,
    lifecycle_revocation_epoch: u64,
) -> VerifiedCertificateExecutionAuthorizationV2 {
    let policy = config();
    let suffix = action.as_str();
    let privileged = requires_approval(action);
    VerifiedCertificateExecutionAuthorizationV2 {
        authorization_id: format!("authorization.certificate.{suffix}.0001"),
        jti: format!("authorization.jti.{suffix}.0001"),
        operation_id: operation_id.into(),
        operation_binding,
        lease_digest_sha256: lease_digest(action),
        command_digest_sha256: digest,
        action,
        issuer: policy.authorization_issuer,
        audience: policy.authorization_audience,
        signature_key_id: policy.authorization_verifier_key_id,
        signature_key_version: policy.authorization_key_version,
        signature_public_key_spki_sha256: policy.authorization_public_key_spki_sha256,
        signature_algorithm: policy.authorization_signature_algorithm,
        signature_key_purpose: policy.authorization_key_purpose,
        trust_revision: policy.trust_revision,
        channel: policy.authorization_channel,
        approval_id: privileged.then(|| "approval.certificate.0001".into()),
        approval_evidence_digest_sha256: privileged.then(|| "37".repeat(32)),
        approval_method: privileged
            .then_some(CertificateApprovalMethodV2::HardwareBackedUserPresence),
        approval_assurance: privileged.then_some(CertificateApprovalAssuranceV2::Aal3),
        approval_verified_at_epoch_s: privileged.then_some(NOW - 5),
        approval_issued_at_epoch_s: privileged.then_some(NOW - 10),
        approval_expires_at_epoch_s: privileged.then_some(NOW + 60),
        security_domain: policy.security_domain,
        deployment_id: policy.deployment_id,
        release_id: "release.certificate.0001".into(),
        release_digest_sha256: "31".repeat(32),
        checkpoint_id: "checkpoint.certificate.0001".into(),
        checkpoint_digest_sha256: "32".repeat(32),
        checkpoint_sequence: 3,
        deployment_provenance_ref: "deployment.provenance.0001".into(),
        pa_reservation_id: format!("reservation.pa.{suffix}.0001"),
        policy_id: policy.authorization_policy_id,
        policy_digest_sha256: policy.authorization_policy_digest_sha256,
        decision_id: "decision.certificate.0001".into(),
        decision_digest_sha256: "34".repeat(32),
        grant_id: "grant.certificate.0001".into(),
        grant_digest_sha256: "35".repeat(32),
        pairwise_subject: "subject.pairwise.nerp".into(),
        requester_pairwise_subject: "subject.requester.nerp".into(),
        approver_pairwise_subject: privileged.then(|| "subject.approver.security".into()),
        requester_profile: "profile.workload.operator".into(),
        requester_device: "device.local.0001".into(),
        requester_actor: "actor.nerp.operator".into(),
        requester_proof_key_ref: "proof.key.local.0001".into(),
        approver_profile: privileged.then(|| "profile.security.approver".into()),
        approver_device: privileged.then(|| "device.security.0001".into()),
        approver_actor: privileged.then(|| "actor.security.approver".into()),
        approver_proof_key_ref: privileged.then(|| "proof.key.security.0001".into()),
        workload: "spiffe://crowsi.test/local/nerp".into(),
        previous_identity_revocation_epoch: 8,
        identity_revocation_epoch: 9,
        previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch,
        identity_revocation_snapshot_id: "revocation.snapshot.0009".into(),
        identity_revocation_snapshot_digest_sha256: "36".repeat(32),
        identity_revocation_snapshot_epoch: 9,
        identity_revocation_snapshot_verified_at_epoch_s: NOW - 1,
        authoritative_identity_revocation_snapshot: true,
        service_id: "service.nerp.local".into(),
        provider: policy.authorization_provider_id,
        target_resource_id: resource.into(),
        target_resource_normalizer_id: policy.target_resource_normalizer_id,
        target_resource_normalizer_version: policy.target_resource_normalizer_version,
        target_resource_normalization_digest_sha256: "46".repeat(32),
        target_resource_normalization_verified: true,
        unknown_evidence_digest_sha256: (action == CertificateAuthorizedActionV2::ReconcileUnknown)
            .then(|| "45".repeat(32)),
        previous_fence: fence(action).0,
        current_fence: fence(action).1,
        expected_resource_version: version,
        issued_at_epoch_s: NOW - 10,
        expires_at_epoch_s: NOW + 60,
        one_use: true,
        signature_verified: true,
    }
}

pub fn mutation_authorization(
    command: &CertificateCommandV2,
) -> VerifiedCertificateExecutionAuthorizationV2 {
    authorization(
        command.digest_sha256(),
        CertificateAuthorizedActionV2::Issue,
        &command.request_id,
        None,
        &command.resource_id,
        command.expected_resource_version,
        command.previous_lifecycle_revocation_epoch,
        command.lifecycle_revocation_epoch,
    )
}

fn lease_digest(action: CertificateAuthorizedActionV2) -> String {
    match action {
        CertificateAuthorizedActionV2::OperationStatus => "12".repeat(32),
        CertificateAuthorizedActionV2::ReconcileUnknown => "13".repeat(32),
        _ => "11".repeat(32),
    }
}

const fn fence(action: CertificateAuthorizedActionV2) -> (u64, u64) {
    match action {
        CertificateAuthorizedActionV2::CertificateStatus => (10, 10),
        CertificateAuthorizedActionV2::OperationStatus => (20, 20),
        CertificateAuthorizedActionV2::ReconcileUnknown => (30, 31),
        _ => (4, 5),
    }
}

const fn requires_approval(action: CertificateAuthorizedActionV2) -> bool {
    matches!(
        action,
        CertificateAuthorizedActionV2::Issue
            | CertificateAuthorizedActionV2::Renew
            | CertificateAuthorizedActionV2::Revoke
            | CertificateAuthorizedActionV2::ReconcileUnknown
    )
}
