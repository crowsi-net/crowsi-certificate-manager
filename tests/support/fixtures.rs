use std::collections::BTreeSet;

use crowsi_certificate_manager::*;

pub const NOW: u64 = 10_000;

pub fn config() -> CertificateManagerConfig {
    CertificateManagerConfig {
        service_id: "service.certificate.manager".into(),
        security_domain: "security.crowsi".into(),
        deployment_id: "deployment.local".into(),
        authority_id: "authority.crowsi.production".into(),
        authority_key_id: "key.certificate.authority".into(),
        authority_key_version: "key.version.ca.0003".into(),
        authority_public_key_spki_sha256: "41".repeat(32),
        authority_signature_algorithm: "ecdsa-p256-sha256".into(),
        authority_key_provider_signature_profile: "ecdsa-p256-sha256-p1363-low-s".into(),
        authority_key_purpose: "workload-certificate-issuance".into(),
        authority_receipt_verifier_key_id: "key.authority.receipt".into(),
        authority_receipt_key_version: "key.version.receipt.0007".into(),
        authority_receipt_public_key_spki_sha256: "42".repeat(32),
        authority_receipt_signature_algorithm: "ecdsa-p256-sha256-p1363-low-s".into(),
        authority_receipt_key_purpose: "certificate-authority-receipt".into(),
        authority_outcome_issuer: "authority://crowsi/certificate".into(),
        authority_outcome_audience: "service://crowsi/policy-administrator".into(),
        authority_attestation_verifier_key_id: "key.attestation.verifier".into(),
        authority_attestation_key_version: "key.version.attestation.0002".into(),
        authority_attestation_public_key_spki_sha256: "43".repeat(32),
        authority_attestation_signature_algorithm: "ed25519".into(),
        authority_attestation_key_purpose: "authority-readiness-attestation".into(),
        authorization_provider_id: "provider.policy.administrator".into(),
        authorization_issuer: "https://ihat.online/pa".into(),
        authorization_audience: "service://crowsi/certificate-manager".into(),
        authorization_policy_id: "policy.certificate.lifecycle".into(),
        authorization_policy_digest_sha256: "10".repeat(32),
        authorization_verifier_key_id: "key.policy.administrator".into(),
        authorization_key_version: "key.version.authorization.0004".into(),
        authorization_public_key_spki_sha256: "44".repeat(32),
        authorization_signature_algorithm: "ed25519".into(),
        authorization_key_purpose: "certificate-execution-authorization".into(),
        authorization_channel: "channel.service.automation".into(),
        target_resource_normalizer_id: "normalizer.crowsi.resource".into(),
        target_resource_normalizer_version: "normalizer.version.0001".into(),
        custody_verifier_key_id: "key.custody.attestation".into(),
        custody_key_version: "key.version.custody.0006".into(),
        custody_public_key_spki_sha256: "45".repeat(32),
        custody_signature_algorithm: "ed25519".into(),
        custody_key_purpose: "leaf-key-custody-attestation".into(),
        manager_commit_issuer: "service://crowsi/certificate-manager".into(),
        manager_commit_audience: "service://crowsi/policy-administrator".into(),
        manager_commit_workload: "spiffe://crowsi.test/local/certificate-manager".into(),
        manager_commit_key_id: "key.manager.commit".into(),
        manager_commit_key_version: "key.version.manager.commit.0001".into(),
        manager_commit_public_key_spki_sha256: "46".repeat(32),
        manager_commit_signature_algorithm: "ecdsa-p256-sha256-p1363-low-s".into(),
        manager_commit_key_purpose: "certificate-manager-commit-receipt".into(),
        manager_handoff_issuer: "service://crowsi/certificate-manager".into(),
        manager_handoff_audience: "service://crowsi/policy-administrator".into(),
        manager_handoff_workload: "spiffe://crowsi.test/local/certificate-manager".into(),
        manager_handoff_key_id: "key.manager.handoff".into(),
        manager_handoff_key_version: "key.version.manager.handoff.0001".into(),
        manager_handoff_public_key_spki_sha256: "47".repeat(32),
        manager_handoff_signature_algorithm: "ecdsa-p256-sha256-p1363-low-s".into(),
        manager_handoff_key_purpose: "certificate-manager-handoff-receipt".into(),
        trust_revision: 7,
        accepted_transport: "native-ipc".into(),
        workload_spiffe_prefix: "spiffe://crowsi.test/local/".into(),
        subject_spiffe_prefix: "spiffe://crowsi.test/subjects/".into(),
        allowed_audiences: BTreeSet::from(["service://nerp/local-api".into()]),
        allowed_purposes: BTreeSet::from(["service-authentication".into()]),
        allowed_leaf_key_algorithms: BTreeSet::from(["ed25519".into()]),
        allowed_custody_providers: BTreeSet::from(["provider.device.tpm".into()]),
        max_certificate_ttl_seconds: 3_600,
        max_authorization_ttl_seconds: 300,
        max_workload_identity_ttl_seconds: 300,
        max_custody_attestation_ttl_seconds: 300,
        max_authority_lease_ttl_seconds: 120,
        max_revocation_snapshot_age_seconds: 60,
        max_reconciliation_receipt_age_seconds: 60,
        max_handoff_recovery_seconds: 60,
        max_completion_evidence_ttl_seconds: 60,
        max_completion_recovery_seconds: 86_400,
        max_scopes: 8,
        max_key_enrollment_bytes: 16_384,
        max_public_certificate_bytes: 131_072,
    }
}

pub fn command(operation: CertificateOperation) -> CertificateCommandV2 {
    let key = operation
        .requires_key_enrollment()
        .then(|| KeyEnrollmentV2::CsrDerBase64 {
            csr_der_base64: "cHVibGljLWNzcg==".into(),
        });
    let target =
        (operation != CertificateOperation::Issue).then(|| "certificate.current.0001".into());
    CertificateCommandV2 {
        schema: "crowsi://certificates/management-command/v2".into(),
        request_id: format!("request.certificate.{}", operation.as_str()),
        nonce: format!("nonce.certificate.{}", operation.as_str()),
        operation,
        resource_id: "resource.certificate.nerp.worker".into(),
        expected_resource_version: u64::from(operation != CertificateOperation::Issue),
        previous_lifecycle_revocation_epoch: match operation {
            CertificateOperation::Issue => 0,
            _ => 2,
        },
        lifecycle_revocation_epoch: match operation {
            CertificateOperation::Issue => 0,
            CertificateOperation::Revoke => 3,
            CertificateOperation::Renew | CertificateOperation::Status => 2,
        },
        profile_id: "certificate.profile.service".into(),
        purpose: "service-authentication".into(),
        subject: "spiffe://crowsi.test/subjects/nerp-worker".into(),
        audience: "service://nerp/local-api".into(),
        scopes: vec!["health.read".into(), "topology.read".into()],
        requested_ttl_seconds: key.as_ref().map_or(0, |_| 900),
        target_certificate_id: target,
        key_enrollment: key,
    }
}

pub fn evidence() -> WorkloadEvidenceV2 {
    WorkloadEvidenceV2::from_native_ipc("dHJhbnNwb3J0LWV2aWRlbmNl")
}

pub fn signed_authorization() -> SignedCertificateExecutionAuthorizationV2 {
    signed_authorization_with_digest("11".repeat(32))
}

pub fn signed_status_authorization() -> SignedCertificateExecutionAuthorizationV2 {
    signed_authorization_with_digest("12".repeat(32))
}

pub fn signed_reconciliation_authorization() -> SignedCertificateExecutionAuthorizationV2 {
    signed_authorization_with_digest("13".repeat(32))
}

fn signed_authorization_with_digest(
    lease_digest_sha256: String,
) -> SignedCertificateExecutionAuthorizationV2 {
    SignedCertificateExecutionAuthorizationV2::new(
        "key.policy.administrator",
        "cGEtcGVwLWxlYXNlLXYy",
        lease_digest_sha256,
        "c2lnbmF0dXJl",
    )
}

pub fn signed_custody() -> SignedKeyCustodyAttestationV2 {
    SignedKeyCustodyAttestationV2::new(
        "key.custody.attestation",
        "Y3VzdG9keS1hdHRlc3RhdGlvbg==",
        "c2lnbmF0dXJl",
    )
}
