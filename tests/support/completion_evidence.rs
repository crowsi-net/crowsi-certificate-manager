use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use crowsi_certificate_manager::*;
use crowsi_control_contracts::{
    CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2, CertificateActionV2,
    CertificateAuthorityOutcomeEvidenceV2, CertificateExecutionDispositionV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
};

pub fn outcome_evidence(
    command: &AuthorityCommandV2,
    outcome: &AuthorityOutcomeV2,
    executed_at_epoch_s: u64,
) -> CertificateAuthorityOutcomeEvidenceV2 {
    finish(CertificateAuthorityOutcomeEvidenceV2 {
        schema: CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2.into(),
        evidence_id: format!("evidence.authority.{}", command.request_id),
        nonce_base64: URL_SAFE_NO_PAD.encode([7_u8; 32]),
        issuer: "authority://crowsi/certificate".into(),
        audience: "service://crowsi/policy-administrator".into(),
        action: action(command.operation),
        authorization_jti: command.authorization_jti.clone(),
        operation_id: command.authorization_operation_id.clone(),
        lease_digest_sha256: command.authorization_lease_digest_sha256.clone(),
        authorization_command_digest_sha256: command.management_command_digest_sha256.clone(),
        target_resource_id: command.resource_id.clone(),
        expected_resource_version: command.expected_resource_version,
        previous_fence: command.previous_fence,
        current_fence: command.current_fence,
        previous_lifecycle_revocation_epoch: command.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: command.lifecycle_revocation_epoch,
        disposition: CertificateExecutionDispositionV2::Completed,
        authority_outcome_digest_sha256: Some(outcome.digest_sha256()),
        original_authorization_jti: None,
        original_operation_id: None,
        original_lease_digest_sha256: None,
        original_action: None,
        original_authority_command_digest_sha256: None,
        original_unknown_evidence_digest_sha256: None,
        lifecycle_reservation_id: None,
        original_previous_fence: None,
        original_current_fence: None,
        original_previous_lifecycle_revocation_epoch: None,
        original_lifecycle_revocation_epoch: None,
        security_domain: command.security_domain.clone(),
        deployment_id: command.deployment_id.clone(),
        trust_revision: command.authority_trust_revision,
        authority_id: command.authority_id.clone(),
        receipt_key_id: command.authority_receipt_key_id.clone(),
        receipt_key_version: command.authority_receipt_key_version.clone(),
        receipt_public_key_spki_sha256: command.authority_receipt_public_key_spki_sha256.clone(),
        receipt_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        receipt_key_purpose: command.authority_receipt_key_purpose.clone(),
        issued_at_epoch_s: executed_at_epoch_s,
        expires_at_epoch_s: executed_at_epoch_s + 60,
        signed: signature(command),
    })
}

pub(super) fn finish(
    mut value: CertificateAuthorityOutcomeEvidenceV2,
) -> CertificateAuthorityOutcomeEvidenceV2 {
    value.signed.digest_sha256 = value.certificate_digest_sha256();
    value
}

fn signature(command: &AuthorityCommandV2) -> CertificateReceiptSignatureV2 {
    signature_for(
        &command.authority_receipt_key_id,
        &command.authority_receipt_key_version,
        &command.authority_receipt_public_key_spki_sha256,
        &command.authority_receipt_key_purpose,
    )
}

pub(super) fn signature_for(
    key: &str,
    version: &str,
    spki: &str,
    purpose: &str,
) -> CertificateReceiptSignatureV2 {
    CertificateReceiptSignatureV2 {
        key_id: key.into(),
        key_version: version.into(),
        public_key_spki_sha256: spki.into(),
        key_purpose: purpose.into(),
        algorithm: CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        digest_sha256: "00".repeat(32),
        signature_base64: STANDARD.encode([8_u8; 64]),
    }
}

const fn action(value: CertificateOperation) -> CertificateActionV2 {
    match value {
        CertificateOperation::Issue => CertificateActionV2::Issue,
        CertificateOperation::Renew => CertificateActionV2::Renew,
        CertificateOperation::Revoke => CertificateActionV2::Revoke,
        CertificateOperation::Status => CertificateActionV2::CertificateStatus,
    }
}
