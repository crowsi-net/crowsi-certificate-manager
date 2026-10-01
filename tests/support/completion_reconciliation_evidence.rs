use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_certificate_manager::*;
use crowsi_control_contracts::{
    CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2, CertificateActionV2,
    CertificateAuthorityOutcomeEvidenceV2, CertificateExecutionDispositionV2,
    CertificateLifecycleActionV2 as ContractLifecycleActionV2,
    CertificateReceiptSignatureAlgorithmV2,
};

use super::completion_evidence::{finish, signature_for};

pub fn reconciliation_evidence(
    command: &AuthorityReconciliationCommandV2,
    outcome: &AuthorityReconciliationOutcomeV2,
) -> CertificateAuthorityOutcomeEvidenceV2 {
    let receipt = &command.current_reconciliation;
    finish(CertificateAuthorityOutcomeEvidenceV2 {
        schema: CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2.into(),
        evidence_id: format!("evidence.authority.{}", command.query_id),
        nonce_base64: URL_SAFE_NO_PAD.encode([9_u8; 32]),
        issuer: "authority://crowsi/certificate".into(),
        audience: "service://crowsi/policy-administrator".into(),
        action: CertificateActionV2::ReconcileUnknown,
        authorization_jti: command.authorization_jti.clone(),
        operation_id: command.authorization_operation_id.clone(),
        lease_digest_sha256: command.authorization_lease_digest_sha256.clone(),
        authorization_command_digest_sha256: command.authorization_command_digest_sha256.clone(),
        target_resource_id: command.resource_id.clone(),
        expected_resource_version: command.expected_resource_version,
        previous_fence: command.authorization_previous_fence,
        current_fence: command.authorization_current_fence,
        previous_lifecycle_revocation_epoch: command
            .authorization_previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: command.authorization_lifecycle_revocation_epoch,
        disposition: disposition(outcome.disposition),
        authority_outcome_digest_sha256: outcome
            .authority_outcome
            .as_ref()
            .map(AuthorityOutcomeV2::digest_sha256),
        original_authorization_jti: Some(command.original_authorization_jti.clone()),
        original_operation_id: Some(command.original_authorization_operation_id.clone()),
        original_lease_digest_sha256: Some(
            command.original_authorization_lease_digest_sha256.clone(),
        ),
        original_action: Some(lifecycle_action(command.original_action)),
        original_authority_command_digest_sha256: Some(
            command.authority_command_digest_sha256.clone(),
        ),
        original_unknown_evidence_digest_sha256: Some(
            command.unknown_evidence_digest_sha256.clone(),
        ),
        lifecycle_reservation_id: Some(command.lifecycle_reservation_id.clone()),
        original_previous_fence: Some(command.lifecycle_previous_fence),
        original_current_fence: Some(command.lifecycle_fence),
        original_previous_lifecycle_revocation_epoch: Some(
            command.previous_lifecycle_revocation_epoch,
        ),
        original_lifecycle_revocation_epoch: Some(command.lifecycle_revocation_epoch),
        security_domain: command.security_domain.clone(),
        deployment_id: command.deployment_id.clone(),
        trust_revision: receipt.trust_revision,
        authority_id: receipt.authority_id.clone(),
        receipt_key_id: receipt.receipt_signing_key_id.clone(),
        receipt_key_version: receipt.receipt_signing_key_version.clone(),
        receipt_public_key_spki_sha256: receipt.receipt_signing_public_key_spki_sha256.clone(),
        receipt_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        receipt_key_purpose: receipt.receipt_key_purpose.clone(),
        issued_at_epoch_s: command.requested_at_epoch_s + 1,
        expires_at_epoch_s: command.requested_at_epoch_s + 61,
        signed: signature_for(
            &receipt.receipt_signing_key_id,
            &receipt.receipt_signing_key_version,
            &receipt.receipt_signing_public_key_spki_sha256,
            &receipt.receipt_key_purpose,
        ),
    })
}

const fn lifecycle_action(value: CertificateLifecycleActionV2) -> ContractLifecycleActionV2 {
    match value {
        CertificateLifecycleActionV2::Issue => ContractLifecycleActionV2::Issue,
        CertificateLifecycleActionV2::Renew => ContractLifecycleActionV2::Renew,
        CertificateLifecycleActionV2::Revoke => ContractLifecycleActionV2::Revoke,
    }
}

const fn disposition(
    value: AuthorityReconciliationDispositionV2,
) -> CertificateExecutionDispositionV2 {
    match value {
        AuthorityReconciliationDispositionV2::Completed => {
            CertificateExecutionDispositionV2::Completed
        }
        AuthorityReconciliationDispositionV2::NotExecuted => {
            CertificateExecutionDispositionV2::NotExecuted
        }
        AuthorityReconciliationDispositionV2::StillUnknown => {
            CertificateExecutionDispositionV2::StillUnknown
        }
    }
}
