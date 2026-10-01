use base64::{Engine as _, engine::general_purpose::STANDARD};
use crowsi_certificate_manager::*;
use crowsi_control_contracts::CertificatePayloadV2;
use sha2::{Digest, Sha256};

use super::NOW;

pub fn outcome(command: &AuthorityCommandV2, executed_at_epoch_s: u64) -> AuthorityOutcomeV2 {
    let metadata = match command.operation {
        CertificateOperation::Issue | CertificateOperation::Renew => CertificateMetadataV2 {
            certificate_id: "certificate.issued.0001".into(),
            serial_number: "a10001".into(),
            fingerprint_sha256: format!("{:x}", Sha256::digest(b"public-certificate")),
            public_key_sha256: command
                .public_key_sha256
                .clone()
                .expect("public key digest"),
            public_key_algorithm: command.public_key_algorithm.clone().expect("algorithm"),
            not_before_epoch_s: executed_at_epoch_s,
            expires_at_epoch_s: command.certificate_expires_at_epoch_s,
            state: CertificateState::Active,
        },
        CertificateOperation::Revoke => CertificateMetadataV2 {
            state: CertificateState::Revoked,
            ..prior_metadata()
        },
        CertificateOperation::Status => prior_metadata(),
    };
    let public_certificate =
        command
            .operation
            .requires_key_enrollment()
            .then(|| PublicCertificateV2 {
                metadata: metadata.clone(),
                certificate_der_base64: STANDARD.encode(b"public-certificate"),
                chain_der_base64: vec![STANDARD.encode(b"public-chain")],
            });
    AuthorityOutcomeV2 {
        metadata,
        public_certificate,
        signed_receipt: SignedAuthorityOutcomeReceiptV2 {
            schema: "crowsi://certificates/authority-outcome-receipt/v2".into(),
            key_id: "key.authority.receipt".into(),
            payload_base64: STANDARD.encode(executed_at_epoch_s.to_string()),
            signature_base64: "c2lnbmF0dXJl".into(),
        },
    }
}

pub fn prior_metadata() -> CertificateMetadataV2 {
    CertificateMetadataV2 {
        certificate_id: "certificate.current.0001".into(),
        serial_number: "a00001".into(),
        fingerprint_sha256: "61".repeat(32),
        public_key_sha256: "62".repeat(32),
        public_key_algorithm: "rsa-1024".into(),
        not_before_epoch_s: NOW - 5_000,
        expires_at_epoch_s: NOW + 5_000,
        state: CertificateState::Active,
    }
}

pub struct CertificateVerifier;
impl PublicCertificateVerifierPort for CertificateVerifier {
    fn verify(
        &mut self,
        certificate: &PublicCertificateV2,
        _: &AuthorityCommandV2,
    ) -> Result<VerifiedPublicCertificateV2, PublicCertificateError> {
        let canonical =
            certificate.certificate_der_base64 == STANDARD.encode(b"public-certificate");
        Ok(VerifiedPublicCertificateV2 {
            metadata_digest_sha256: certificate.metadata.digest_sha256(),
            tbs_certificate_digest_sha256: "91".repeat(32),
            signing_key_version: "key.version.ca.0003".into(),
            signing_public_key_spki_sha256: "41".repeat(32),
            signature_encoding: "x509-der-ecdsa-sig-value".into(),
            signature_canonical: canonical,
            high_s_rejected: canonical,
            chain_verified: true,
            profile_verified: true,
            fingerprint_verified: true,
        })
    }
}

pub struct OutcomeVerifier {
    pub use_ca_key: bool,
}

impl AuthorityOutcomeVerifierPort for OutcomeVerifier {
    fn verify(
        &mut self,
        value: &AuthorityOutcomeV2,
        command: &AuthorityCommandV2,
    ) -> Result<VerifiedAuthorityOutcomeReceiptV2, AuthorityOutcomeError> {
        let executed_at_epoch_s = STANDARD
            .decode(&value.signed_receipt.payload_base64)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| text.parse().ok())
            .ok_or(AuthorityOutcomeError::Rejected)?;
        let completion_evidence = super::outcome_evidence(command, value, executed_at_epoch_s);
        let receipt_digest_sha256 = completion_evidence.certificate_digest_sha256();
        Ok(VerifiedAuthorityOutcomeReceiptV2 {
            completion_evidence,
            request_id: command.request_id.clone(),
            management_command_digest_sha256: command.management_command_digest_sha256.clone(),
            authority_command_digest_sha256: command.digest_sha256(),
            authority_outcome_digest_sha256: value.digest_sha256(),
            authority_id: command.authority_id.clone(),
            authority_key_id: command.authority_key_id.clone(),
            authority_key_version: command.authority_key_version.clone(),
            authority_public_key_spki_sha256: command.authority_public_key_spki_sha256.clone(),
            signature_key_id: if self.use_ca_key {
                command.authority_key_id.clone()
            } else {
                command.authority_receipt_key_id.clone()
            },
            authority_receipt_key_version: command.authority_receipt_key_version.clone(),
            authority_receipt_public_key_spki_sha256: command
                .authority_receipt_public_key_spki_sha256
                .clone(),
            signature_algorithm: command.authority_receipt_signature_algorithm.clone(),
            key_purpose: command.authority_receipt_key_purpose.clone(),
            authority_lease_id: command.authority_lease_id.clone(),
            authority_attestation_digest_sha256: command
                .authority_attestation_digest_sha256
                .clone(),
            authority_fence: command.authority_fence,
            authority_trust_revision: command.authority_trust_revision,
            lifecycle_reservation_id: command.lifecycle_reservation_id.clone(),
            lifecycle_fence: command.current_fence,
            executed_at_epoch_s,
            receipt_digest_sha256,
            signature_verified: true,
        })
    }

    fn verify_reconciliation(
        &mut self,
        value: &AuthorityReconciliationOutcomeV2,
        command: &AuthorityReconciliationCommandV2,
    ) -> Result<VerifiedAuthorityReconciliationV2, AuthorityOutcomeError> {
        Ok(super::reconciliation::reconciliation_receipt(
            value, command,
        ))
    }
}
