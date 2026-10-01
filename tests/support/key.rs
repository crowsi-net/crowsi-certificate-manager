use std::collections::VecDeque;

use crowsi_certificate_manager::*;
use sha2::{Digest, Sha256};

use super::{NOW, config, workload};

pub struct EnrollmentVerifier(pub VerifiedKeyEnrollmentV2);
impl KeyEnrollmentVerifierPort for EnrollmentVerifier {
    fn verify(
        &mut self,
        _: &KeyEnrollmentV2,
    ) -> Result<VerifiedKeyEnrollmentV2, KeyEnrollmentError> {
        Ok(self.0.clone())
    }
}

pub fn enrollment() -> VerifiedKeyEnrollmentV2 {
    let public_key_spki_der = b"public-spki-ed25519".to_vec();
    VerifiedKeyEnrollmentV2 {
        public_key_sha256: format!("{:x}", Sha256::digest(&public_key_spki_der)),
        public_key_spki_der,
        algorithm: "ed25519".into(),
        proof_of_possession_verified: true,
    }
}

pub struct CustodyVerifier(pub VecDeque<Result<VerifiedKeyCustodyAttestationV2, KeyCustodyError>>);
impl KeyCustodyAttestationVerifierPort for CustodyVerifier {
    fn verify(
        &mut self,
        _: &SignedKeyCustodyAttestationV2,
    ) -> Result<VerifiedKeyCustodyAttestationV2, KeyCustodyError> {
        self.0
            .pop_front()
            .unwrap_or(Err(KeyCustodyError::Unavailable))
    }
}

pub fn custody(command_digest: String) -> VerifiedKeyCustodyAttestationV2 {
    let policy = config();
    let identity = workload();
    VerifiedKeyCustodyAttestationV2 {
        attestation_id: "attestation.custody.0001".into(),
        security_domain: policy.security_domain,
        deployment_id: policy.deployment_id,
        service_id: identity.service_id,
        workload_id: identity.workload_id,
        pairwise_subject: identity.pairwise_subject,
        device_id: identity.device,
        profile: identity.profile,
        proof_key_ref: identity.proof_key_ref,
        identity_revocation_epoch: identity.identity_revocation_epoch,
        public_key_sha256: enrollment().public_key_sha256,
        command_digest_sha256: command_digest,
        provider_id: "provider.device.tpm".into(),
        signature_key_id: policy.custody_verifier_key_id,
        signature_key_version: policy.custody_key_version,
        signature_public_key_spki_sha256: policy.custody_public_key_spki_sha256,
        signature_algorithm: policy.custody_signature_algorithm,
        signature_key_purpose: policy.custody_key_purpose,
        trust_revision: policy.trust_revision,
        custody: KeyCustodyStateV2::NonExportable,
        attestation_digest_sha256: "44".repeat(32),
        issued_at_epoch_s: NOW - 10,
        expires_at_epoch_s: NOW + 60,
        signature_verified: true,
    }
}
