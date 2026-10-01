use std::sync::{Arc, Mutex};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use crowsi_certificate_manager::*;
use crowsi_control_contracts::{
    CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2, CertificateManagerCommitEvidenceV2,
    CertificatePayloadV2, CertificateReceiptSignatureV2, Validate,
};

#[derive(Default)]
pub struct CompletionSignerState {
    pub sign_calls: usize,
    pub recover_calls: usize,
    pub unknown_once: bool,
    pub signed: Option<CertificateManagerCommitEvidenceV2>,
}

pub struct CompletionSigner(pub Arc<Mutex<CompletionSignerState>>);

impl CertificateCompletionEvidenceSignerPort for CompletionSigner {
    fn sign(
        &mut self,
        draft: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CertificateManagerCommitEvidenceV2, CompletionEvidenceError> {
        let mut state = self.0.lock().expect("signer");
        state.sign_calls += 1;
        let evidence = evidence(draft);
        state.signed = Some(evidence.clone());
        if state.unknown_once {
            state.unknown_once = false;
            return Err(CompletionEvidenceError::ResultUnknown);
        }
        Ok(evidence)
    }

    fn recover(
        &mut self,
        draft: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CertificateManagerCommitEvidenceV2, CompletionEvidenceError> {
        let mut state = self.0.lock().expect("signer");
        state.recover_calls += 1;
        state
            .signed
            .clone()
            .filter(|value| value.commit_id == draft.commit_id)
            .ok_or(CompletionEvidenceError::ResultUnknown)
    }
}

pub struct CompletionVerifier(pub bool);

impl CertificateCompletionEvidenceVerifierPort for CompletionVerifier {
    fn verify(
        &mut self,
        evidence: &CertificateManagerCommitEvidenceV2,
    ) -> Result<(), CompletionEvidenceError> {
        (!self.0 && evidence.validate().is_ok())
            .then_some(())
            .ok_or(CompletionEvidenceError::Rejected)
    }
}

pub struct CompletionChallenge(pub Arc<Mutex<u8>>);

impl CompletionChallengeSourcePort for CompletionChallenge {
    fn issue(
        &mut self,
        commit: &CompletionCommitReadbackV2,
    ) -> Result<CompletionChallengeV2, CompletionChallengeError> {
        let mut sequence = self.0.lock().expect("challenge");
        *sequence = sequence.saturating_add(1);
        Ok(CompletionChallengeV2 {
            commit_id: commit.completion_id.clone(),
            nonce_base64: URL_SAFE_NO_PAD.encode([*sequence; 32]),
        })
    }
}

pub fn completion_challenge() -> (CompletionChallenge, Arc<Mutex<u8>>) {
    let state = Arc::new(Mutex::new(0));
    (CompletionChallenge(Arc::clone(&state)), state)
}

pub fn completion_signer(
    unknown_once: bool,
) -> (CompletionSigner, Arc<Mutex<CompletionSignerState>>) {
    let state = Arc::new(Mutex::new(CompletionSignerState {
        unknown_once,
        ..CompletionSignerState::default()
    }));
    (CompletionSigner(Arc::clone(&state)), state)
}

fn evidence(value: &ManagerCommitEvidenceDraftV2) -> CertificateManagerCommitEvidenceV2 {
    let mut result = CertificateManagerCommitEvidenceV2 {
        schema: CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2.into(),
        commit_id: value.commit_id.clone(),
        nonce_base64: value.nonce_base64.clone(),
        issuer: value.issuer.clone(),
        audience: value.audience.clone(),
        action: value.action,
        authorization_jti: value.authorization_jti.clone(),
        operation_id: value.operation_id.clone(),
        lease_digest_sha256: value.lease_digest_sha256.clone(),
        authorization_command_digest_sha256: value.authorization_command_digest_sha256.clone(),
        target_resource_id: value.target_resource_id.clone(),
        state_revision: value.state_revision,
        resource_version: value.resource_version,
        previous_fence: value.previous_fence,
        current_fence: value.current_fence,
        previous_lifecycle_revocation_epoch: value.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: value.lifecycle_revocation_epoch,
        disposition: value.disposition,
        authority_evidence_id: value.authority_evidence_id.clone(),
        authority_evidence_digest_sha256: value.authority_evidence_digest_sha256.clone(),
        security_domain: value.security_domain.clone(),
        deployment_id: value.deployment_id.clone(),
        trust_revision: value.trust_revision,
        manager_workload: value.manager_workload.clone(),
        commit_key_id: value.commit_key_id.clone(),
        commit_key_version: value.commit_key_version.clone(),
        commit_public_key_spki_sha256: value.commit_public_key_spki_sha256.clone(),
        commit_signature_algorithm: value.commit_signature_algorithm,
        commit_key_purpose: value.commit_key_purpose.clone(),
        committed_at_epoch_s: value.committed_at_epoch_s,
        evidence_issued_at_epoch_s: value.evidence_issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
        submission_recovery_deadline_epoch_s: value.submission_recovery_deadline_epoch_s,
        signed: signature(value),
    };
    result.signed.digest_sha256 = result.certificate_digest_sha256();
    result
}

fn signature(value: &ManagerCommitEvidenceDraftV2) -> CertificateReceiptSignatureV2 {
    CertificateReceiptSignatureV2 {
        key_id: value.commit_key_id.clone(),
        key_version: value.commit_key_version.clone(),
        public_key_spki_sha256: value.commit_public_key_spki_sha256.clone(),
        key_purpose: value.commit_key_purpose.clone(),
        algorithm: value.commit_signature_algorithm,
        digest_sha256: "00".repeat(32),
        signature_base64: STANDARD.encode([5_u8; 64]),
    }
}
