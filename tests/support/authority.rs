use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crowsi_certificate_manager::*;

use super::{NOW, outcome};

pub struct ReadinessVerifier(pub VecDeque<AuthorityReadinessV2>);
impl AuthorityReadinessVerifierPort for ReadinessVerifier {
    fn verify(
        &mut self,
        _: &SignedAuthorityReadinessAttestationV2,
    ) -> Result<AuthorityReadinessV2, AuthorityOutcomeError> {
        self.0.pop_front().ok_or(AuthorityOutcomeError::Unavailable)
    }
}

pub fn readiness(fence: u64) -> AuthorityReadinessV2 {
    AuthorityReadinessV2 {
        authority_state: ReadinessState::Ready,
        key_provider_state: ReadinessState::Ready,
        attestation_state: AttestationState::Verified,
        lease: AuthorityAttestationLeaseV2 {
            lease_id: format!("authority.lease.{fence:04}"),
            security_domain: "security.crowsi".into(),
            deployment_id: "deployment.local".into(),
            authority_id: "authority.crowsi.production".into(),
            key_id: "key.certificate.authority".into(),
            authority_key_version: "key.version.ca.0003".into(),
            authority_public_key_spki_sha256: "41".repeat(32),
            signature_algorithm: "ecdsa-p256-sha256".into(),
            key_provider_signature_profile: "ecdsa-p256-sha256-p1363-low-s".into(),
            key_purpose: "workload-certificate-issuance".into(),
            authority_receipt_key_id: "key.authority.receipt".into(),
            authority_receipt_key_version: "key.version.receipt.0007".into(),
            authority_receipt_public_key_spki_sha256: "42".repeat(32),
            authority_receipt_signature_algorithm: "ecdsa-p256-sha256-p1363-low-s".into(),
            authority_receipt_key_purpose: "certificate-authority-receipt".into(),
            verifier_key_id: "key.attestation.verifier".into(),
            verifier_key_version: "key.version.attestation.0002".into(),
            verifier_public_key_spki_sha256: "43".repeat(32),
            verifier_signature_algorithm: "ed25519".into(),
            verifier_key_purpose: "authority-readiness-attestation".into(),
            trust_revision: 7,
            attestation_digest_sha256: format!("{fence:064x}"),
            fence,
            issued_at_epoch_s: NOW - 10 + fence,
            expires_at_epoch_s: NOW + 60 + fence,
        },
    }
}

pub struct AuthorityState {
    pub executed: Vec<AuthorityCommandV2>,
    pub executed_at_epoch_s: Vec<u64>,
    pub execute_error: Option<AuthorityError>,
    pub reconciliation: AuthorityReconciliationDispositionV2,
    pub reconciled: Vec<AuthorityReconciliationCommandV2>,
    pub executed_at_override: Option<u64>,
    pub not_before_override: Option<u64>,
    pub expires_override: Option<u64>,
    pub invalid_certificate_signature: bool,
}

pub struct Authority {
    pub state: Arc<Mutex<AuthorityState>>,
}

impl CertificateAuthorityPort for Authority {
    fn readiness(&mut self) -> Result<SignedAuthorityReadinessAttestationV2, AuthorityError> {
        Ok(SignedAuthorityReadinessAttestationV2::new(
            "key.attestation.verifier",
            "cmVhZGluZXNz",
            "c2lnbmF0dXJl",
        ))
    }

    fn execute(
        &mut self,
        command: &AuthorityCommandV2,
        invoked_at_epoch_s: u64,
    ) -> Result<AuthorityOutcomeV2, AuthorityError> {
        let mut state = self.state.lock().expect("authority state");
        let executed_at_epoch_s = state.executed_at_override.unwrap_or(invoked_at_epoch_s);
        state.executed.push(command.clone());
        state.executed_at_epoch_s.push(executed_at_epoch_s);
        if let Some(error) = state.execute_error {
            return Err(error);
        }
        let mut result = outcome(command, executed_at_epoch_s);
        if let Some(value) = state.not_before_override {
            result.metadata.not_before_epoch_s = value;
        }
        if let Some(value) = state.expires_override {
            result.metadata.expires_at_epoch_s = value;
        }
        if let Some(certificate) = result.public_certificate.as_mut() {
            certificate.metadata = result.metadata.clone();
            if state.invalid_certificate_signature {
                certificate.certificate_der_base64 = "aGlnaC1z".into();
            }
        }
        Ok(result)
    }

    fn reconcile(
        &mut self,
        command: &AuthorityReconciliationCommandV2,
    ) -> Result<AuthorityReconciliationOutcomeV2, AuthorityError> {
        let mut state = self.state.lock().expect("authority state");
        state.reconciled.push(command.clone());
        let recovered = (state.reconciliation == AuthorityReconciliationDispositionV2::Completed)
            .then(|| {
                state
                    .executed
                    .last()
                    .zip(state.executed_at_epoch_s.last())
                    .map(|(original, executed)| outcome(original, *executed))
            })
            .flatten();
        Ok(AuthorityReconciliationOutcomeV2 {
            disposition: state.reconciliation,
            authority_outcome: recovered,
            signed_receipt: SignedAuthorityReconciliationReceiptV2 {
                schema: "crowsi://certificates/authority-reconciliation-receipt/v2".into(),
                key_id: command
                    .current_reconciliation
                    .receipt_signing_key_id
                    .clone(),
                payload_base64: "cmVjb25jaWxpYXRpb24=".into(),
                signature_base64: "c2lnbmF0dXJl".into(),
            },
        })
    }
}

pub fn authority() -> (Authority, Arc<Mutex<AuthorityState>>) {
    let state = Arc::new(Mutex::new(AuthorityState {
        executed: Vec::new(),
        executed_at_epoch_s: Vec::new(),
        execute_error: None,
        reconciliation: AuthorityReconciliationDispositionV2::StillUnknown,
        reconciled: Vec::new(),
        executed_at_override: None,
        not_before_override: None,
        expires_override: None,
        invalid_certificate_signature: false,
    }));
    (
        Authority {
            state: Arc::clone(&state),
        },
        state,
    )
}
