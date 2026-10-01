use std::sync::{Arc, Mutex};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use crowsi_certificate_manager::*;
use crowsi_control_contracts::{
    CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2, CertificateManagerHandoffDispositionV2,
    CertificateManagerHandoffEvidenceV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
};

#[derive(Default)]
pub struct HandoffState {
    pub calls: usize,
    pub result_unknown_once: bool,
    pub not_accepted: bool,
}

pub struct Handoff(pub Arc<Mutex<HandoffState>>);

impl CertificateManagerHandoffPort for Handoff {
    fn accept(
        &mut self,
        readback: &ManagerHandoffReadbackV2,
    ) -> Result<VerifiedManagerHandoffV2, HandoffError> {
        let mut state = self.0.lock().expect("handoff");
        state.calls += 1;
        if state.result_unknown_once {
            state.result_unknown_once = false;
            return Err(HandoffError::ResultUnknown);
        }
        Ok(verified(readback, state.not_accepted))
    }
}

pub fn accepted_handoff() -> Handoff {
    Handoff(Arc::new(Mutex::new(HandoffState::default())))
}

pub fn configured_handoff(
    result_unknown_once: bool,
    not_accepted: bool,
) -> (Handoff, Arc<Mutex<HandoffState>>) {
    let state = Arc::new(Mutex::new(HandoffState {
        result_unknown_once,
        not_accepted,
        ..HandoffState::default()
    }));
    (Handoff(Arc::clone(&state)), state)
}

fn verified(readback: &ManagerHandoffReadbackV2, rejected: bool) -> VerifiedManagerHandoffV2 {
    let disposition = if rejected {
        CertificateManagerHandoffDispositionV2::NotAccepted
    } else {
        CertificateManagerHandoffDispositionV2::Accepted
    };
    let observed = if rejected {
        readback.expires_at_epoch_s
    } else {
        readback.reserved_at_epoch_s
    };
    let mut evidence = CertificateManagerHandoffEvidenceV2 {
        schema: CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2.into(),
        receipt_id: readback.receipt_id.clone(),
        nonce_base64: URL_SAFE_NO_PAD.encode([4_u8; 32]),
        issuer: "service://crowsi/certificate-manager".into(),
        audience: "service://crowsi/policy-administrator".into(),
        disposition,
        action: readback.action,
        authorization_jti: readback.authorization_jti.clone(),
        operation_id: readback.operation_id.clone(),
        lease_digest_sha256: readback.lease_digest_sha256.clone(),
        authorization_command_digest_sha256: readback.authorization_command_digest_sha256.clone(),
        security_domain: readback.security_domain.clone(),
        deployment_id: readback.deployment_id.clone(),
        trust_revision: readback.trust_revision,
        target_resource_id: readback.target_resource_id.clone(),
        expected_resource_version: readback.expected_resource_version,
        previous_fence: readback.previous_fence,
        current_fence: readback.current_fence,
        previous_lifecycle_revocation_epoch: readback.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: readback.lifecycle_revocation_epoch,
        manager_workload: "spiffe://crowsi.test/local/certificate-manager".into(),
        receipt_key_id: "key.manager.handoff".into(),
        receipt_key_version: "key.version.manager.handoff.0001".into(),
        receipt_public_key_spki_sha256: "47".repeat(32),
        receipt_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        receipt_key_purpose: "certificate-manager-handoff-receipt".into(),
        observed_at_epoch_s: observed,
        expires_at_epoch_s: observed + 60,
        signed: signature(),
    };
    evidence.signed.digest_sha256 = evidence.certificate_digest_sha256();
    let state = if rejected { "abandoned" } else { "executing" };
    VerifiedManagerHandoffV2 {
        acknowledgement: CertificateHandoffReceiptAckV2 {
            authorization_jti: evidence.authorization_jti.clone(),
            receipt_id: evidence.receipt_id.clone(),
            evidence_digest_sha256: evidence.certificate_digest_sha256(),
            disposition: evidence.disposition.as_str().into(),
            resulting_state: state.into(),
            recorded_at_epoch_s: observed,
        },
        evidence,
    }
}

fn signature() -> CertificateReceiptSignatureV2 {
    CertificateReceiptSignatureV2 {
        key_id: "key.manager.handoff".into(),
        key_version: "key.version.manager.handoff.0001".into(),
        public_key_spki_sha256: "47".repeat(32),
        key_purpose: "certificate-manager-handoff-receipt".into(),
        algorithm: CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        digest_sha256: "00".repeat(32),
        signature_base64: STANDARD.encode([3_u8; 64]),
    }
}
