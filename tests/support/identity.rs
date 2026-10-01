use std::collections::VecDeque;

use crowsi_certificate_manager::*;

use super::{NOW, config};

pub struct SequenceClock(pub VecDeque<Result<u64, ClockError>>);
impl TrustedClock for SequenceClock {
    fn now_epoch_s(&mut self) -> Result<u64, ClockError> {
        self.0.pop_front().unwrap_or(Err(ClockError::Unavailable))
    }
}

pub struct WorkloadVerifier {
    fallback: VerifiedWorkloadV2,
    values: VecDeque<Result<VerifiedWorkloadV2, WorkloadIdentityError>>,
}

impl WorkloadVerifier {
    pub fn stable(value: VerifiedWorkloadV2) -> Self {
        Self {
            fallback: value,
            values: VecDeque::new(),
        }
    }

    pub fn sequence(fallback: VerifiedWorkloadV2, values: Vec<VerifiedWorkloadV2>) -> Self {
        Self {
            fallback,
            values: values.into_iter().map(Ok).collect(),
        }
    }
}

impl WorkloadIdentityVerifierPort for WorkloadVerifier {
    fn verify(
        &mut self,
        _: &WorkloadEvidenceV2,
    ) -> Result<VerifiedWorkloadV2, WorkloadIdentityError> {
        self.values
            .pop_front()
            .unwrap_or_else(|| Ok(self.fallback.clone()))
    }
}

pub fn workload() -> VerifiedWorkloadV2 {
    VerifiedWorkloadV2 {
        service_id: "service.nerp.local".into(),
        workload_id: "spiffe://crowsi.test/local/nerp".into(),
        pairwise_subject: "subject.pairwise.nerp".into(),
        actor: "actor.nerp.operator".into(),
        device: "device.local.0001".into(),
        profile: "profile.workload.operator".into(),
        proof_key_ref: "proof.key.local.0001".into(),
        identity_revocation_epoch: 9,
        authenticated_at_epoch_s: NOW - 10,
        expires_at_epoch_s: NOW + 120,
        transport: "native-ipc".into(),
        evidence_sha256: "22".repeat(32),
    }
}

pub struct AuthorizationVerifier(
    pub VecDeque<Result<VerifiedCertificateExecutionAuthorizationV2, AuthorizationError>>,
);
impl CertificateExecutionAuthorizationVerifierPort for AuthorizationVerifier {
    fn verify(
        &mut self,
        _: &SignedCertificateExecutionAuthorizationV2,
    ) -> Result<VerifiedCertificateExecutionAuthorizationV2, AuthorizationError> {
        self.0
            .pop_front()
            .unwrap_or(Err(AuthorizationError::Unavailable))
    }
}
