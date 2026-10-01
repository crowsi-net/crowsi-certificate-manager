use crate::{
    AuthorizationError, ClockError, KeyCustodyError, KeyEnrollmentError, KeyEnrollmentV2,
    SignedCertificateExecutionAuthorizationV2, SignedKeyCustodyAttestationV2,
    VerifiedCertificateExecutionAuthorizationV2, VerifiedKeyCustodyAttestationV2,
    VerifiedKeyEnrollmentV2, VerifiedWorkloadV2, WorkloadEvidenceV2, WorkloadIdentityError,
};

pub trait TrustedClock {
    /// Returns rollback-resistant time owned by the local trust boundary.
    ///
    /// # Errors
    ///
    /// Fails when freshness or monotonicity cannot be established.
    fn now_epoch_s(&mut self) -> Result<u64, ClockError>;
}

pub trait WorkloadIdentityVerifierPort {
    /// Converts transport evidence to authenticated workload and device claims.
    ///
    /// # Errors
    ///
    /// Fails closed when transport identity cannot be independently verified.
    fn verify(
        &mut self,
        evidence: &WorkloadEvidenceV2,
    ) -> Result<VerifiedWorkloadV2, WorkloadIdentityError>;
}

pub trait CertificateExecutionAuthorizationVerifierPort {
    /// Bridges PA/PEP V2 signed policy, identity, grant, lease, fence, and CAS state.
    /// Verification is repeatable cryptographic validation plus a current
    /// revocation check; one-use consumption belongs only to the state transaction.
    /// Privileged claims must be derived from independently verified, one-use,
    /// phishing-resistant signed approval evidence bound to the exact request,
    /// action, actor, device, and canonical target. The verifier also proves
    /// provider-scoped normalization by independently replaying the proof with
    /// the configured implementation and version; callers may never self-assert
    /// the flattened approval, proof-verification, or target fields.
    ///
    /// # Errors
    ///
    /// Legacy envelopes and locally self-asserted claims must be rejected.
    fn verify(
        &mut self,
        authorization: &SignedCertificateExecutionAuthorizationV2,
    ) -> Result<VerifiedCertificateExecutionAuthorizationV2, AuthorizationError>;
}

pub trait KeyEnrollmentVerifierPort {
    /// Verifies the public key and proof of possession without receiving a private key.
    ///
    /// # Errors
    ///
    /// Rejects malformed enrollment or an invalid proof of possession.
    fn verify(
        &mut self,
        enrollment: &KeyEnrollmentV2,
    ) -> Result<VerifiedKeyEnrollmentV2, KeyEnrollmentError>;
}

pub trait KeyCustodyAttestationVerifierPort {
    /// Verifies device-backed non-exportable custody for the enrolled public key.
    ///
    /// # Errors
    ///
    /// Rejects exportable, stale, foreign-device, or unbound attestations.
    fn verify(
        &mut self,
        attestation: &SignedKeyCustodyAttestationV2,
    ) -> Result<VerifiedKeyCustodyAttestationV2, KeyCustodyError>;
}
