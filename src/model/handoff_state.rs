use super::{
    AuthorityCommandV2, AuthorityReadinessV2, ManagerHandoffReadbackV2, OperationReservationV2,
    VerifiedCertificateExecutionAuthorizationV2, VerifiedKeyCustodyAttestationV2,
    VerifiedKeyEnrollmentV2, VerifiedManagerHandoffV2, VerifiedWorkloadV2,
};

#[derive(Clone, Eq, PartialEq)]
pub struct HandoffResumeQueryV2 {
    pub request_id: String,
    pub command_digest_sha256: String,
    pub authorization_lease_digest_sha256: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationHandoffPendingV2 {
    pub source_state_revision: u64,
    pub query: HandoffResumeQueryV2,
    pub readback: ManagerHandoffReadbackV2,
    pub authority_command: AuthorityCommandV2,
    pub workload: VerifiedWorkloadV2,
    pub authorization: VerifiedCertificateExecutionAuthorizationV2,
    pub enrollment: Option<VerifiedKeyEnrollmentV2>,
    pub custody: Option<VerifiedKeyCustodyAttestationV2>,
    pub initial_readiness: AuthorityReadinessV2,
    pub readiness: AuthorityReadinessV2,
    pub staged_at_epoch_s: u64,
    pub recovery_deadline_epoch_s: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HandoffResumeContextV2 {
    pub reservation: OperationReservationV2,
    pub pending: OperationHandoffPendingV2,
    pub accepted: Option<VerifiedManagerHandoffV2>,
}
