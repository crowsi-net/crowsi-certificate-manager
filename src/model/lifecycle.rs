use serde::{Deserialize, Serialize};

use super::{CertificateMetadataV2, CertificateOperation, UnknownReasonV2};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleStateV2 {
    Absent,
    Active,
    Revoked,
    Expired,
}

impl LifecycleStateV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleReservationIntentV2 {
    pub request_id: String,
    pub authorization_id: String,
    pub required_reservation_id: String,
    pub command_digest_sha256: String,
    pub operation: CertificateOperation,
    pub resource_id: String,
    pub target_certificate_id: Option<String>,
    pub owner_service_id: String,
    pub owner_workload_id: String,
    pub owner_subject: String,
    pub owner_profile: String,
    pub certificate_subject: String,
    pub certificate_profile: String,
    pub expected_resource_version: u64,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleReservationV2 {
    pub reservation_id: String,
    pub intent: LifecycleReservationIntentV2,
    pub prior_state: LifecycleStateV2,
    pub prior_certificate_id: Option<String>,
    pub prior_metadata: Option<CertificateMetadataV2>,
    pub prior_resource_version: u64,
    pub prior_lifecycle_revocation_epoch: u64,
    pub reserved_resource_version: u64,
    pub previous_fence: u64,
    pub current_fence: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleCommitV2 {
    pub reservation_id: String,
    pub authority_command_digest_sha256: String,
    pub authority_outcome_digest_sha256: String,
    pub resulting_metadata: CertificateMetadataV2,
    pub resulting_state: LifecycleStateV2,
    pub resulting_resource_version: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRecordV2 {
    pub resource_id: String,
    pub owner_service_id: String,
    pub owner_workload_id: String,
    pub owner_subject: String,
    pub owner_profile: String,
    pub certificate_id: Option<String>,
    pub state: LifecycleStateV2,
    pub resource_version: u64,
    pub fence: u64,
    pub lifecycle_revocation_epoch: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleUnknownV2 {
    pub reservation_id: String,
    pub authority_command_digest_sha256: String,
    pub reason: UnknownReasonV2,
}
