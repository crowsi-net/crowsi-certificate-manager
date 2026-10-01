use crate::digest::DigestBuilder;

use super::AuditStatusQueryV2;

#[derive(Clone, Eq, PartialEq)]
pub struct OperationStatusQueryV2 {
    pub query_id: String,
    pub nonce: String,
    pub target_request_id: String,
    pub resource_id: String,
    pub owner_subject: String,
    pub owner_profile: String,
    pub expected_resource_version: u64,
    pub expected_lifecycle_revocation_epoch: u64,
}

impl OperationStatusQueryV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-operation-status-query-v2");
        for value in [
            &self.query_id,
            &self.nonce,
            &self.target_request_id,
            &self.resource_id,
            &self.owner_subject,
            &self.owner_profile,
        ] {
            digest.text(value);
        }
        digest.number(self.expected_resource_version);
        digest.number(self.expected_lifecycle_revocation_epoch);
        digest.finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationStatusBeginV2 {
    pub query_id: String,
    pub nonce: String,
    pub authorization_id: String,
    pub authorization_jti: String,
    pub authorization_lease_digest_sha256: String,
    pub query_digest_sha256: String,
    pub expected_resource_version: u64,
    pub expected_lifecycle_revocation_epoch: u64,
    pub status_query: AuditStatusQueryV2,
}
