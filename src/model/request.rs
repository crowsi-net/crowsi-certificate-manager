use std::fmt;

use serde::{Deserialize, Serialize};

use super::KeyEnrollmentV2;
use crate::digest::DigestBuilder;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateOperation {
    Issue,
    Renew,
    Revoke,
    Status,
}

impl CertificateOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
            Self::Status => "status",
        }
    }

    #[must_use]
    pub const fn requires_key_enrollment(self) -> bool {
        matches!(self, Self::Issue | Self::Renew)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateCommandV2 {
    pub schema: String,
    pub request_id: String,
    pub nonce: String,
    pub operation: CertificateOperation,
    pub resource_id: String,
    pub expected_resource_version: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub profile_id: String,
    pub purpose: String,
    pub subject: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub requested_ttl_seconds: u64,
    pub target_certificate_id: Option<String>,
    pub key_enrollment: Option<KeyEnrollmentV2>,
}

impl CertificateCommandV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-command-v2");
        for value in [
            &self.schema,
            &self.request_id,
            &self.nonce,
            self.operation.as_str(),
            &self.resource_id,
        ] {
            digest.text(value);
        }
        digest.number(self.expected_resource_version);
        digest.number(self.previous_lifecycle_revocation_epoch);
        digest.number(self.lifecycle_revocation_epoch);
        for value in [
            &self.profile_id,
            &self.purpose,
            &self.subject,
            &self.audience,
        ] {
            digest.text(value);
        }
        digest.number(u64::try_from(self.scopes.len()).unwrap_or(u64::MAX));
        for scope in &self.scopes {
            digest.text(scope);
        }
        digest.number(self.requested_ttl_seconds);
        digest.optional(self.target_certificate_id.as_deref());
        match &self.key_enrollment {
            Some(value) => value.add_to_digest(&mut digest),
            None => digest.text("no-enrollment"),
        }
        digest.finish()
    }
}

impl fmt::Debug for CertificateCommandV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateCommandV2")
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("resource_id", &self.resource_id)
            .field("key_enrollment", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
