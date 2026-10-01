use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCertificateExecutionAuthorizationV2 {
    schema: String,
    verifier_key_id: String,
    pa_pep_lease_base64: String,
    lease_digest_sha256: String,
    signature_base64: String,
}

impl SignedCertificateExecutionAuthorizationV2 {
    #[must_use]
    pub fn new(
        verifier_key_id: impl Into<String>,
        pa_pep_lease_base64: impl Into<String>,
        lease_digest_sha256: impl Into<String>,
        signature_base64: impl Into<String>,
    ) -> Self {
        Self {
            schema: "crowsi://certificates/execution-authorization/v2".into(),
            verifier_key_id: verifier_key_id.into(),
            pa_pep_lease_base64: pa_pep_lease_base64.into(),
            lease_digest_sha256: lease_digest_sha256.into(),
            signature_base64: signature_base64.into(),
        }
    }

    pub(crate) fn parts(&self) -> (&str, &str, &str, &str, &str) {
        (
            &self.schema,
            &self.verifier_key_id,
            &self.pa_pep_lease_base64,
            &self.lease_digest_sha256,
            &self.signature_base64,
        )
    }

    pub(crate) fn lease_digest_sha256(&self) -> &str {
        &self.lease_digest_sha256
    }
}

impl fmt::Debug for SignedCertificateExecutionAuthorizationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedCertificateExecutionAuthorizationV2")
            .field("verifier_key_id", &self.verifier_key_id)
            .field("pa_pep_lease", &"[REDACTED]")
            .field("lease_digest_sha256", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
