use std::fmt;

#[derive(Clone, Eq, PartialEq)]
pub struct WorkloadEvidenceV2 {
    schema: String,
    transport: String,
    evidence_base64: String,
}

impl WorkloadEvidenceV2 {
    /// Native adapters create evidence only after an authenticated IPC handshake.
    #[must_use]
    pub fn from_native_ipc(evidence_base64: impl Into<String>) -> Self {
        Self {
            schema: "crowsi://certificates/workload-evidence/v2".into(),
            transport: "native-ipc".into(),
            evidence_base64: evidence_base64.into(),
        }
    }

    pub(crate) fn parts(&self) -> (&str, &str, &str) {
        (&self.schema, &self.transport, &self.evidence_base64)
    }
}

impl fmt::Debug for WorkloadEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadEvidenceV2")
            .field("transport", &self.transport)
            .field("evidence", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedWorkloadV2 {
    pub service_id: String,
    pub workload_id: String,
    pub pairwise_subject: String,
    pub actor: String,
    pub device: String,
    pub profile: String,
    pub proof_key_ref: String,
    pub identity_revocation_epoch: u64,
    pub authenticated_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub transport: String,
    pub evidence_sha256: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedKeyEnrollmentV2 {
    pub public_key_spki_der: Vec<u8>,
    pub public_key_sha256: String,
    pub algorithm: String,
    pub proof_of_possession_verified: bool,
}

impl fmt::Debug for VerifiedKeyEnrollmentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedKeyEnrollmentV2")
            .field("public_key_spki_der", &"[REDACTED]")
            .field("public_key_sha256", &self.public_key_sha256)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedPublicCertificateV2 {
    pub metadata_digest_sha256: String,
    pub tbs_certificate_digest_sha256: String,
    pub signing_key_version: String,
    pub signing_public_key_spki_sha256: String,
    pub signature_encoding: String,
    pub signature_canonical: bool,
    pub high_s_rejected: bool,
    pub chain_verified: bool,
    pub profile_verified: bool,
    pub fingerprint_verified: bool,
}
