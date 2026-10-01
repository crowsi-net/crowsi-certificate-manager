use std::fmt;

use serde::{Deserialize, Serialize};

use super::super::AuthorityOutcomeV2;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityReconciliationReceiptV2 {
    pub schema: String,
    pub key_id: String,
    pub payload_base64: String,
    pub signature_base64: String,
}

impl fmt::Debug for SignedAuthorityReconciliationReceiptV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAuthorityReconciliationReceiptV2")
            .field("key_id", &self.key_id)
            .field("payload", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityReconciliationDispositionV2 {
    NotExecuted,
    Completed,
    StillUnknown,
}

impl AuthorityReconciliationDispositionV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotExecuted => "not-executed",
            Self::Completed => "completed",
            Self::StillUnknown => "still-unknown",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityReconciliationOutcomeV2 {
    pub disposition: AuthorityReconciliationDispositionV2,
    pub authority_outcome: Option<AuthorityOutcomeV2>,
    pub signed_receipt: SignedAuthorityReconciliationReceiptV2,
}

impl fmt::Debug for AuthorityReconciliationOutcomeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityReconciliationOutcomeV2")
            .field("disposition", &self.disposition)
            .field("authority_outcome", &"[REDACTED]")
            .field("signed_receipt", &self.signed_receipt)
            .finish()
    }
}
