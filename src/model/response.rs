use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    CertificateMetadataV2, CertificateOperation, CertificateState, LifecycleRecordV2,
    OperationReceiptV2, PublicCertificateV2,
};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateResponseV2 {
    pub request_id: String,
    pub operation: CertificateOperation,
    pub state: CertificateState,
    pub metadata: CertificateMetadataV2,
    pub public_certificate: Option<PublicCertificateV2>,
    pub lifecycle: LifecycleRecordV2,
    pub receipt: OperationReceiptV2,
}

impl fmt::Debug for CertificateResponseV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateResponseV2")
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("state", &self.state)
            .field("certificate_id", &self.metadata.certificate_id)
            .field("public_certificate", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
