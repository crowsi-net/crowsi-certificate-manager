use serde::{Deserialize, Serialize};

use super::super::CertificateOperation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateLifecycleActionV2 {
    Issue,
    Renew,
    Revoke,
}

impl CertificateLifecycleActionV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateAuthorizedActionV2 {
    Issue,
    Renew,
    Revoke,
    CertificateStatus,
    OperationStatus,
    ReconcileUnknown,
}

impl CertificateAuthorizedActionV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
            Self::CertificateStatus => "certificate-status",
            Self::OperationStatus => "operation-status",
            Self::ReconcileUnknown => "reconcile-unknown",
        }
    }
}

impl From<CertificateOperation> for CertificateAuthorizedActionV2 {
    fn from(value: CertificateOperation) -> Self {
        match value {
            CertificateOperation::Issue => Self::Issue,
            CertificateOperation::Renew => Self::Renew,
            CertificateOperation::Revoke => Self::Revoke,
            CertificateOperation::Status => Self::CertificateStatus,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateApprovalMethodV2 {
    AuthenticatedSession,
    LocalUserPresence,
    HardwareBackedUserPresence,
}

impl CertificateApprovalMethodV2 {
    #[must_use]
    pub const fn has_user_presence(self) -> bool {
        matches!(
            self,
            Self::LocalUserPresence | Self::HardwareBackedUserPresence
        )
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedSession => "authenticated-session",
            Self::LocalUserPresence => "local-user-presence",
            Self::HardwareBackedUserPresence => "hardware-backed-user-presence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateApprovalAssuranceV2 {
    Aal2,
    Aal3,
}

impl CertificateApprovalAssuranceV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aal2 => "aal2",
            Self::Aal3 => "aal3",
        }
    }
}
