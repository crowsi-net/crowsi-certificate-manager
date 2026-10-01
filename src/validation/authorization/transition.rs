use crate::{CertificateAuthorizedActionV2, VerifiedCertificateExecutionAuthorizationV2};

pub const fn requires_user_presence(action: CertificateAuthorizedActionV2) -> bool {
    matches!(
        action,
        CertificateAuthorizedActionV2::Issue
            | CertificateAuthorizedActionV2::Renew
            | CertificateAuthorizedActionV2::Revoke
            | CertificateAuthorizedActionV2::ReconcileUnknown
    )
}

pub fn valid_lifecycle_epoch(value: &VerifiedCertificateExecutionAuthorizationV2) -> bool {
    let previous = value.previous_lifecycle_revocation_epoch;
    let current = value.lifecycle_revocation_epoch;
    match value.action {
        CertificateAuthorizedActionV2::Issue => previous == 0 && current == 0,
        CertificateAuthorizedActionV2::Renew
        | CertificateAuthorizedActionV2::CertificateStatus
        | CertificateAuthorizedActionV2::OperationStatus => previous == current,
        CertificateAuthorizedActionV2::Revoke => previous.checked_add(1) == Some(current),
        CertificateAuthorizedActionV2::ReconcileUnknown => {
            previous == current || previous.checked_add(1) == Some(current)
        }
    }
}

pub fn valid_fence(value: &VerifiedCertificateExecutionAuthorizationV2) -> bool {
    match value.action {
        CertificateAuthorizedActionV2::CertificateStatus
        | CertificateAuthorizedActionV2::OperationStatus => {
            value.previous_fence == value.current_fence
        }
        CertificateAuthorizedActionV2::Issue
        | CertificateAuthorizedActionV2::Renew
        | CertificateAuthorizedActionV2::Revoke
        | CertificateAuthorizedActionV2::ReconcileUnknown => {
            value.previous_fence.checked_add(1) == Some(value.current_fence)
        }
    }
}
