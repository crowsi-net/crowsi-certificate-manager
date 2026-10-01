use crowsi_certificate_manager::{
    CertificateApprovalAssuranceV2 as ManagerAssurance,
    CertificateApprovalMethodV2 as ManagerMethod,
    CertificateAuthorizationOperationBindingV2 as ManagerOperation,
    CertificateAuthorizedActionV2 as ManagerAction,
    CertificateLifecycleActionV2 as ManagerLifecycle,
};
use crowsi_control_contracts::{
    CertificateActionV2 as ContractAction, CertificateApprovalAssuranceV2 as ContractAssurance,
    CertificateApprovalMethodV2 as ContractMethod,
    CertificateLifecycleActionV2 as ContractLifecycle,
    VerifiedCertificateExecutionAuthorizationV2 as Contract,
};

pub fn contract_action(value: ContractAction) -> ManagerAction {
    match value {
        ContractAction::Issue => ManagerAction::Issue,
        ContractAction::Renew => ManagerAction::Renew,
        ContractAction::Revoke => ManagerAction::Revoke,
        ContractAction::CertificateStatus => ManagerAction::CertificateStatus,
        ContractAction::OperationStatus => ManagerAction::OperationStatus,
        ContractAction::ReconcileUnknown => ManagerAction::ReconcileUnknown,
    }
}

pub fn contract_approval_method(value: ContractMethod) -> ManagerMethod {
    match value {
        ContractMethod::AuthenticatedSession => ManagerMethod::AuthenticatedSession,
        ContractMethod::LocalUserPresence => ManagerMethod::LocalUserPresence,
        ContractMethod::HardwareBackedUserPresence => ManagerMethod::HardwareBackedUserPresence,
    }
}

pub fn contract_approval_assurance(value: ContractAssurance) -> ManagerAssurance {
    match value {
        ContractAssurance::Aal2 => ManagerAssurance::Aal2,
        ContractAssurance::Aal3 => ManagerAssurance::Aal3,
    }
}

fn lifecycle(value: ContractLifecycle) -> ManagerLifecycle {
    match value {
        ContractLifecycle::Issue => ManagerLifecycle::Issue,
        ContractLifecycle::Renew => ManagerLifecycle::Renew,
        ContractLifecycle::Revoke => ManagerLifecycle::Revoke,
    }
}

// Outer None rejects an invalid projection; inner None is a valid lifecycle action.
#[allow(clippy::option_option)]
pub fn contract_operation(value: &Contract) -> Option<Option<ManagerOperation>> {
    match value.action {
        ContractAction::OperationStatus => Some(Some(ManagerOperation::OperationStatus {
            target_operation_id: value.target_operation_id.clone()?,
        })),
        ContractAction::ReconcileUnknown => Some(Some(ManagerOperation::ReconcileUnknown {
            original_action: lifecycle(value.original_action?),
            target_operation_id: value.target_operation_id.clone()?,
            lifecycle_reservation_id: value.lifecycle_reservation_id.clone()?,
            authority_command_digest_sha256: value.authority_command_digest_sha256.clone()?,
            unknown_evidence_digest_sha256: value.unknown_evidence_digest_sha256.clone()?,
            locked_previous_fence: value.locked_previous_fence?,
            locked_current_fence: value.locked_current_fence?,
            locked_previous_lifecycle_revocation_epoch: value
                .locked_previous_lifecycle_revocation_epoch?,
            locked_lifecycle_revocation_epoch: value.locked_lifecycle_revocation_epoch?,
        })),
        _ => no_operation_fields(value).then_some(None),
    }
}

fn no_operation_fields(value: &Contract) -> bool {
    value.target_operation_id.is_none()
        && value.original_action.is_none()
        && value.lifecycle_reservation_id.is_none()
        && value.authority_command_digest_sha256.is_none()
        && value.unknown_evidence_digest_sha256.is_none()
        && value.locked_previous_fence.is_none()
        && value.locked_current_fence.is_none()
        && value.locked_previous_lifecycle_revocation_epoch.is_none()
        && value.locked_lifecycle_revocation_epoch.is_none()
}
