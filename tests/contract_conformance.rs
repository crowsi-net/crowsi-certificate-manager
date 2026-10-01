use crate::support;

use crowsi_certificate_manager::{
    CertificateApprovalAssuranceV2, CertificateApprovalMethodV2, CertificateAuthorizedActionV2,
    VerifiedCertificateExecutionAuthorizationV2,
};
use crowsi_control_contracts::{
    CertificateActionV2, CertificateApprovalAssuranceV2 as ContractAssurance,
    CertificateApprovalMethodV2 as ContractMethod,
    VerifiedCertificateExecutionAuthorizationV2 as ContractAuthorization,
};
use support::{
    adapt_contract_authorization, contract_action, contract_approval_assurance,
    contract_approval_method,
};

#[test]
fn control_contract_authorization_has_a_compile_checked_adapter() {
    let adapter: fn(ContractAuthorization) -> Option<VerifiedCertificateExecutionAuthorizationV2> =
        adapt_contract_authorization;
    assert_eq!(
        contract_action(CertificateActionV2::OperationStatus),
        CertificateAuthorizedActionV2::OperationStatus
    );
    assert_eq!(
        contract_approval_method(ContractMethod::HardwareBackedUserPresence),
        CertificateApprovalMethodV2::HardwareBackedUserPresence
    );
    assert_eq!(
        contract_approval_assurance(ContractAssurance::Aal3),
        CertificateApprovalAssuranceV2::Aal3
    );
    let _ = adapter;
}
