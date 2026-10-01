use crowsi_certificate_manager::*;
use crowsi_control_contracts::CertificatePayloadV2;

use super::*;

pub fn make_unknown(command: &CertificateCommandV2) -> Harness {
    let mut initial = harness(command);
    initial.state.lock().expect("state").fail_finalize = true;
    assert_eq!(
        initial.manager.execute_mutation(
            &evidence(),
            command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuthorityResultUnknown)
    );
    initial.state.lock().expect("state").fail_finalize = false;
    initial
}

pub fn reconciliation_query_for(
    command: &CertificateCommandV2,
    state: &std::sync::Arc<std::sync::Mutex<StoreData>>,
) -> ReconciliationQueryV2 {
    let digest = state
        .lock()
        .expect("state")
        .authority_command
        .as_ref()
        .expect("authority command")
        .digest_sha256();
    reconciliation_query(command, digest)
}

pub fn reconciliation_receipt(
    value: &AuthorityReconciliationOutcomeV2,
    command: &AuthorityReconciliationCommandV2,
) -> VerifiedAuthorityReconciliationV2 {
    let completion_evidence = super::reconciliation_evidence(command, value);
    let receipt_digest_sha256 = completion_evidence.certificate_digest_sha256();
    VerifiedAuthorityReconciliationV2 {
        completion_evidence,
        query_id: command.query_id.clone(),
        original_action: command.original_action,
        reconciliation_command_digest_sha256: command.digest_sha256(),
        authority_command_digest_sha256: command.authority_command_digest_sha256.clone(),
        unknown_evidence_digest_sha256: command.unknown_evidence_digest_sha256.clone(),
        disposition: value.disposition,
        authority_outcome_digest_sha256: value
            .authority_outcome
            .as_ref()
            .map(AuthorityOutcomeV2::digest_sha256),
        reconciliation_authorization_ancestry_digest_sha256: command
            .reconciliation_authorization_ancestry_digest_sha256
            .clone(),
        reconciliation_query_digest_sha256: command.reconciliation_query_digest_sha256.clone(),
        expected_resource_version: command.expected_resource_version,
        original_execution: command.original_execution.clone(),
        current_reconciliation: command.current_reconciliation.clone(),
        security_domain: command.security_domain.clone(),
        deployment_id: command.deployment_id.clone(),
        signature_key_id: command
            .current_reconciliation
            .receipt_signing_key_id
            .clone(),
        signature_algorithm: command
            .current_reconciliation
            .receipt_signature_algorithm
            .clone(),
        key_purpose: command.current_reconciliation.receipt_key_purpose.clone(),
        lifecycle_reservation_id: command.lifecycle_reservation_id.clone(),
        lifecycle_previous_fence: command.lifecycle_previous_fence,
        lifecycle_fence: command.lifecycle_fence,
        previous_lifecycle_revocation_epoch: command.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: command.lifecycle_revocation_epoch,
        observed_at_epoch_s: command.requested_at_epoch_s + 1,
        receipt_digest_sha256,
        signature_verified: true,
    }
}
