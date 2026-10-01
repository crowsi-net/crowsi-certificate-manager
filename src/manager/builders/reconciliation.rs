use crate::{
    AuthorityReadinessV2, AuthorityReconciliationCommandV2, OriginalAuthorityExecutionBindingV2,
    ReconciliationAuthorityBindingV2, ReconciliationContextV2, ReconciliationQueryV2,
};

pub fn authority_reconciliation_command(
    query: &ReconciliationQueryV2,
    context: &ReconciliationContextV2,
    readiness: &AuthorityReadinessV2,
    now: u64,
) -> Option<AuthorityReconciliationCommandV2> {
    let original = context.authority_command.as_ref()?;
    let current = &readiness.lease;
    if original.authority_receipt_key_id == current.key_id
        || original.authority_key_id == current.authority_receipt_key_id
        || original.authority_receipt_public_key_spki_sha256
            == current.authority_public_key_spki_sha256
        || original.authority_public_key_spki_sha256
            == current.authority_receipt_public_key_spki_sha256
    {
        return None;
    }
    Some(AuthorityReconciliationCommandV2 {
        query_id: query.query_id.clone(),
        authorization_jti: context.reconciliation_begin.authorization_jti.clone(),
        authorization_operation_id: context
            .reconciliation_begin
            .authorization
            .operation_id
            .clone(),
        authorization_lease_digest_sha256: context
            .reconciliation_begin
            .authorization
            .lease_digest_sha256
            .clone(),
        authorization_command_digest_sha256: context
            .reconciliation_begin
            .authorization_command_digest_sha256
            .clone(),
        original_action: query.original_action,
        original_authorization_jti: context.original_begin.authorization_jti.clone(),
        original_authorization_operation_id: context
            .original_begin
            .audit
            .authorization
            .operation_id
            .clone(),
        original_authorization_lease_digest_sha256: context
            .original_begin
            .audit
            .authorization
            .lease_digest_sha256
            .clone(),
        target_request_id: query.target_request_id.clone(),
        resource_id: query.resource_id.clone(),
        security_domain: context
            .original_begin
            .audit
            .authorization
            .security_domain
            .clone(),
        deployment_id: context
            .original_begin
            .audit
            .authorization
            .deployment_id
            .clone(),
        authority_command_digest_sha256: original.digest_sha256(),
        unknown_evidence_digest_sha256: query.expected_unknown_evidence_digest_sha256.clone(),
        reconciliation_authorization_ancestry_digest_sha256: context
            .reconciliation_begin
            .authorization
            .digest_sha256(),
        reconciliation_query_digest_sha256: context
            .reconciliation_begin
            .query_digest_sha256
            .clone(),
        expected_resource_version: context.reconciliation_begin.expected_resource_version,
        authorization_previous_fence: context.reconciliation_begin.authorization.previous_fence,
        authorization_current_fence: context.reconciliation_begin.authorization.current_fence,
        authorization_previous_lifecycle_revocation_epoch: context
            .reconciliation_begin
            .authorization
            .previous_lifecycle_revocation_epoch,
        authorization_lifecycle_revocation_epoch: context
            .reconciliation_begin
            .authorization
            .lifecycle_revocation_epoch,
        original_execution: OriginalAuthorityExecutionBindingV2::from_command(original),
        current_reconciliation: ReconciliationAuthorityBindingV2::from_lease(current),
        lifecycle_reservation_id: context.reservation.lifecycle.reservation_id.clone(),
        lifecycle_previous_fence: context.reservation.lifecycle.previous_fence,
        lifecycle_fence: context.reservation.lifecycle.current_fence,
        previous_lifecycle_revocation_epoch: context
            .reservation
            .lifecycle
            .prior_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: context
            .reservation
            .lifecycle
            .intent
            .lifecycle_revocation_epoch,
        requested_at_epoch_s: now,
    })
}
