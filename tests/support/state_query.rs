use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::StoreData;

pub fn operation_status(
    shared: &Arc<Mutex<StoreData>>,
    begin: &OperationStatusBeginV2,
) -> Result<AuditOperationStatusV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    let original = data.begin.as_ref().ok_or(OperationStateError::Rejected)?;
    if original.lifecycle.expected_resource_version != begin.expected_resource_version
        || original.lifecycle.lifecycle_revocation_epoch
            != begin.expected_lifecycle_revocation_epoch
    {
        return Err(OperationStateError::Conflict);
    }
    let snapshot = status(&data, &begin.status_query)?;
    super::state_helpers::reserve_keys(
        &mut data.replay_keys,
        &[
            &begin.query_id,
            &begin.nonce,
            &begin.authorization_id,
            &begin.authorization_jti,
            &begin.authorization_lease_digest_sha256,
        ],
    )?;
    Ok(snapshot)
}

pub fn status(
    data: &StoreData,
    query: &AuditStatusQueryV2,
) -> Result<AuditOperationStatusV2, OperationStateError> {
    let begin = data.begin.as_ref().ok_or(OperationStateError::Rejected)?;
    let intent = &begin.lifecycle;
    if begin.request_id != query.target_request_id
        || intent.resource_id != query.resource_id
        || intent.owner_service_id != query.owner_service_id
        || intent.owner_workload_id != query.owner_workload_id
        || intent.owner_subject != query.owner_subject
        || intent.owner_profile != query.owner_profile
        || intent.expected_resource_version != query.operation_expected_resource_version
        || intent.lifecycle_revocation_epoch != query.operation_lifecycle_revocation_epoch
    {
        return Err(OperationStateError::Ownership);
    }
    let phase = data.phase.ok_or(OperationStateError::Rejected)?;
    let authorization = data
        .last_reconciliation_begin
        .as_ref()
        .map_or(&begin.audit.authorization, |item| &item.authorization);
    let command_digest = data
        .authority_command
        .as_ref()
        .map(AuthorityCommandV2::digest_sha256);
    Ok(AuditOperationStatusV2 {
        request_id: begin.request_id.clone(),
        reservation_id: begin.lifecycle.required_reservation_id.clone(),
        resource_id: intent.resource_id.clone(),
        owner_service_id: intent.owner_service_id.clone(),
        owner_workload_id: intent.owner_workload_id.clone(),
        owner_subject: intent.owner_subject.clone(),
        owner_profile: intent.owner_profile.clone(),
        operation_expected_resource_version: intent.expected_resource_version,
        operation_lifecycle_revocation_epoch: intent.lifecycle_revocation_epoch,
        policy_authorization_ref: authorization.decision_id.clone(),
        policy_authorization_digest_sha256: authorization.decision_digest_sha256.clone(),
        operator_approval_evidence_ref: authorization.approval_id.clone().expect("approval"),
        operator_approval_evidence_digest_sha256: authorization
            .approval_evidence_digest_sha256
            .clone()
            .expect("approval"),
        operator_approval_method: authorization.approval_method.expect("approval"),
        operator_approval_assurance: authorization.approval_assurance.expect("approval"),
        operator_approval_verified_at_epoch_s: authorization
            .approval_verified_at_epoch_s
            .expect("approval"),
        state_revision: data.state_revision,
        state: phase,
        event_digest_sha256: data.event_digest_sha256.clone(),
        authority_command_digest_sha256: command_digest,
        abandon_reason: data.abandon_reason,
        abandon_receipt_digest_sha256: data.abandon_receipt_digest_sha256.clone(),
        reconciliation_receipt_digest_sha256: data.reconciliation_receipt_digest_sha256.clone(),
        reconciliation_authorization_digest_sha256: data
            .reconciliation_authorization_digest_sha256
            .clone(),
        reconciliation_query_digest_sha256: data.reconciliation_query_digest_sha256.clone(),
    })
}
