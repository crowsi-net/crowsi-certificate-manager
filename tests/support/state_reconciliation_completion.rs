use crowsi_certificate_manager::*;

use super::StoreData;

pub(super) fn record(
    data: &mut StoreData,
    context: &ReconciliationContextV2,
    resolution: &ReconciliationStateResolutionV2,
) {
    let evidence = &resolution.verified.completion_evidence;
    data.completion_commits.push(CompletionCommitReadbackV2 {
        completion_id: format!("completion.{}", evidence.evidence_id),
        state_record_id: format!("audit.record.{}", evidence.evidence_id),
        state_event_digest_sha256: resolution.verified.receipt_digest_sha256.clone(),
        state_revision: data.state_revision,
        resource_version: context.status.operation_expected_resource_version,
        committed_at_epoch_s: resolution.verified.observed_at_epoch_s,
        authority_evidence: evidence.clone(),
    });
}
