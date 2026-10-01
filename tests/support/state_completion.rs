use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;
use crowsi_control_contracts::CertificateManagerCommitEvidenceV2;

use super::StoreData;

impl CompletionOutboxStorePort for super::StateStore {
    fn next_completion_commit(
        &mut self,
    ) -> Result<Option<CompletionCommitReadbackV2>, CompletionStateError> {
        next(&self.0)
    }

    fn recover_completion_signing(
        &mut self,
        commit: &CompletionCommitReadbackV2,
    ) -> Result<Option<CompletionSigningWorkV2>, CompletionStateError> {
        recover(&self.0, commit)
    }

    fn begin_completion_signing(
        &mut self,
        commit: &CompletionCommitReadbackV2,
        draft: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CompletionSigningWorkV2, CompletionStateError> {
        begin(&self.0, commit, draft)
    }

    fn stage_completion_delivery(
        &mut self,
        work: &CompletionSigningWorkV2,
        evidence: &CertificateManagerCommitEvidenceV2,
    ) -> Result<(), CompletionStateError> {
        stage(&self.0, work, evidence)
    }

    fn next_completion_delivery(
        &mut self,
    ) -> Result<Option<CompletionDeliveryItemV2>, CompletionStateError> {
        super::state_completion_delivery::next(&self.0)
    }

    fn begin_completion_delivery(
        &mut self,
        item: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryWorkV2, CompletionStateError> {
        super::state_completion_delivery::begin(&self.0, item)
    }

    fn acknowledge_completion_delivery(
        &mut self,
        work: &CompletionDeliveryWorkV2,
        receipt: &CompletionDeliveryReceiptV2,
    ) -> Result<(), CompletionStateError> {
        super::state_completion_delivery::acknowledge(&self.0, work, receipt)
    }
}

fn recover(
    shared: &Arc<Mutex<StoreData>>,
    commit: &CompletionCommitReadbackV2,
) -> Result<Option<CompletionSigningWorkV2>, CompletionStateError> {
    let data = shared
        .lock()
        .map_err(|_| CompletionStateError::Unavailable)?;
    if data.completion_commits.first() != Some(commit) {
        return Err(CompletionStateError::Conflict);
    }
    Ok(data
        .completion_work
        .as_ref()
        .map(|stored| CompletionSigningWorkV2 {
            mode: CompletionSigningModeV2::Recover,
            ..stored.clone()
        }))
}

pub(super) fn next(
    shared: &Arc<Mutex<StoreData>>,
) -> Result<Option<CompletionCommitReadbackV2>, CompletionStateError> {
    Ok(shared
        .lock()
        .map_err(|_| CompletionStateError::Unavailable)?
        .completion_commits
        .first()
        .cloned())
}

pub(super) fn begin(
    shared: &Arc<Mutex<StoreData>>,
    commit: &CompletionCommitReadbackV2,
    draft: &ManagerCommitEvidenceDraftV2,
) -> Result<CompletionSigningWorkV2, CompletionStateError> {
    let mut data = shared
        .lock()
        .map_err(|_| CompletionStateError::Unavailable)?;
    if data.completion_commits.first() != Some(commit) {
        return Err(CompletionStateError::Conflict);
    }
    if data.completion_work.is_some() {
        return Err(CompletionStateError::Conflict);
    }
    let stored = CompletionSigningWorkV2 {
        claim_id: format!("claim.{}", commit.completion_id),
        commit: commit.clone(),
        draft: draft.clone(),
        mode: CompletionSigningModeV2::Recover,
    };
    data.completion_work = Some(stored.clone());
    Ok(CompletionSigningWorkV2 {
        mode: CompletionSigningModeV2::Sign,
        ..stored
    })
}

pub(super) fn stage(
    shared: &Arc<Mutex<StoreData>>,
    work: &CompletionSigningWorkV2,
    evidence: &CertificateManagerCommitEvidenceV2,
) -> Result<(), CompletionStateError> {
    let mut data = shared
        .lock()
        .map_err(|_| CompletionStateError::Unavailable)?;
    let valid = data.completion_commits.first() == Some(&work.commit)
        && data
            .completion_work
            .as_ref()
            .is_some_and(|stored| exact_work(stored, &work.commit, &work.draft));
    if !valid {
        return Err(CompletionStateError::Conflict);
    }
    if data.fail_completion_stage {
        return Err(CompletionStateError::Unavailable);
    }
    data.completion_deliveries.push(CompletionDeliveryItemV2 {
        delivery_id: format!("delivery.{}", work.commit.completion_id),
        authority_evidence: work.commit.authority_evidence.clone(),
        manager_evidence: evidence.clone(),
    });
    data.completion_commits.remove(0);
    data.completion_work = None;
    Ok(())
}

fn exact_work(
    stored: &CompletionSigningWorkV2,
    commit: &CompletionCommitReadbackV2,
    draft: &ManagerCommitEvidenceDraftV2,
) -> bool {
    &stored.commit == commit && &stored.draft == draft
}
