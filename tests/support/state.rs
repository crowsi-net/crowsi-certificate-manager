use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::{
    StoreData, state_begin, state_finalize, state_handoff, state_query, state_reconciliation,
    state_transition,
};

pub struct StateStore(pub Arc<Mutex<StoreData>>);

impl OperationStateStorePort for StateStore {
    fn begin_operation(
        &mut self,
        begin: &OperationBeginV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        state_begin::begin(&self.0, begin)
    }

    fn find_handoff_resume(
        &mut self,
        query: &HandoffResumeQueryV2,
    ) -> Result<Option<HandoffResumeContextV2>, OperationStateError> {
        state_handoff::find(&self.0, query)
    }

    fn stage_handoff(
        &mut self,
        reservation: &OperationReservationV2,
        pending: &OperationHandoffPendingV2,
    ) -> Result<HandoffResumeContextV2, OperationStateError> {
        state_handoff::stage(&self.0, reservation, pending)
    }

    fn mark_handoff_accepted(
        &mut self,
        context: &HandoffResumeContextV2,
        accepted: &VerifiedManagerHandoffV2,
    ) -> Result<HandoffResumeContextV2, OperationStateError> {
        let mut committed = state_handoff::accept(&self.0, context, accepted)?;
        if self
            .0
            .lock()
            .expect("state")
            .corrupt_handoff_accept_projection
        {
            committed
                .accepted
                .as_mut()
                .expect("accepted")
                .acknowledgement
                .recorded_at_epoch_s += 1;
        }
        Ok(committed)
    }

    fn mark_invoked(
        &mut self,
        reservation: &OperationReservationV2,
        invocation: &OperationInvocationV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        let mut committed = state_transition::mark_invoked(&self.0, reservation, invocation)?;
        if self.0.lock().expect("state").corrupt_invocation_projection {
            committed.state_revision = committed.state_revision.saturating_add(1);
        }
        if self.0.lock().expect("state").corrupt_invocation_phase {
            committed.phase = AuditOperationState::Reserved;
        }
        if self.0.lock().expect("state").corrupt_invocation_digest {
            committed.invoked_authority_command_digest_sha256 = Some("ff".repeat(32));
        }
        if self.0.lock().expect("state").lose_invocation_ack {
            return Err(OperationStateError::Unavailable);
        }
        Ok(committed)
    }

    fn abandon_pre_handoff(
        &mut self,
        reservation: &OperationReservationV2,
        abandon: &OperationAbandonV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        state_transition::abandon_pre_handoff(&self.0, reservation, abandon)
    }

    fn commit_handoff_not_accepted(
        &mut self,
        context: &HandoffResumeContextV2,
        rejected: &VerifiedManagerHandoffV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        state_handoff::reject(&self.0, context, rejected)
    }

    fn finalize_operation(
        &mut self,
        reservation: &OperationReservationV2,
        finalize: &OperationFinalizeV2,
    ) -> Result<OperationCommitV2, OperationStateError> {
        state_finalize::finalize(&self.0, reservation, finalize)
    }

    fn mark_result_unknown(
        &mut self,
        reservation: &OperationReservationV2,
        unknown: &OperationUnknownV2,
    ) -> Result<(), OperationStateError> {
        state_transition::mark_unknown(&self.0, reservation, unknown)
    }

    fn confirm_unknown_transition(
        &mut self,
        reservation: &OperationReservationV2,
        unknown: &OperationUnknownV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError> {
        state_transition::confirm_unknown(&self.0, reservation, unknown)
    }

    fn operation_status(
        &mut self,
        begin: &OperationStatusBeginV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError> {
        state_query::operation_status(&self.0, begin)
    }

    fn begin_reconciliation(
        &mut self,
        begin: &ReconciliationBeginV2,
    ) -> Result<ReconciliationContextV2, OperationStateError> {
        state_reconciliation::begin(&self.0, begin)
    }

    fn resolve_reconciliation(
        &mut self,
        context: &ReconciliationContextV2,
        resolution: &ReconciliationStateResolutionV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError> {
        state_reconciliation::resolve_projected(&self.0, context, resolution)
    }
}

pub fn state_store() -> (StateStore, Arc<Mutex<StoreData>>) {
    let data = Arc::new(Mutex::new(StoreData::default()));
    (StateStore(Arc::clone(&data)), data)
}
