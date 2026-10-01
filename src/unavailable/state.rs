use crate::{
    AuditOperationStatusV2, HandoffResumeContextV2, HandoffResumeQueryV2, OperationAbandonV2,
    OperationBeginV2, OperationCommitV2, OperationFinalizeV2, OperationHandoffPendingV2,
    OperationInvocationV2, OperationReservationV2, OperationStateError, OperationStateStorePort,
    OperationStatusBeginV2, OperationUnknownV2, ReconciliationBeginV2, ReconciliationContextV2,
    ReconciliationStateResolutionV2, VerifiedManagerHandoffV2,
};

pub struct UnavailableOperationStateStore;
impl OperationStateStorePort for UnavailableOperationStateStore {
    fn begin_operation(
        &mut self,
        _: &OperationBeginV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn find_handoff_resume(
        &mut self,
        _: &HandoffResumeQueryV2,
    ) -> Result<Option<HandoffResumeContextV2>, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn stage_handoff(
        &mut self,
        _: &OperationReservationV2,
        _: &OperationHandoffPendingV2,
    ) -> Result<HandoffResumeContextV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn mark_handoff_accepted(
        &mut self,
        _: &HandoffResumeContextV2,
        _: &VerifiedManagerHandoffV2,
    ) -> Result<HandoffResumeContextV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn mark_invoked(
        &mut self,
        _: &OperationReservationV2,
        _: &OperationInvocationV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn abandon_pre_handoff(
        &mut self,
        _: &OperationReservationV2,
        _: &OperationAbandonV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn commit_handoff_not_accepted(
        &mut self,
        _: &HandoffResumeContextV2,
        _: &VerifiedManagerHandoffV2,
    ) -> Result<OperationReservationV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn finalize_operation(
        &mut self,
        _: &OperationReservationV2,
        _: &OperationFinalizeV2,
    ) -> Result<OperationCommitV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn mark_result_unknown(
        &mut self,
        _: &OperationReservationV2,
        _: &OperationUnknownV2,
    ) -> Result<(), OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn confirm_unknown_transition(
        &mut self,
        _: &OperationReservationV2,
        _: &OperationUnknownV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn operation_status(
        &mut self,
        _: &OperationStatusBeginV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn begin_reconciliation(
        &mut self,
        _: &ReconciliationBeginV2,
    ) -> Result<ReconciliationContextV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }

    fn resolve_reconciliation(
        &mut self,
        _: &ReconciliationContextV2,
        _: &ReconciliationStateResolutionV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError> {
        Err(OperationStateError::Unavailable)
    }
}
