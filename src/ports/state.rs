use crate::{
    AuditOperationStatusV2, HandoffResumeContextV2, HandoffResumeQueryV2, OperationAbandonV2,
    OperationBeginV2, OperationCommitV2, OperationFinalizeV2, OperationHandoffPendingV2,
    OperationInvocationV2, OperationReservationV2, OperationStateError, OperationStatusBeginV2,
    OperationUnknownV2, ReconciliationBeginV2, ReconciliationContextV2,
    ReconciliationStateResolutionV2, VerifiedManagerHandoffV2,
};

pub trait OperationStateStorePort {
    /// Atomically writes replay keys, lifecycle CAS reservation, and audit intent.
    ///
    /// Implementations must use one durable transaction and an outbox. A partial
    /// replay reservation, lifecycle lock, or audit record is contract-invalid.
    ///
    /// # Errors
    ///
    /// Rejects replay, ownership, stale version/fence, or unavailable durability.
    fn begin_operation(
        &mut self,
        begin: &OperationBeginV2,
    ) -> Result<OperationReservationV2, OperationStateError>;

    /// Looks up only an exact durable handoff substate before fresh preflight.
    ///
    /// # Errors
    ///
    /// Rejects changed command/lease bindings or corrupted handoff state.
    fn find_handoff_resume(
        &mut self,
        query: &HandoffResumeQueryV2,
    ) -> Result<Option<HandoffResumeContextV2>, OperationStateError>;

    /// Atomically stages the exact CA command before contacting the PA.
    ///
    /// # Errors
    ///
    /// Rejects a stale reservation, a changed pending document, or replay.
    fn stage_handoff(
        &mut self,
        reservation: &OperationReservationV2,
        pending: &OperationHandoffPendingV2,
    ) -> Result<HandoffResumeContextV2, OperationStateError>;

    /// Durably records the exact accepted PA acknowledgement before invocation.
    ///
    /// # Errors
    ///
    /// Rejects `NotAccepted`, changed evidence, stale pending state, or replay.
    fn mark_handoff_accepted(
        &mut self,
        context: &HandoffResumeContextV2,
        accepted: &VerifiedManagerHandoffV2,
    ) -> Result<HandoffResumeContextV2, OperationStateError>;

    /// Durably moves a reserved operation to invoked before the CA boundary and
    /// returns the exact committed revision/digest readback.
    ///
    /// # Errors
    ///
    /// Rejects a stale reservation or duplicate/inconsistent invocation.
    fn mark_invoked(
        &mut self,
        reservation: &OperationReservationV2,
        invocation: &OperationInvocationV2,
    ) -> Result<OperationReservationV2, OperationStateError>;

    /// Releases a reservation only before any handoff was durably staged.
    /// The store, not the caller, assigns the trusted abandonment timestamp.
    ///
    /// # Errors
    ///
    /// Rejects any handoff-pending, accepted, invoked, or stale revision.
    fn abandon_pre_handoff(
        &mut self,
        reservation: &OperationReservationV2,
        abandon: &OperationAbandonV2,
    ) -> Result<OperationReservationV2, OperationStateError>;

    /// Commits abandonment from an exact signed `NotAccepted` PA result.
    ///
    /// This is the only abandonment transition after handoff staging. Accepted
    /// evidence, a changed pending document, or a stale revision must fail.
    ///
    /// # Errors
    ///
    /// Rejects non-`NotAccepted`, altered evidence/ACK, accepted state, invocation,
    /// or a context that is not the current durable handoff-pending revision.
    fn commit_handoff_not_accepted(
        &mut self,
        context: &HandoffResumeContextV2,
        not_accepted: &VerifiedManagerHandoffV2,
    ) -> Result<OperationReservationV2, OperationStateError>;

    /// Atomically commits lifecycle state, audit receipt, and exact completion
    /// readback. The readback is the only input accepted by the commit signer;
    /// omitting it or reconstructing it after commit is contract-invalid.
    ///
    /// # Errors
    ///
    /// Rejects a stale revision or inconsistent outcome, owner, version, fence,
    /// receipt, or signed authority-evidence bindings.
    fn finalize_operation(
        &mut self,
        reservation: &OperationReservationV2,
        finalize: &OperationFinalizeV2,
    ) -> Result<OperationCommitV2, OperationStateError>;

    /// Atomically blocks lifecycle reuse and records an ambiguous invoked result.
    ///
    /// # Errors
    ///
    /// Fails unless both state changes are durably committed together from the
    /// exact supplied reservation revision.
    fn mark_result_unknown(
        &mut self,
        reservation: &OperationReservationV2,
        unknown: &OperationUnknownV2,
    ) -> Result<(), OperationStateError>;

    /// Reads back a conflicting unknown transition without consuming a new
    /// service authorization.
    ///
    /// # Errors
    ///
    /// Returns only an exact, durable projection for the supplied reservation
    /// and authority command; echoing caller fields is contract-invalid.
    fn confirm_unknown_transition(
        &mut self,
        reservation: &OperationReservationV2,
        unknown: &OperationUnknownV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError>;

    /// Atomically consumes query ID, nonce, authorization ID/JTI/lease and reads
    /// an owner/version-scoped stored projection without echoing query fields.
    ///
    /// # Errors
    ///
    /// Status authorization can never be upgraded to authority reconciliation.
    fn operation_status(
        &mut self,
        begin: &OperationStatusBeginV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError>;

    /// Atomically consumes query ID, nonce, authorization ID/JTI/lease and reads
    /// only the owner/version/digest-scoped reconciliation projection.
    ///
    /// # Errors
    ///
    /// Rejects partial replay reservations, cross-action reuse, cross-owner reads,
    /// and unavailable durable state.
    fn begin_reconciliation(
        &mut self,
        begin: &ReconciliationBeginV2,
    ) -> Result<ReconciliationContextV2, OperationStateError>;

    /// Atomically appends a verified disposition and its exact completion
    /// readback, releasing only a proven not-executed lifecycle lock;
    /// still-unknown remains blocked.
    ///
    /// # Errors
    ///
    /// Rejects a stale context or an unbound reconciliation proof.
    fn resolve_reconciliation(
        &mut self,
        context: &ReconciliationContextV2,
        resolution: &ReconciliationStateResolutionV2,
    ) -> Result<AuditOperationStatusV2, OperationStateError>;
}
