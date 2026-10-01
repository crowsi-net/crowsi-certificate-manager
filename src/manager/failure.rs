use crate::{
    AbandonReasonV2, AuthorityError, IntegrityViolationKindV2, IntegrityViolationV2, ManagerError,
    OperationAbandonV2, OperationCommitV2, OperationReservationV2, OperationStateStorePort,
    ReceiptDraftV2, UnknownReasonV2, validation::validate_abandon_commit,
};

use super::{CertificateManager, builders};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    S: OperationStateStorePort,
{
    pub(crate) fn abandon(
        &mut self,
        reservation: &OperationReservationV2,
        reason: AbandonReasonV2,
        _observed_at_epoch_s: u64,
    ) -> Result<(), ManagerError> {
        let abandon = OperationAbandonV2 {
            reservation_id: reservation.lifecycle.reservation_id.clone(),
            reason,
        };
        let committed = self
            .state_store
            .abandon_pre_handoff(reservation, &abandon)
            .map_err(|_| ManagerError::AuditUnavailable)?;
        validate_abandon_commit(reservation, &abandon, &committed)
    }

    pub(crate) fn persist_unknown(
        &mut self,
        reservation: &OperationReservationV2,
        command_digest: String,
        reason: UnknownReasonV2,
        now: u64,
    ) -> Result<(), ManagerError> {
        let unknown = builders::operation_unknown(reservation, command_digest, reason, now);
        match self.state_store.mark_result_unknown(reservation, &unknown) {
            Ok(()) => Ok(()),
            Err(crate::OperationStateError::Conflict) => {
                self.confirm_unknown_conflict(reservation, &unknown)
            }
            Err(_) => Err(ManagerError::AuditUnavailable),
        }
    }

    fn confirm_unknown_conflict(
        &mut self,
        reservation: &OperationReservationV2,
        unknown: &crate::OperationUnknownV2,
    ) -> Result<(), ManagerError> {
        let observed = self
            .state_store
            .confirm_unknown_transition(reservation, unknown)
            .map_err(|_| ManagerError::AuditUnavailable)?;
        let intent = &reservation.lifecycle.intent;
        let query = crate::AuditStatusQueryV2 {
            target_request_id: intent.request_id.clone(),
            resource_id: intent.resource_id.clone(),
            owner_service_id: intent.owner_service_id.clone(),
            owner_workload_id: intent.owner_workload_id.clone(),
            owner_subject: intent.owner_subject.clone(),
            owner_profile: intent.owner_profile.clone(),
            operation_expected_resource_version: intent.expected_resource_version,
            operation_lifecycle_revocation_epoch: intent.lifecycle_revocation_epoch,
        };
        let valid = crate::validation::validate_audit_status(&query, &observed).is_ok()
            && observed.reservation_id == reservation.lifecycle.reservation_id
            && matches!(
                observed.state,
                crate::AuditOperationState::ResultUnknown | crate::AuditOperationState::Finalized
            )
            && observed.authority_command_digest_sha256.as_deref()
                == Some(unknown.audit.authority_command_digest_sha256.as_str());
        if valid {
            return Ok(());
        }
        self.integrity_sink
            .emit(&IntegrityViolationV2 {
                kind: IntegrityViolationKindV2::UnknownTransitionMismatch,
                request_id: intent.request_id.clone(),
                reservation_id: reservation.lifecycle.reservation_id.clone(),
                authority_command_digest_sha256: unknown
                    .audit
                    .authority_command_digest_sha256
                    .clone(),
                expected_receipt_digest_sha256: unknown
                    .audit
                    .authority_command_digest_sha256
                    .clone(),
                observed_receipt_digest_sha256: observed
                    .authority_command_digest_sha256
                    .unwrap_or_else(|| "00".repeat(32)),
            })
            .map_err(|_| ManagerError::AuditUnavailable)?;
        Err(ManagerError::AuditUnavailable)
    }

    pub(crate) fn report_commit_mismatch(
        &mut self,
        reservation: &OperationReservationV2,
        receipt: &ReceiptDraftV2,
        commit: &OperationCommitV2,
        authority_command_digest: String,
    ) -> Result<(), ManagerError> {
        self.integrity_sink
            .emit(&IntegrityViolationV2 {
                kind: IntegrityViolationKindV2::CommitProjectionMismatch,
                request_id: reservation.lifecycle.intent.request_id.clone(),
                reservation_id: reservation.lifecycle.reservation_id.clone(),
                authority_command_digest_sha256: authority_command_digest,
                expected_receipt_digest_sha256: receipt.digest_sha256(),
                observed_receipt_digest_sha256: commit.audit.event_digest_sha256.clone(),
            })
            .map_err(|_| ManagerError::AuditUnavailable)
    }
}

pub const fn authority_reason(error: AuthorityError) -> UnknownReasonV2 {
    match error {
        AuthorityError::Unavailable => UnknownReasonV2::AuthorityUnavailable,
        AuthorityError::Rejected => UnknownReasonV2::AuthorityRejected,
        AuthorityError::ResultUnknown => UnknownReasonV2::AuthorityAmbiguous,
    }
}

pub const fn abandon_reason(error: ManagerError) -> AbandonReasonV2 {
    match error {
        ManagerError::TrustedTimeRejected => AbandonReasonV2::TrustedClockRejected,
        ManagerError::KeyCustodyRejected => AbandonReasonV2::CustodyExpired,
        ManagerError::AuthorityUnavailable => AbandonReasonV2::AuthorityLeaseExpired,
        ManagerError::WorkloadClaimsRejected => AbandonReasonV2::IdentityExpired,
        ManagerError::AuthorizationBindingRejected | ManagerError::AuthorizationUnavailable => {
            AbandonReasonV2::AuthorizationExpired
        }
        _ => AbandonReasonV2::TrustChanged,
    }
}
