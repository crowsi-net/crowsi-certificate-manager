use crate::{
    CertificateCommandV2, HandoffResumeContextV2, HandoffResumeQueryV2, ManagerError,
    validation::{
        validate_custody, validate_handoff_resume, validate_key_enrollment,
        validate_operation_reservation, validate_readiness, validate_workload,
    },
};

use super::{CertificateManager, PreparedV2, builders, refresh::valid_readiness_refresh};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T> {
    /// Re-derives the complete CA command from independently stored inputs.
    pub(crate) fn validate_handoff_context(
        &self,
        command: &CertificateCommandV2,
        query: &HandoffResumeQueryV2,
        context: &HandoffResumeContextV2,
    ) -> Result<(), ManagerError> {
        validate_handoff_resume(&self.config, query, context)?;
        let pending = &context.pending;
        let staged = pending.staged_at_epoch_s;
        validate_workload(&self.config, &pending.workload, staged)
            .map_err(|_| ManagerError::HandoffResultUnknown)?;
        validate_readiness(&self.config, &pending.readiness, staged)
            .map_err(|_| ManagerError::HandoffResultUnknown)?;
        validate_readiness(&self.config, &pending.initial_readiness, staged)
            .map_err(|_| ManagerError::HandoffResultUnknown)?;
        if !valid_readiness_refresh(&pending.initial_readiness, &pending.readiness) {
            return Err(ManagerError::HandoffResultUnknown);
        }
        self.validate_stored_key_material(command, context, staged)?;
        let prepared = PreparedV2 {
            workload: pending.workload.clone(),
            authorization: pending.authorization.clone(),
            enrollment: pending.enrollment.clone(),
            custody: pending.custody.clone(),
            initial_readiness: pending.initial_readiness.clone(),
            readiness: pending.readiness.clone(),
            initial_time_epoch_s: staged,
        };
        let begin = builders::operation_begin(command, &prepared, staged);
        validate_operation_reservation(&begin, &context.reservation)
            .map_err(|_| ManagerError::HandoffResultUnknown)?;
        if pending.readback != builders::handoff_readback(&begin, &context.reservation) {
            return Err(ManagerError::HandoffResultUnknown);
        }
        let expected =
            builders::authority_command(command, &prepared, &context.reservation, staged)
                .map_err(|_| ManagerError::HandoffResultUnknown)?;
        (expected == pending.authority_command)
            .then_some(())
            .ok_or(ManagerError::HandoffResultUnknown)
    }

    pub(crate) fn validate_handoff_execution_window(
        context: &HandoffResumeContextV2,
        now: u64,
    ) -> Result<(), ManagerError> {
        let authority = &context.pending.authority_command;
        if now >= authority.authority_lease_expires_at_epoch_s {
            return Err(ManagerError::AuthorityUnavailable);
        }
        if authority
            .custody_expires_at_epoch_s
            .is_some_and(|expires| now >= expires)
        {
            return Err(ManagerError::KeyCustodyRejected);
        }
        Ok(())
    }

    fn validate_stored_key_material(
        &self,
        command: &CertificateCommandV2,
        context: &HandoffResumeContextV2,
        staged: u64,
    ) -> Result<(), ManagerError> {
        let pending = &context.pending;
        let required = command.operation.requires_key_enrollment();
        if required != pending.enrollment.is_some() || required != pending.custody.is_some() {
            return Err(ManagerError::HandoffResultUnknown);
        }
        let Some((enrollment, custody)) = pending.enrollment.as_ref().zip(pending.custody.as_ref())
        else {
            return Ok(());
        };
        validate_key_enrollment(&self.config, enrollment)
            .map_err(|_| ManagerError::HandoffResultUnknown)?;
        validate_custody(
            &self.config,
            &pending.workload,
            enrollment,
            &command.digest_sha256(),
            custody,
            staged,
        )
        .map_err(|_| ManagerError::HandoffResultUnknown)
    }
}
