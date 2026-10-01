use crate::{
    AuthorityReadinessVerifierPort, CertificateAuthorityPort, CertificateCommandV2,
    CertificateExecutionAuthorizationVerifierPort, HandoffResumeContextV2,
    KeyCustodyAttestationVerifierPort, KeyEnrollmentVerifierPort, ManagerError,
    SignedCertificateExecutionAuthorizationV2, SignedKeyCustodyAttestationV2, TrustedClock,
    WorkloadEvidenceV2, WorkloadIdentityVerifierPort,
    validation::{validate_handoff_recovery_authorization, validate_readiness},
};

use super::{CertificateManager, mapping, refresh::valid_readiness_refresh};

pub(crate) struct HandoffInvocationSnapshot {
    security: super::handoff_security::HandoffSecuritySnapshot,
    authorization: crate::VerifiedCertificateExecutionAuthorizationV2,
    readiness: crate::AuthorityReadinessV2,
    checked_at_epoch_s: u64,
}

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    A: CertificateAuthorityPort,
    R: AuthorityReadinessVerifierPort,
    W: WorkloadIdentityVerifierPort,
    P: CertificateExecutionAuthorizationVerifierPort,
    K: KeyEnrollmentVerifierPort,
    C: KeyCustodyAttestationVerifierPort,
    T: TrustedClock,
{
    /// Authenticates the caller and captures current verified claims before PA I/O.
    pub(crate) fn prepare_handoff_invocation(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        command: &CertificateCommandV2,
        signed: &SignedCertificateExecutionAuthorizationV2,
        signed_custody: Option<&SignedKeyCustodyAttestationV2>,
        context: &HandoffResumeContextV2,
    ) -> Result<HandoffInvocationSnapshot, ManagerError> {
        let now = self
            .clock
            .now_epoch_s()
            .map_err(|_| ManagerError::TrustedTimeRejected)?;
        if now < context.pending.staged_at_epoch_s
            || now >= context.pending.recovery_deadline_epoch_s
        {
            return Err(ManagerError::HandoffResultUnknown);
        }
        Self::validate_handoff_execution_window(context, now)?;
        let snapshot =
            self.revalidate_handoff_security(evidence, command, signed_custody, context, now)?;
        let current = self
            .authorization_verifier
            .verify(signed)
            .map_err(mapping::authorization)?;
        validate_handoff_recovery_authorization(
            &self.config,
            command,
            signed,
            &context.pending.authorization,
            &current,
            now,
        )?;
        let readiness = self.verify_readiness(now)?;
        if !valid_readiness_refresh(&context.pending.readiness, &readiness) {
            return Err(ManagerError::AuthorityUnavailable);
        }
        let final_now = self
            .clock
            .now_epoch_s()
            .map_err(|_| ManagerError::TrustedTimeRejected)?;
        if final_now < now
            || final_now >= context.pending.recovery_deadline_epoch_s
            || final_now < context.pending.staged_at_epoch_s
        {
            return Err(ManagerError::HandoffResultUnknown);
        }
        Self::validate_handoff_execution_window(context, final_now)?;
        self.validate_handoff_security_snapshot(command, &snapshot, final_now)?;
        validate_handoff_recovery_authorization(
            &self.config,
            command,
            signed,
            &context.pending.authorization,
            &current,
            final_now,
        )?;
        validate_readiness(&self.config, &readiness, final_now)?;
        Ok(HandoffInvocationSnapshot {
            security: snapshot,
            authorization: current,
            readiness,
            checked_at_epoch_s: final_now,
        })
    }

    /// Rechecks captured claims at a new trusted time after durable PA acceptance.
    pub(crate) fn complete_handoff_invocation(
        &mut self,
        command: &CertificateCommandV2,
        signed: &SignedCertificateExecutionAuthorizationV2,
        context: &HandoffResumeContextV2,
        snapshot: &HandoffInvocationSnapshot,
    ) -> Result<u64, ManagerError> {
        let now = self
            .clock
            .now_epoch_s()
            .map_err(|_| ManagerError::TrustedTimeRejected)?;
        if now < snapshot.checked_at_epoch_s
            || now >= context.pending.recovery_deadline_epoch_s
            || now < context.pending.staged_at_epoch_s
        {
            return Err(ManagerError::HandoffResultUnknown);
        }
        Self::validate_handoff_execution_window(context, now)?;
        self.validate_handoff_security_snapshot(command, &snapshot.security, now)?;
        validate_handoff_recovery_authorization(
            &self.config,
            command,
            signed,
            &context.pending.authorization,
            &snapshot.authorization,
            now,
        )?;
        validate_readiness(&self.config, &snapshot.readiness, now)?;
        Ok(now)
    }
}
