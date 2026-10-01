use crate::{
    AuthorityReadinessVerifierPort, CertificateAuthorityPort, CertificateCommandV2,
    CertificateExecutionAuthorizationVerifierPort, HandoffResumeContextV2,
    KeyCustodyAttestationVerifierPort, KeyEnrollmentVerifierPort, ManagerError,
    SignedKeyCustodyAttestationV2, TrustedClock, WorkloadEvidenceV2, WorkloadIdentityVerifierPort,
    validation::{
        validate_custody, validate_key_enrollment, validate_workload, validate_workload_evidence,
    },
};

use super::{
    CertificateManager,
    handoff_security_binding::{same_custody_binding, same_workload_binding},
    mapping,
};

pub(crate) struct HandoffSecuritySnapshot {
    workload: crate::VerifiedWorkloadV2,
    enrollment: Option<crate::VerifiedKeyEnrollmentV2>,
    custody: Option<crate::VerifiedKeyCustodyAttestationV2>,
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
    /// Re-authenticates the current IPC peer and key custody before a resumed CA call.
    pub(crate) fn revalidate_handoff_security(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        command: &CertificateCommandV2,
        signed_custody: Option<&SignedKeyCustodyAttestationV2>,
        context: &HandoffResumeContextV2,
        now: u64,
    ) -> Result<HandoffSecuritySnapshot, ManagerError> {
        let workload = self.verify_handoff_caller(evidence, context, now)?;
        let required = command.operation.requires_key_enrollment();
        if required != signed_custody.is_some() {
            return Err(ManagerError::InvalidCommand);
        }
        let enrollment = command
            .key_enrollment
            .as_ref()
            .map(|value| {
                self.enrollment_verifier
                    .verify(value)
                    .map_err(mapping::enrollment)
            })
            .transpose()?;
        if let Some(value) = &enrollment {
            validate_key_enrollment(&self.config, value)?;
        }
        if enrollment != context.pending.enrollment {
            return Err(ManagerError::KeyEnrollmentRejected);
        }
        let custody = self.verify_custody(
            signed_custody,
            enrollment.as_ref(),
            &workload,
            &command.digest_sha256(),
            now,
        )?;
        let same_custody = custody
            .as_ref()
            .zip(context.pending.custody.as_ref())
            .is_none_or(|(current, stored)| same_custody_binding(stored, current));
        if !same_custody || custody.is_some() != context.pending.custody.is_some() {
            return Err(ManagerError::KeyCustodyRejected);
        }
        Ok(HandoffSecuritySnapshot {
            workload,
            enrollment,
            custody,
        })
    }

    pub(crate) fn validate_handoff_security_snapshot(
        &self,
        command: &CertificateCommandV2,
        snapshot: &HandoffSecuritySnapshot,
        now: u64,
    ) -> Result<(), ManagerError> {
        validate_workload(&self.config, &snapshot.workload, now)?;
        if let Some(custody) = &snapshot.custody {
            validate_custody(
                &self.config,
                &snapshot.workload,
                snapshot
                    .enrollment
                    .as_ref()
                    .ok_or(ManagerError::KeyEnrollmentRejected)?,
                &command.digest_sha256(),
                custody,
                now,
            )?;
        }
        Ok(())
    }

    pub(crate) fn revalidate_handoff_caller(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        context: &HandoffResumeContextV2,
        now: u64,
    ) -> Result<(), ManagerError> {
        self.verify_handoff_caller(evidence, context, now).map(drop)
    }

    fn verify_handoff_caller(
        &mut self,
        evidence: &WorkloadEvidenceV2,
        context: &HandoffResumeContextV2,
        now: u64,
    ) -> Result<crate::VerifiedWorkloadV2, ManagerError> {
        validate_workload_evidence(&self.config, evidence)?;
        let workload = self
            .workload_verifier
            .verify(evidence)
            .map_err(mapping::workload)?;
        validate_workload(&self.config, &workload, now)?;
        same_workload_binding(
            &context.pending.workload,
            &context.pending.authorization,
            &workload,
        )
        .then_some(workload)
        .ok_or(ManagerError::WorkloadClaimsRejected)
    }
}
