mod builders;
mod completion;
mod entrypoints;
mod execution;
mod failure;
mod handoff;
mod handoff_binding;
mod handoff_guard;
mod handoff_resume;
mod handoff_security;
mod handoff_security_binding;
mod invocation;
mod mapping;
mod operation_status;
mod preflight;
mod readiness;
mod reconcile;
mod reconcile_recovery;
mod reconcile_resolution;
mod reconcile_support;
mod refresh;
mod result;

use crate::{
    AuthorityReadinessV2, CertificateManagerConfig, VerifiedCertificateExecutionAuthorizationV2,
    VerifiedKeyCustodyAttestationV2, VerifiedKeyEnrollmentV2, VerifiedWorkloadV2,
};

pub struct CertificateManager<A, R, W, P, K, C, V, O, S, T> {
    config: CertificateManagerConfig,
    authority: A,
    readiness_verifier: R,
    workload_verifier: W,
    authorization_verifier: P,
    enrollment_verifier: K,
    custody_verifier: C,
    certificate_verifier: V,
    outcome_verifier: O,
    state_store: S,
    handoff: Box<dyn crate::CertificateManagerHandoffPort>,
    integrity_sink: Box<dyn crate::IntegrityAlertSinkPort>,
    clock: T,
}

pub(crate) struct PreparedV2 {
    workload: VerifiedWorkloadV2,
    authorization: VerifiedCertificateExecutionAuthorizationV2,
    enrollment: Option<VerifiedKeyEnrollmentV2>,
    custody: Option<VerifiedKeyCustodyAttestationV2>,
    initial_readiness: AuthorityReadinessV2,
    readiness: AuthorityReadinessV2,
    initial_time_epoch_s: u64,
}

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T> {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        config: CertificateManagerConfig,
        authority: A,
        readiness_verifier: R,
        workload_verifier: W,
        authorization_verifier: P,
        enrollment_verifier: K,
        custody_verifier: C,
        certificate_verifier: V,
        outcome_verifier: O,
        state_store: S,
        integrity_sink: Box<dyn crate::IntegrityAlertSinkPort>,
        clock: T,
    ) -> Self {
        Self {
            config,
            authority,
            readiness_verifier,
            workload_verifier,
            authorization_verifier,
            enrollment_verifier,
            custody_verifier,
            certificate_verifier,
            outcome_verifier,
            state_store,
            handoff: Box::new(crate::UnavailableCertificateManagerHandoff),
            integrity_sink,
            clock,
        }
    }

    #[must_use]
    pub fn with_handoff(mut self, handoff: Box<dyn crate::CertificateManagerHandoffPort>) -> Self {
        self.handoff = handoff;
        self
    }
}
