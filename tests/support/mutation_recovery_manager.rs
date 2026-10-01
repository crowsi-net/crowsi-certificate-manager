use std::collections::VecDeque;

use crowsi_certificate_manager::*;

use super::*;

#[allow(clippy::too_many_arguments)]
pub fn build_recovery_security_manager(
    _command: &CertificateCommandV2,
    authority: Authority,
    store: StateStore,
    times: Vec<u64>,
    verified: VerifiedCertificateExecutionAuthorizationV2,
    workloads: Vec<VerifiedWorkloadV2>,
    custodies: Vec<VerifiedKeyCustodyAttestationV2>,
) -> TestManager {
    let fallback = workloads.last().cloned().unwrap_or_else(workload);
    let (integrity, _) = integrity_sink();
    CertificateManager::new(
        config(),
        authority,
        ReadinessVerifier([readiness(10), readiness(11), readiness(12), readiness(13)].into()),
        WorkloadVerifier::sequence(fallback, workloads),
        AuthorizationVerifier(VecDeque::from([
            Ok(verified.clone()),
            Ok(verified.clone()),
            Ok(verified.clone()),
            Ok(verified),
        ])),
        EnrollmentVerifier(enrollment()),
        CustodyVerifier(custodies.into_iter().map(Ok).collect()),
        CertificateVerifier,
        OutcomeVerifier { use_ca_key: false },
        store,
        Box::new(integrity),
        SequenceClock(times.into_iter().map(Ok).collect()),
    )
    .with_handoff(Box::new(accepted_handoff()))
}
