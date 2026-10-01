use std::collections::VecDeque;

use crowsi_certificate_manager::*;

use super::*;

pub fn build_manager(
    command: &CertificateCommandV2,
    authority: Authority,
    store: StateStore,
    times: Vec<u64>,
    use_ca_key_for_receipt: bool,
) -> TestManager {
    let (integrity_sink, _) = integrity_sink();
    build_manager_with_sink(
        command,
        authority,
        store,
        times,
        use_ca_key_for_receipt,
        integrity_sink,
    )
}

pub fn build_manager_with_sink(
    command: &CertificateCommandV2,
    authority: Authority,
    store: StateStore,
    times: Vec<u64>,
    use_ca_key_for_receipt: bool,
    integrity_sink: IntegritySink,
) -> TestManager {
    build_manager_with_config(
        command,
        authority,
        store,
        times,
        use_ca_key_for_receipt,
        integrity_sink,
        config(),
    )
}

pub fn build_manager_with_config(
    command: &CertificateCommandV2,
    authority: Authority,
    store: StateStore,
    times: Vec<u64>,
    use_ca_key_for_receipt: bool,
    integrity_sink: IntegritySink,
    manager_config: CertificateManagerConfig,
) -> TestManager {
    let verified = authorization(
        command.digest_sha256(),
        CertificateAuthorizedActionV2::from(command.operation),
        &command.request_id,
        None,
        &command.resource_id,
        command.expected_resource_version,
        command.previous_lifecycle_revocation_epoch,
        command.lifecycle_revocation_epoch,
    );
    build_manager_with_authorization(
        command,
        authority,
        store,
        times,
        use_ca_key_for_receipt,
        integrity_sink,
        manager_config,
        verified,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_manager_with_authorization(
    command: &CertificateCommandV2,
    authority: Authority,
    store: StateStore,
    times: Vec<u64>,
    use_ca_key_for_receipt: bool,
    integrity_sink: IntegritySink,
    manager_config: CertificateManagerConfig,
    verified: VerifiedCertificateExecutionAuthorizationV2,
) -> TestManager {
    build_manager_with_readiness(
        command,
        authority,
        store,
        times,
        use_ca_key_for_receipt,
        integrity_sink,
        manager_config,
        verified,
        vec![readiness(10), readiness(11), readiness(12), readiness(13)],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_manager_with_readiness(
    command: &CertificateCommandV2,
    authority: Authority,
    store: StateStore,
    times: Vec<u64>,
    use_ca_key_for_receipt: bool,
    integrity_sink: IntegritySink,
    manager_config: CertificateManagerConfig,
    verified: VerifiedCertificateExecutionAuthorizationV2,
    readiness_values: Vec<AuthorityReadinessV2>,
) -> TestManager {
    let custody = custody(command.digest_sha256());
    let times = completion_times(times);
    CertificateManager::new(
        manager_config,
        authority,
        ReadinessVerifier(readiness_values.into()),
        WorkloadVerifier::stable(workload()),
        AuthorizationVerifier(VecDeque::from(vec![Ok(verified); 8])),
        EnrollmentVerifier(enrollment()),
        CustodyVerifier(VecDeque::from(vec![Ok(custody); 8])),
        CertificateVerifier,
        OutcomeVerifier {
            use_ca_key: use_ca_key_for_receipt,
        },
        store,
        Box::new(integrity_sink),
        SequenceClock(times.into_iter().map(Ok).collect()),
    )
    .with_handoff(Box::new(accepted_handoff()))
}

fn completion_times(mut values: Vec<u64>) -> Vec<u64> {
    if values.len() == 2 {
        while values.len() < 10 {
            let next = values.last().copied().unwrap_or(NOW).saturating_add(1);
            values.push(next);
        }
    }
    values
}
