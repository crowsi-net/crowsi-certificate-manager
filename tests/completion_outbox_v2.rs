use crate::support;

use crowsi_certificate_manager::{
    CertificateCompletionWorker, CertificateOperation, CompletionWorkerError,
    CompletionWorkerOutcomeV2,
};
use crowsi_control_contracts::CertificatePayloadV2;
use support::*;

#[test]
fn committed_state_stages_both_exact_proofs_without_reinvoking_authority() {
    let (mut worker, state, signer, authority) = completed_worker(false);

    assert_eq!(worker.process_next(), Ok(CompletionWorkerOutcomeV2::Staged));

    let data = state.lock().expect("state");
    assert!(data.completion_commits.is_empty());
    assert_eq!(data.completion_deliveries.len(), 1);
    let item = &data.completion_deliveries[0];
    assert_eq!(
        item.manager_evidence.authority_evidence_digest_sha256,
        item.authority_evidence.certificate_digest_sha256()
    );
    assert_eq!(authority.lock().expect("authority").executed.len(), 1);
    assert_eq!(signer.lock().expect("signer").sign_calls, 1);
}

#[test]
fn ambiguous_signing_recovers_exact_result_without_reinvoking_authority() {
    let (mut worker, state, signer, authority) = completed_worker(true);

    assert_eq!(
        worker.process_next(),
        Ok(CompletionWorkerOutcomeV2::SigningResultUnknown)
    );
    assert_eq!(worker.process_next(), Ok(CompletionWorkerOutcomeV2::Staged));

    let signing = signer.lock().expect("signer");
    assert_eq!((signing.sign_calls, signing.recover_calls), (1, 1));
    assert_eq!(authority.lock().expect("authority").executed.len(), 1);
    assert_eq!(state.lock().expect("state").completion_deliveries.len(), 1);
}

#[test]
fn failed_atomic_stage_keeps_recoverable_signing_work() {
    let (mut worker, state, signer, authority) = completed_worker(false);
    state.lock().expect("state").fail_completion_stage = true;

    assert_eq!(
        worker.process_next(),
        Err(CompletionWorkerError::StateUnavailable)
    );
    state.lock().expect("state").fail_completion_stage = false;
    assert_eq!(worker.process_next(), Ok(CompletionWorkerOutcomeV2::Staged));

    let signing = signer.lock().expect("signer");
    assert_eq!((signing.sign_calls, signing.recover_calls), (1, 1));
    assert_eq!(authority.lock().expect("authority").executed.len(), 1);
}

#[test]
fn delayed_first_signing_uses_fresh_evidence_inside_recovery_window() {
    let (mut worker, state, _, authority) = completed_worker_at(false, NOW + 3_600);

    assert_eq!(worker.process_next(), Ok(CompletionWorkerOutcomeV2::Staged));

    let data = state.lock().expect("state");
    let evidence = &data.completion_deliveries[0].manager_evidence;
    assert_eq!(evidence.evidence_issued_at_epoch_s, NOW + 3_600);
    assert_eq!(evidence.expires_at_epoch_s, NOW + 3_660);
    assert_eq!(authority.lock().expect("authority").executed.len(), 1);
}

fn completed_worker(unknown_once: bool) -> WorkerFixture {
    completed_worker_at(unknown_once, NOW + 6)
}

type WorkerFixture = (
    CertificateCompletionWorker<
        StateStore,
        CompletionSigner,
        CompletionVerifier,
        CompletionChallenge,
        SequenceClock,
    >,
    std::sync::Arc<std::sync::Mutex<StoreData>>,
    std::sync::Arc<std::sync::Mutex<CompletionSignerState>>,
    std::sync::Arc<std::sync::Mutex<AuthorityState>>,
);

fn completed_worker_at(unknown_once: bool, worker_time: u64) -> WorkerFixture {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness
        .manager
        .execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        )
        .expect("commit");
    let (signer, signer_state) = completion_signer(unknown_once);
    let (challenge, _) = completion_challenge();
    let clock = SequenceClock([Ok(worker_time), Ok(worker_time + 1)].into());
    let worker = CertificateCompletionWorker::new(
        config(),
        StateStore(std::sync::Arc::clone(&harness.state)),
        signer,
        CompletionVerifier(false),
        challenge,
        clock,
    );
    (worker, harness.state, signer_state, harness.authority)
}
