use crate::support;

use crowsi_certificate_manager::{
    CertificateCompletionDeliveryWorker, CertificateCompletionWorker, CertificateOperation,
    CompletionDeliveryWorkerOutcomeV2, CompletionWorkerOutcomeV2,
};
use support::*;

#[test]
fn pa_ack_loss_recovers_exact_receipt_before_outbox_removal() {
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
    let store = StateStore(std::sync::Arc::clone(&harness.state));
    let (signer, _) = completion_signer(false);
    let (challenge, _) = completion_challenge();
    let mut signing = CertificateCompletionWorker::new(
        config(),
        store,
        signer,
        CompletionVerifier(false),
        challenge,
        SequenceClock([Ok(NOW + 6)].into()),
    );
    assert_eq!(
        signing.process_next(),
        Ok(CompletionWorkerOutcomeV2::Staged)
    );
    let (delivery, delivery_state) = completion_delivery(true);
    let mut worker = CertificateCompletionDeliveryWorker::new(
        StateStore(std::sync::Arc::clone(&harness.state)),
        delivery,
    );

    assert_eq!(
        worker.process_next(),
        Ok(CompletionDeliveryWorkerOutcomeV2::DeliveryResultUnknown)
    );
    assert_eq!(
        worker.process_next(),
        Ok(CompletionDeliveryWorkerOutcomeV2::Acknowledged)
    );

    let transport = delivery_state.lock().expect("delivery");
    assert_eq!((transport.submit_calls, transport.recover_calls), (1, 1));
    let state = harness.state.lock().expect("state");
    assert!(state.completion_deliveries.is_empty());
    assert_eq!(state.completion_receipts.len(), 1);
    assert_eq!(
        harness.authority.lock().expect("authority").executed.len(),
        1
    );
}
