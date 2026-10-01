use crate::support;

use std::sync::Arc;

use crowsi_certificate_manager::{
    CertificateCompletionWorker, CertificateOperation, CompletionWorkerOutcomeV2,
};
use support::*;

#[test]
fn handoff_and_completion_debug_output_omit_security_envelopes() {
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
    {
        let state = harness.state.lock().expect("state");
        let pending = state.handoff_pending.as_ref().expect("pending");
        let accepted = state.handoff_accepted.as_ref().expect("accepted");
        let output = format!("{:?} {accepted:?}", pending.readback);
        assert!(!output.contains(&pending.readback.reservation_id));
        assert!(!output.contains(&pending.readback.target_resource_id));
        assert!(!output.contains(&pending.authorization.jti));
        assert!(!output.contains(&pending.authorization.lease_digest_sha256));
        assert!(!output.contains(&accepted.evidence.receipt_id));
        assert!(!output.contains(&accepted.evidence.signed.signature_base64));
    }
    let authorization = format!("{:?}", signed_authorization());
    assert!(!authorization.contains("cGEtcGVwLWxlYXNlLXYy"));
    assert!(!authorization.contains(&"11".repeat(32)));
    assert!(!authorization.contains("c2lnbmF0dXJl"));
    let custody = format!("{:?}", signed_custody());
    assert!(!custody.contains("Y3VzdG9keS1hdHRlc3RhdGlvbg=="));
    assert!(!custody.contains("c2lnbmF0dXJl"));

    let (signer, _) = completion_signer(false);
    let (challenge, _) = completion_challenge();
    let mut worker = CertificateCompletionWorker::new(
        config(),
        StateStore(Arc::clone(&harness.state)),
        signer,
        CompletionVerifier(false),
        challenge,
        SequenceClock([Ok(NOW + 6), Ok(NOW + 7)].into()),
    );
    assert_eq!(worker.process_next(), Ok(CompletionWorkerOutcomeV2::Staged));
    let state = harness.state.lock().expect("state");
    let item = state.completion_deliveries.first().expect("delivery");
    let output = format!("{item:?}");
    assert!(!output.contains(&item.delivery_id));
    assert!(!output.contains(&item.authority_evidence.evidence_id));
    assert!(!output.contains(&item.authority_evidence.authorization_jti));
    assert!(!output.contains(&item.authority_evidence.lease_digest_sha256));
    assert!(!output.contains(&item.authority_evidence.signed.signature_base64));
    assert!(!output.contains(&item.manager_evidence.signed.signature_base64));
    assert!(!output.contains(&item.manager_evidence.nonce_base64));
}
