use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;
use crowsi_control_contracts::CertificatePayloadV2;

#[derive(Default)]
pub struct CompletionDeliveryState {
    pub submit_calls: usize,
    pub recover_calls: usize,
    pub result_unknown_once: bool,
    pub receipt: Option<CompletionDeliveryReceiptV2>,
}

pub struct CompletionDelivery(pub Arc<Mutex<CompletionDeliveryState>>);

impl CertificateCompletionDeliveryPort for CompletionDelivery {
    fn submit(
        &mut self,
        item: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryReceiptV2, CompletionDeliveryError> {
        let mut state = self.0.lock().expect("delivery");
        state.submit_calls += 1;
        let receipt = receipt(item);
        state.receipt = Some(receipt.clone());
        if state.result_unknown_once {
            state.result_unknown_once = false;
            return Err(CompletionDeliveryError::ResultUnknown);
        }
        Ok(receipt)
    }

    fn recover(
        &mut self,
        item: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryReceiptV2, CompletionDeliveryError> {
        let mut state = self.0.lock().expect("delivery");
        state.recover_calls += 1;
        state
            .receipt
            .clone()
            .filter(|receipt| receipt.commit_id == item.manager_evidence.commit_id)
            .ok_or(CompletionDeliveryError::ResultUnknown)
    }
}

pub fn completion_delivery(
    result_unknown_once: bool,
) -> (CompletionDelivery, Arc<Mutex<CompletionDeliveryState>>) {
    let state = Arc::new(Mutex::new(CompletionDeliveryState {
        result_unknown_once,
        ..CompletionDeliveryState::default()
    }));
    (CompletionDelivery(Arc::clone(&state)), state)
}

fn receipt(item: &CompletionDeliveryItemV2) -> CompletionDeliveryReceiptV2 {
    let manager = &item.manager_evidence;
    let received = manager.evidence_issued_at_epoch_s + 1;
    CompletionDeliveryReceiptV2 {
        authorization_jti: item.authority_evidence.authorization_jti.clone(),
        commit_id: manager.commit_id.clone(),
        authority_evidence_digest_sha256: item.authority_evidence.certificate_digest_sha256(),
        manager_commit_digest_sha256: manager.certificate_digest_sha256(),
        disposition: item.authority_evidence.disposition.as_str().into(),
        received_at_epoch_s: received,
        completed_at_epoch_s: received + 1,
    }
}
