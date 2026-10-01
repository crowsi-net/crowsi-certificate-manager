use crowsi_control_contracts::CertificateManagerCommitEvidenceV2;

use crate::{
    CertificateCompletionDeliveryPort, CertificateCompletionEvidenceSignerPort,
    CertificateCompletionEvidenceVerifierPort, CompletionChallengeError,
    CompletionChallengeSourcePort, CompletionChallengeV2, CompletionCommitReadbackV2,
    CompletionDeliveryError, CompletionDeliveryItemV2, CompletionDeliveryReceiptV2,
    CompletionDeliveryWorkV2, CompletionEvidenceError, CompletionOutboxStorePort,
    CompletionSigningWorkV2, CompletionStateError, ManagerCommitEvidenceDraftV2,
};

pub struct UnavailableCertificateCompletionDelivery;
impl CertificateCompletionDeliveryPort for UnavailableCertificateCompletionDelivery {
    fn submit(
        &mut self,
        _: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryReceiptV2, CompletionDeliveryError> {
        Err(CompletionDeliveryError::Unavailable)
    }

    fn recover(
        &mut self,
        _: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryReceiptV2, CompletionDeliveryError> {
        Err(CompletionDeliveryError::Unavailable)
    }
}

pub struct UnavailableCompletionChallengeSource;
impl CompletionChallengeSourcePort for UnavailableCompletionChallengeSource {
    fn issue(
        &mut self,
        _: &CompletionCommitReadbackV2,
    ) -> Result<CompletionChallengeV2, CompletionChallengeError> {
        Err(CompletionChallengeError::Unavailable)
    }
}

pub struct UnavailableCertificateCompletionEvidenceSigner;
impl CertificateCompletionEvidenceSignerPort for UnavailableCertificateCompletionEvidenceSigner {
    fn sign(
        &mut self,
        _: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CertificateManagerCommitEvidenceV2, CompletionEvidenceError> {
        Err(CompletionEvidenceError::Unavailable)
    }

    fn recover(
        &mut self,
        _: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CertificateManagerCommitEvidenceV2, CompletionEvidenceError> {
        Err(CompletionEvidenceError::Unavailable)
    }
}

pub struct UnavailableCertificateCompletionEvidenceVerifier;
impl CertificateCompletionEvidenceVerifierPort
    for UnavailableCertificateCompletionEvidenceVerifier
{
    fn verify(
        &mut self,
        _: &CertificateManagerCommitEvidenceV2,
    ) -> Result<(), CompletionEvidenceError> {
        Err(CompletionEvidenceError::Unavailable)
    }
}

pub struct UnavailableCompletionOutboxStore;
impl CompletionOutboxStorePort for UnavailableCompletionOutboxStore {
    fn next_completion_commit(
        &mut self,
    ) -> Result<Option<CompletionCommitReadbackV2>, CompletionStateError> {
        Err(CompletionStateError::Unavailable)
    }

    fn recover_completion_signing(
        &mut self,
        _: &CompletionCommitReadbackV2,
    ) -> Result<Option<CompletionSigningWorkV2>, CompletionStateError> {
        Err(CompletionStateError::Unavailable)
    }

    fn begin_completion_signing(
        &mut self,
        _: &CompletionCommitReadbackV2,
        _: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CompletionSigningWorkV2, CompletionStateError> {
        Err(CompletionStateError::Unavailable)
    }

    fn stage_completion_delivery(
        &mut self,
        _: &CompletionSigningWorkV2,
        _: &CertificateManagerCommitEvidenceV2,
    ) -> Result<(), CompletionStateError> {
        Err(CompletionStateError::Unavailable)
    }

    fn next_completion_delivery(
        &mut self,
    ) -> Result<Option<CompletionDeliveryItemV2>, CompletionStateError> {
        Err(CompletionStateError::Unavailable)
    }

    fn begin_completion_delivery(
        &mut self,
        _: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryWorkV2, CompletionStateError> {
        Err(CompletionStateError::Unavailable)
    }

    fn acknowledge_completion_delivery(
        &mut self,
        _: &CompletionDeliveryWorkV2,
        _: &CompletionDeliveryReceiptV2,
    ) -> Result<(), CompletionStateError> {
        Err(CompletionStateError::Unavailable)
    }
}
