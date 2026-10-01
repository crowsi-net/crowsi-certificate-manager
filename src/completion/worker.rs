use crate::{
    CertificateCompletionEvidenceSignerPort, CertificateCompletionEvidenceVerifierPort,
    CertificateManagerConfig, CompletionChallengeSourcePort, CompletionEvidenceError,
    CompletionOutboxStorePort, CompletionSigningModeV2, CompletionWorkerError,
    CompletionWorkerOutcomeV2, TrustedClock,
    validation::{
        validate_completion_draft, validate_completion_readback, validate_completion_work,
        validate_config, validate_manager_commit_evidence,
    },
};

pub struct CertificateCompletionWorker<S, G, V, N, T> {
    config: CertificateManagerConfig,
    store: S,
    signer: G,
    verifier: V,
    challenge: N,
    clock: T,
}

impl<S, G, V, N, T> CertificateCompletionWorker<S, G, V, N, T>
where
    S: CompletionOutboxStorePort,
    G: CertificateCompletionEvidenceSignerPort,
    V: CertificateCompletionEvidenceVerifierPort,
    N: CompletionChallengeSourcePort,
    T: TrustedClock,
{
    #[must_use]
    pub const fn new(
        config: CertificateManagerConfig,
        store: S,
        signer: G,
        verifier: V,
        challenge: N,
        clock: T,
    ) -> Self {
        Self {
            config,
            store,
            signer,
            verifier,
            challenge,
            clock,
        }
    }

    /// Signs one durable commit and atomically stages the PA delivery outbox.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid readback, trust, time, signature, or outbox state.
    pub fn process_next(&mut self) -> Result<CompletionWorkerOutcomeV2, CompletionWorkerError> {
        validate_config(&self.config).map_err(|_| CompletionWorkerError::InvalidConfiguration)?;
        let Some(commit) = self
            .store
            .next_completion_commit()
            .map_err(|_| CompletionWorkerError::StateUnavailable)?
        else {
            return Ok(CompletionWorkerOutcomeV2::Idle);
        };
        let now = self
            .clock
            .now_epoch_s()
            .map_err(|_| CompletionWorkerError::TrustedTimeRejected)?;
        validate_completion_readback(&self.config, &commit, now)?;
        let existing = self
            .store
            .recover_completion_signing(&commit)
            .map_err(|_| CompletionWorkerError::StateUnavailable)?;
        let work = match existing {
            Some(work) => work,
            None => self.begin_signing(&commit, now)?,
        };
        validate_completion_work(&commit, &work)?;
        let evidence = match work.mode {
            CompletionSigningModeV2::Sign => self.signer.sign(&work.draft),
            CompletionSigningModeV2::Recover => self.signer.recover(&work.draft),
        };
        let evidence = match evidence {
            Ok(value) => value,
            Err(CompletionEvidenceError::ResultUnknown) => {
                return Ok(CompletionWorkerOutcomeV2::SigningResultUnknown);
            }
            Err(CompletionEvidenceError::Unavailable) => {
                return Err(CompletionWorkerError::EvidenceUnavailable);
            }
            Err(CompletionEvidenceError::Rejected) => {
                return Err(CompletionWorkerError::EvidenceRejected);
            }
        };
        self.verifier
            .verify(&evidence)
            .map_err(map_evidence_error)?;
        validate_manager_commit_evidence(&self.config, &work, &evidence)?;
        self.store
            .stage_completion_delivery(&work, &evidence)
            .map_err(|_| CompletionWorkerError::StateUnavailable)?;
        Ok(CompletionWorkerOutcomeV2::Staged)
    }

    fn begin_signing(
        &mut self,
        commit: &crate::CompletionCommitReadbackV2,
        now: u64,
    ) -> Result<crate::CompletionSigningWorkV2, CompletionWorkerError> {
        let challenge = self
            .challenge
            .issue(commit)
            .map_err(|_| CompletionWorkerError::ChallengeUnavailable)?;
        let draft = super::builder::draft(&self.config, commit, challenge, now)?;
        validate_completion_draft(&self.config, commit, &draft, now)?;
        self.store
            .begin_completion_signing(commit, &draft)
            .map_err(|_| CompletionWorkerError::StateUnavailable)
    }
}

const fn map_evidence_error(value: CompletionEvidenceError) -> CompletionWorkerError {
    match value {
        CompletionEvidenceError::Unavailable | CompletionEvidenceError::ResultUnknown => {
            CompletionWorkerError::EvidenceUnavailable
        }
        CompletionEvidenceError::Rejected => CompletionWorkerError::EvidenceRejected,
    }
}
