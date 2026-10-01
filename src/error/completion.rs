use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompletionEvidenceError {
    #[error("manager completion signer unavailable")]
    Unavailable,
    #[error("manager completion evidence rejected")]
    Rejected,
    #[error("manager completion signing result is unknown")]
    ResultUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompletionStateError {
    #[error("completion outbox unavailable")]
    Unavailable,
    #[error("completion state conflicts with durable commit")]
    Conflict,
    #[error("completion transition rejected")]
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompletionDeliveryError {
    #[error("completion delivery unavailable")]
    Unavailable,
    #[error("completion delivery rejected")]
    Rejected,
    #[error("completion delivery result is unknown")]
    ResultUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompletionDeliveryWorkerError {
    #[error("completion delivery outbox unavailable or inconsistent")]
    StateUnavailable,
    #[error("completion delivery transport unavailable")]
    DeliveryUnavailable,
    #[error("completion delivery acknowledgement rejected")]
    DeliveryRejected,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompletionWorkerError {
    #[error("completion configuration or durable readback is invalid")]
    InvalidConfiguration,
    #[error("completion outbox state is unavailable or inconsistent")]
    StateUnavailable,
    #[error("completion challenge generation failed")]
    ChallengeUnavailable,
    #[error("completion signer or independent verifier is unavailable")]
    EvidenceUnavailable,
    #[error("completion evidence is invalid")]
    EvidenceRejected,
    #[error("trusted time is unavailable or moved backwards")]
    TrustedTimeRejected,
}
