use thiserror::Error;

mod completion;
mod handoff;

pub use completion::{
    CompletionDeliveryError, CompletionDeliveryWorkerError, CompletionEvidenceError,
    CompletionStateError, CompletionWorkerError,
};
pub use handoff::HandoffError;

macro_rules! boundary_error {
    ($name:ident, $unavailable:literal, $rejected:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
        pub enum $name {
            #[error($unavailable)]
            Unavailable,
            #[error($rejected)]
            Rejected,
        }
    };
}

boundary_error!(
    WorkloadIdentityError,
    "workload identity verifier unavailable",
    "workload evidence rejected"
);
boundary_error!(
    AuthorizationError,
    "certificate authorization verifier unavailable",
    "certificate authorization rejected"
);
boundary_error!(
    KeyEnrollmentError,
    "key enrollment verifier unavailable",
    "key enrollment rejected"
);
boundary_error!(
    KeyCustodyError,
    "key custody verifier unavailable",
    "key custody attestation rejected"
);
boundary_error!(
    PublicCertificateError,
    "public certificate verifier unavailable",
    "public certificate rejected"
);
boundary_error!(
    AuthorityOutcomeError,
    "authority outcome verifier unavailable",
    "authority outcome receipt rejected"
);
boundary_error!(
    IntegrityAlertError,
    "independent integrity alert sink unavailable",
    "independent integrity alert rejected"
);
boundary_error!(
    CompletionChallengeError,
    "completion challenge source unavailable",
    "completion challenge rejected"
);
boundary_error!(
    AuditError,
    "durable audit store unavailable",
    "durable audit transition rejected"
);
boundary_error!(
    LifecycleError,
    "certificate lifecycle store unavailable",
    "certificate lifecycle transition rejected"
);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OperationStateError {
    #[error("operation transaction store unavailable")]
    Unavailable,
    #[error("request, nonce, authorization, or JTI replayed")]
    Replay,
    #[error("lifecycle owner does not match")]
    Ownership,
    #[error("lifecycle state, version, reservation, or fence conflicts")]
    Conflict,
    #[error("operation transition rejected")]
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClockError {
    #[error("trusted clock unavailable")]
    Unavailable,
    #[error("trusted clock rollback detected")]
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LedgerError {
    #[error("one-use ledger unavailable")]
    Unavailable,
    #[error("one-use value replayed")]
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthorityError {
    #[error("certificate authority unavailable")]
    Unavailable,
    #[error("certificate authority rejected the command")]
    Rejected,
    #[error("certificate authority result is ambiguous")]
    ResultUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagerError {
    #[error("certificate manager configuration is invalid")]
    InvalidConfiguration,
    #[error("certificate command is invalid or unsupported")]
    InvalidCommand,
    #[error("workload evidence is invalid")]
    InvalidWorkloadEvidence,
    #[error("workload authentication failed")]
    WorkloadNotAuthenticated,
    #[error("workload claims do not satisfy the local policy")]
    WorkloadClaimsRejected,
    #[error("trusted time is unavailable or rolled back")]
    TrustedTimeRejected,
    #[error("V2 execution authorization is unavailable")]
    AuthorizationUnavailable,
    #[error("V2 execution authorization binding is invalid")]
    AuthorizationBindingRejected,
    #[error("key enrollment proof is invalid")]
    KeyEnrollmentRejected,
    #[error("non-exportable device key custody is not proven")]
    KeyCustodyRejected,
    #[error("authority attestation lease is unavailable or invalid")]
    AuthorityUnavailable,
    #[error("manager handoff was not accepted")]
    HandoffRejected,
    #[error("manager handoff result is unknown and must be retried")]
    HandoffResultUnknown,
    #[error("one-use execution authorization was replayed")]
    Replay,
    #[error("lifecycle ownership, CAS, or monotonic transition was rejected")]
    LifecycleRejected,
    #[error("durable lifecycle storage is unavailable")]
    LifecycleUnavailable,
    #[error("durable audit storage is unavailable")]
    AuditUnavailable,
    #[error("authority command was rejected before an accepted outcome")]
    AuthorityRejected,
    #[error("authority result is unknown and requires reconciliation")]
    AuthorityResultUnknown,
    #[error("scoped reconciliation was rejected")]
    ReconciliationRejected,
}
