//! High-assurance certificate lifecycle boundary for Crowsi services.
//!
//! The crate exposes only V2 mutation contracts. Private keys never cross this
//! boundary, and every production adapter is unavailable until explicitly wired.

mod completion;
mod digest;
mod error;
mod manager;
mod model;
mod ports;
mod unavailable;
mod validation;

pub use completion::{CertificateCompletionDeliveryWorker, CertificateCompletionWorker};
pub use error::{
    AuditError, AuthorityError, AuthorityOutcomeError, AuthorizationError, ClockError,
    CompletionChallengeError, CompletionDeliveryError, CompletionDeliveryWorkerError,
    CompletionEvidenceError, CompletionStateError, CompletionWorkerError, HandoffError,
    IntegrityAlertError, KeyCustodyError, KeyEnrollmentError, LedgerError, LifecycleError,
    ManagerError, OperationStateError, PublicCertificateError, WorkloadIdentityError,
};
pub use manager::CertificateManager;
pub use model::*;
pub use ports::*;
pub use unavailable::*;
