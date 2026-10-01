use crate::{
    AuthorityError, AuthorizationError, KeyCustodyError, KeyEnrollmentError, ManagerError,
    OperationStateError, WorkloadIdentityError,
};

pub const fn workload(_: WorkloadIdentityError) -> ManagerError {
    ManagerError::WorkloadNotAuthenticated
}

pub const fn authorization(error: AuthorizationError) -> ManagerError {
    match error {
        AuthorizationError::Unavailable => ManagerError::AuthorizationUnavailable,
        AuthorizationError::Rejected => ManagerError::AuthorizationBindingRejected,
    }
}

pub const fn enrollment(_: KeyEnrollmentError) -> ManagerError {
    ManagerError::KeyEnrollmentRejected
}

pub const fn custody(_: KeyCustodyError) -> ManagerError {
    ManagerError::KeyCustodyRejected
}

pub const fn readiness(_: AuthorityError) -> ManagerError {
    ManagerError::AuthorityUnavailable
}

pub const fn begin(error: OperationStateError) -> ManagerError {
    match error {
        OperationStateError::Unavailable => ManagerError::LifecycleUnavailable,
        OperationStateError::Replay => ManagerError::Replay,
        OperationStateError::Ownership
        | OperationStateError::Conflict
        | OperationStateError::Rejected => ManagerError::LifecycleRejected,
    }
}

pub const fn reconcile(error: OperationStateError) -> ManagerError {
    match error {
        OperationStateError::Unavailable => ManagerError::AuditUnavailable,
        OperationStateError::Replay
        | OperationStateError::Ownership
        | OperationStateError::Conflict
        | OperationStateError::Rejected => ManagerError::ReconciliationRejected,
    }
}
