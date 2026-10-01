use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HandoffError {
    #[error("manager handoff boundary unavailable")]
    Unavailable,
    #[error("manager handoff evidence or acknowledgement rejected")]
    Rejected,
    #[error("manager handoff result is unknown")]
    ResultUnknown,
}
