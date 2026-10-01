use crate::{IntegrityAlertError, IntegrityViolationV2};

pub trait IntegrityAlertSinkPort {
    /// Durably latches a critical event outside lifecycle and audit projections.
    ///
    /// # Errors
    ///
    /// The caller must surface sink failure as an operational outage.
    fn emit(&mut self, violation: &IntegrityViolationV2) -> Result<(), IntegrityAlertError>;
}
