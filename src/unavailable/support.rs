use crate::{
    ClockError, IntegrityAlertError, IntegrityAlertSinkPort, IntegrityViolationV2, TrustedClock,
};

pub struct UnavailableTrustedClock;
impl TrustedClock for UnavailableTrustedClock {
    fn now_epoch_s(&mut self) -> Result<u64, ClockError> {
        Err(ClockError::Unavailable)
    }
}

pub struct UnavailableIntegrityAlertSink;
impl IntegrityAlertSinkPort for UnavailableIntegrityAlertSink {
    fn emit(&mut self, _: &IntegrityViolationV2) -> Result<(), IntegrityAlertError> {
        Err(IntegrityAlertError::Unavailable)
    }
}
