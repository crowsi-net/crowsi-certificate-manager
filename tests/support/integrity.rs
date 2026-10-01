use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

#[derive(Default)]
pub struct IntegrityData {
    pub events: Vec<IntegrityViolationV2>,
    pub fail: bool,
}

pub struct IntegritySink(pub Arc<Mutex<IntegrityData>>);

impl IntegrityAlertSinkPort for IntegritySink {
    fn emit(&mut self, violation: &IntegrityViolationV2) -> Result<(), IntegrityAlertError> {
        let mut data = self.0.lock().expect("integrity sink");
        if data.fail {
            return Err(IntegrityAlertError::Unavailable);
        }
        data.events.push(violation.clone());
        Ok(())
    }
}

pub fn integrity_sink() -> (IntegritySink, Arc<Mutex<IntegrityData>>) {
    let data = Arc::new(Mutex::new(IntegrityData::default()));
    (IntegritySink(Arc::clone(&data)), data)
}
