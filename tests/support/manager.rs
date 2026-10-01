use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::CertificateManager;

use super::*;

pub type TestManager = CertificateManager<
    Authority,
    ReadinessVerifier,
    WorkloadVerifier,
    AuthorizationVerifier,
    EnrollmentVerifier,
    CustodyVerifier,
    CertificateVerifier,
    OutcomeVerifier,
    StateStore,
    SequenceClock,
>;

pub struct Harness {
    pub manager: TestManager,
    pub state: Arc<Mutex<StoreData>>,
    pub authority: Arc<Mutex<AuthorityState>>,
    pub integrity: Arc<Mutex<IntegrityData>>,
}

pub fn harness(command: &crowsi_certificate_manager::CertificateCommandV2) -> Harness {
    let (authority, authority_state) = authority();
    let (store, state) = state_store();
    let (integrity_sink, integrity) = integrity_sink();
    Harness {
        manager: build_manager_with_sink(
            command,
            authority,
            store,
            vec![NOW, NOW + 1],
            false,
            integrity_sink,
        ),
        state,
        authority: authority_state,
        integrity,
    }
}
