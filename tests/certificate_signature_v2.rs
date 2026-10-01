use crate::support;

use crowsi_certificate_manager::{AuditOperationState, CertificateOperation, ManagerError};
use support::*;

#[test]
fn noncanonical_or_high_s_x509_signature_fails_closed() {
    let command = command(CertificateOperation::Issue);
    let mut harness = harness(&command);
    harness
        .authority
        .lock()
        .expect("authority")
        .invalid_certificate_signature = true;

    assert!(matches!(
        harness.manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::AuthorityResultUnknown)
    ));
    assert_eq!(
        harness.state.lock().expect("state").phase,
        Some(AuditOperationState::ResultUnknown)
    );
}
