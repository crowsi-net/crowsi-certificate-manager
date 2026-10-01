use crate::support;

use crowsi_certificate_manager::{CertificateOperation, ReconciliationResultV2};
use support::*;

#[test]
fn service_responses_match_their_closed_top_level_documents() {
    let command = command(CertificateOperation::Issue);
    let mut initial = harness(&command);
    let response = initial
        .manager
        .execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        )
        .expect("issue response");
    assert_required_keys(
        &serde_json::to_value(&response).expect("serialize response"),
        "management-response-v2.schema.json",
    );
    let query = operation_status_query(&command);
    let mut manager = operation_status_manager(&query, initial.authority, initial.state);
    let status = manager
        .operation_status(&evidence(), &query, &signed_status_authorization())
        .expect("operation status");
    let status_document = serde_json::to_value(&status).expect("serialize status");
    assert_required_keys(&status_document, "operation-status-v2.schema.json");
    assert_control_projection_is_redacted(&status_document);
    let reconciliation = ReconciliationResultV2 {
        status,
        recovered_outcome: None,
    };
    assert_required_keys(
        &serde_json::to_value(reconciliation).expect("serialize reconciliation"),
        "reconciliation-response-v2.schema.json",
    );
}

fn assert_control_projection_is_redacted(value: &serde_json::Value) {
    const FORBIDDEN: &[&str] = &[
        "authorization_jti",
        "authorization_lease_digest_sha256",
        "key_enrollment",
        "public_certificate",
        "receipt",
        "payload_base64",
        "signature_base64",
    ];
    match value {
        serde_json::Value::Object(fields) => {
            for key in fields.keys() {
                assert!(!FORBIDDEN.contains(&key.as_str()), "leaked field: {key}");
            }
            for nested in fields.values() {
                assert_control_projection_is_redacted(nested);
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                assert_control_projection_is_redacted(nested);
            }
        }
        _ => {}
    }
}
