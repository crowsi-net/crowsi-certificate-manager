use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::Value;

pub const DOCUMENTS: [(&str, &str); 11] = [
    (
        "common-definitions-v2.schema.json",
        "crowsi://certificates/common-definitions/v2",
    ),
    (
        "management-command-v2.schema.json",
        "crowsi://certificates/management-command/v2",
    ),
    (
        "execution-authorization-v2.schema.json",
        "crowsi://certificates/execution-authorization/v2",
    ),
    (
        "key-custody-attestation-v2.schema.json",
        "crowsi://certificates/key-custody-attestation/v2",
    ),
    (
        "authority-readiness-attestation-v2.schema.json",
        "crowsi://certificates/authority-readiness-attestation/v2",
    ),
    (
        "authority-outcome-receipt-v2.schema.json",
        "crowsi://certificates/authority-outcome-receipt/v2",
    ),
    (
        "authority-reconciliation-receipt-v2.schema.json",
        "crowsi://certificates/authority-reconciliation-receipt/v2",
    ),
    (
        "service-projections-v2.schema.json",
        "crowsi://certificates/service-projections/v2",
    ),
    (
        "management-response-v2.schema.json",
        "crowsi://certificates/management-response/v2",
    ),
    (
        "operation-status-v2.schema.json",
        "crowsi://certificates/operation-status/v2",
    ),
    (
        "reconciliation-response-v2.schema.json",
        "crowsi://certificates/reconciliation-response/v2",
    ),
];

pub fn schema_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

pub fn read_schema(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("schema document")).expect("valid JSON")
}

pub fn assert_schema(value: &impl Serialize, expected: &str) {
    assert_eq!(
        serde_json::to_value(value).expect("serialize")["schema"],
        expected
    );
}

pub fn assert_required_keys(value: &Value, document: &str) {
    let schema = read_schema(&schema_directory().join(document));
    let required = schema["required"]
        .as_array()
        .expect("required array")
        .iter()
        .map(|item| item.as_str().expect("required key"))
        .collect::<BTreeSet<_>>();
    let actual = value
        .as_object()
        .expect("serialized object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, required);
}
