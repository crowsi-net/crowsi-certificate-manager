use std::{collections::BTreeSet, fs};

use crowsi_certificate_manager::{
    CertificateCommandV2, CertificateOperation, SignedAuthorityOutcomeReceiptV2,
    SignedAuthorityReadinessAttestationV2, SignedAuthorityReconciliationReceiptV2,
    SignedCertificateExecutionAuthorizationV2, SignedKeyCustodyAttestationV2,
};
use support::*;

#[test]
fn schema_directory_contains_only_the_declared_v2_contracts() {
    let directory = schema_directory();
    let actual = fs::read_dir(&directory)
        .expect("schema directory")
        .map(|entry| entry.expect("schema entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    let expected = DOCUMENTS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    for (name, id) in DOCUMENTS {
        let document = read_schema(&directory.join(name));
        assert_eq!(document["$id"], id);
        assert_eq!(
            document["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
}

#[test]
fn serialized_ingress_envelopes_use_the_documented_v2_uris() {
    let command = CertificateCommandV2 {
        schema: DOCUMENTS[1].1.into(),
        request_id: "request.issue.0001".into(),
        nonce: "nonce.issue.0001".into(),
        operation: CertificateOperation::Issue,
        resource_id: "resource.certificate.0001".into(),
        expected_resource_version: 0,
        previous_lifecycle_revocation_epoch: 0,
        lifecycle_revocation_epoch: 0,
        profile_id: "profile.service".into(),
        purpose: "service-authentication".into(),
        subject: "spiffe://crowsi.test/subjects/service".into(),
        audience: "service://example/local".into(),
        scopes: vec!["service.read".into()],
        requested_ttl_seconds: 60,
        target_certificate_id: None,
        key_enrollment: None,
    };
    assert_schema(&command, DOCUMENTS[1].1);
    assert_schema(
        &SignedCertificateExecutionAuthorizationV2::new(
            "key.pa",
            "cGF5bG9hZA==",
            "11".repeat(32),
            "c2ln",
        ),
        DOCUMENTS[2].1,
    );
    assert_schema(
        &SignedKeyCustodyAttestationV2::new("key.custody", "cGF5bG9hZA==", "c2ln"),
        DOCUMENTS[3].1,
    );
    assert_schema(
        &SignedAuthorityReadinessAttestationV2::new("key.attestation", "cGF5bG9hZA==", "c2ln"),
        DOCUMENTS[4].1,
    );
    assert_schema(&authority_receipt(), DOCUMENTS[5].1);
    assert_schema(&reconciliation_receipt(), DOCUMENTS[6].1);
}

fn authority_receipt() -> SignedAuthorityOutcomeReceiptV2 {
    SignedAuthorityOutcomeReceiptV2 {
        schema: DOCUMENTS[5].1.into(),
        key_id: "key.receipt".into(),
        payload_base64: "cGF5bG9hZA==".into(),
        signature_base64: "c2ln".into(),
    }
}

fn reconciliation_receipt() -> SignedAuthorityReconciliationReceiptV2 {
    SignedAuthorityReconciliationReceiptV2 {
        schema: DOCUMENTS[6].1.into(),
        key_id: "key.receipt".into(),
        payload_base64: "cGF5bG9hZA==".into(),
        signature_base64: "c2ln".into(),
    }
}
use crate::support;
