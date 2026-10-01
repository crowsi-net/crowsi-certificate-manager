use crate::support;

use crowsi_certificate_manager::{CertificateManagerConfig, CertificateOperation, ManagerError};
use support::*;

#[test]
fn configuration_rejects_reused_cryptographic_key_roles() {
    let mut reused_id = config();
    reused_id.authority_receipt_verifier_key_id = reused_id.authority_key_id.clone();
    assert_invalid(reused_id);

    let mut reused_spki = config();
    reused_spki.authority_receipt_public_key_spki_sha256 =
        reused_spki.authority_public_key_spki_sha256.clone();
    assert_invalid(reused_spki);

    let mut commit_reuses_receipt = config();
    commit_reuses_receipt.manager_commit_key_id = commit_reuses_receipt
        .authority_receipt_verifier_key_id
        .clone();
    assert_invalid(commit_reuses_receipt);

    let mut commit_reuses_spki = config();
    commit_reuses_spki.manager_commit_public_key_spki_sha256 = commit_reuses_spki
        .authority_receipt_public_key_spki_sha256
        .clone();
    assert_invalid(commit_reuses_spki);

    let mut handoff_reuses_commit = config();
    handoff_reuses_commit.manager_handoff_key_id =
        handoff_reuses_commit.manager_commit_key_id.clone();
    assert_invalid(handoff_reuses_commit);

    let mut handoff_reuses_spki = config();
    handoff_reuses_spki.manager_handoff_public_key_spki_sha256 = handoff_reuses_spki
        .manager_commit_public_key_spki_sha256
        .clone();
    assert_invalid(handoff_reuses_spki);
}

#[test]
fn authority_receipts_require_the_provider_p1363_low_s_profile() {
    for algorithm in ["ed25519", "ecdsa-p256-sha256"] {
        let mut invalid = config();
        invalid.authority_receipt_signature_algorithm = algorithm.into();
        assert_invalid(invalid);

        let mut invalid = config();
        invalid.manager_commit_signature_algorithm = algorithm.into();
        assert_invalid(invalid);

        let mut invalid = config();
        invalid.manager_handoff_signature_algorithm = algorithm.into();
        assert_invalid(invalid);
    }
}

fn assert_invalid(config: CertificateManagerConfig) {
    let command = command(CertificateOperation::Issue);
    let (authority, authority_state) = authority();
    let (store, _) = state_store();
    let (sink, _) = integrity_sink();
    let mut manager = build_manager_with_config(
        &command,
        authority,
        store,
        vec![NOW, NOW + 1],
        false,
        sink,
        config,
    );

    assert_eq!(
        manager.execute_mutation(
            &evidence(),
            &command,
            &signed_authorization(),
            Some(&signed_custody()),
        ),
        Err(ManagerError::InvalidConfiguration)
    );
    assert!(
        authority_state
            .lock()
            .expect("authority")
            .executed
            .is_empty()
    );
}
