pub(super) fn same_workload_binding(
    stored: &crate::VerifiedWorkloadV2,
    authorization: &crate::VerifiedCertificateExecutionAuthorizationV2,
    current: &crate::VerifiedWorkloadV2,
) -> bool {
    let stable = current.service_id == stored.service_id
        && current.workload_id == stored.workload_id
        && current.pairwise_subject == stored.pairwise_subject
        && current.actor == stored.actor
        && current.device == stored.device
        && current.profile == stored.profile
        && current.proof_key_ref == stored.proof_key_ref
        && current.identity_revocation_epoch == stored.identity_revocation_epoch
        && current.transport == stored.transport;
    let authorized = current.service_id == authorization.service_id
        && current.workload_id == authorization.workload
        && current.pairwise_subject == authorization.pairwise_subject
        && current.actor == authorization.requester_actor
        && current.device == authorization.requester_device
        && current.profile == authorization.requester_profile
        && current.proof_key_ref == authorization.requester_proof_key_ref
        && current.identity_revocation_epoch == authorization.identity_revocation_epoch;
    stable && authorized
}

pub(super) fn same_custody_binding(
    stored: &crate::VerifiedKeyCustodyAttestationV2,
    current: &crate::VerifiedKeyCustodyAttestationV2,
) -> bool {
    current.security_domain == stored.security_domain
        && current.deployment_id == stored.deployment_id
        && current.service_id == stored.service_id
        && current.workload_id == stored.workload_id
        && current.pairwise_subject == stored.pairwise_subject
        && current.device_id == stored.device_id
        && current.profile == stored.profile
        && current.proof_key_ref == stored.proof_key_ref
        && current.identity_revocation_epoch == stored.identity_revocation_epoch
        && current.public_key_sha256 == stored.public_key_sha256
        && current.command_digest_sha256 == stored.command_digest_sha256
        && current.provider_id == stored.provider_id
        && current.signature_key_id == stored.signature_key_id
        && current.signature_key_version == stored.signature_key_version
        && current.signature_public_key_spki_sha256 == stored.signature_public_key_spki_sha256
        && current.signature_algorithm == stored.signature_algorithm
        && current.signature_key_purpose == stored.signature_key_purpose
        && current.trust_revision == stored.trust_revision
        && current.custody == stored.custody
}
