use crate::{
    AuthorityReadinessVerifierPort, CertificateAuthorityPort, CertificateCommandV2,
    CertificateExecutionAuthorizationVerifierPort, KeyCustodyAttestationVerifierPort, ManagerError,
    SignedCertificateExecutionAuthorizationV2, SignedKeyCustodyAttestationV2, TrustedClock,
    VerifiedKeyEnrollmentV2, VerifiedWorkloadV2,
    validation::{
        validate_command_authorization, validate_custody, validate_signed_custody,
        validate_workload,
    },
};

use super::{CertificateManager, PreparedV2, mapping, preflight::validate_authorization_lease};

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    A: CertificateAuthorityPort,
    R: AuthorityReadinessVerifierPort,
    P: CertificateExecutionAuthorizationVerifierPort,
    C: KeyCustodyAttestationVerifierPort,
    T: TrustedClock,
{
    pub(crate) fn refresh_before_authority(
        &mut self,
        prepared: &mut PreparedV2,
        command: &CertificateCommandV2,
        signed_authorization: &SignedCertificateExecutionAuthorizationV2,
        signed_custody: Option<&SignedKeyCustodyAttestationV2>,
    ) -> Result<u64, ManagerError> {
        let now = self
            .clock
            .now_epoch_s()
            .map_err(|_| ManagerError::TrustedTimeRejected)?;
        if now < prepared.initial_time_epoch_s {
            return Err(ManagerError::TrustedTimeRejected);
        }
        validate_workload(&self.config, &prepared.workload, now)?;
        let authorization = self
            .authorization_verifier
            .verify(signed_authorization)
            .map_err(mapping::authorization)?;
        validate_authorization_lease(signed_authorization, &authorization)?;
        validate_command_authorization(
            &self.config,
            &prepared.workload,
            command,
            &authorization,
            now,
        )?;
        if authorization != prepared.authorization {
            return Err(ManagerError::AuthorizationBindingRejected);
        }
        let custody = self.verify_custody(
            signed_custody,
            prepared.enrollment.as_ref(),
            &prepared.workload,
            &command.digest_sha256(),
            now,
        )?;
        if custody != prepared.custody {
            return Err(ManagerError::KeyCustodyRejected);
        }
        let readiness = self.verify_readiness(now)?;
        if !valid_readiness_refresh(&prepared.readiness, &readiness) {
            return Err(ManagerError::AuthorityUnavailable);
        }
        prepared.readiness = readiness;
        Ok(now)
    }

    pub(crate) fn verify_custody(
        &mut self,
        signed: Option<&SignedKeyCustodyAttestationV2>,
        enrollment: Option<&VerifiedKeyEnrollmentV2>,
        workload: &VerifiedWorkloadV2,
        command_digest: &str,
        now: u64,
    ) -> Result<Option<crate::VerifiedKeyCustodyAttestationV2>, ManagerError> {
        let Some((signed, enrollment)) = signed.zip(enrollment) else {
            return Ok(None);
        };
        validate_signed_custody(&self.config, signed)?;
        let value = self
            .custody_verifier
            .verify(signed)
            .map_err(mapping::custody)?;
        validate_custody(
            &self.config,
            workload,
            enrollment,
            command_digest,
            &value,
            now,
        )?;
        Ok(Some(value))
    }
}

pub(crate) fn valid_readiness_refresh(
    previous: &crate::AuthorityReadinessV2,
    current: &crate::AuthorityReadinessV2,
) -> bool {
    let old = &previous.lease;
    let new = &current.lease;
    let stable = old.security_domain == new.security_domain
        && old.deployment_id == new.deployment_id
        && old.authority_id == new.authority_id
        && old.key_id == new.key_id
        && old.authority_key_version == new.authority_key_version
        && old.authority_public_key_spki_sha256 == new.authority_public_key_spki_sha256
        && old.signature_algorithm == new.signature_algorithm
        && old.key_provider_signature_profile == new.key_provider_signature_profile
        && old.key_purpose == new.key_purpose
        && old.authority_receipt_key_id == new.authority_receipt_key_id
        && old.authority_receipt_key_version == new.authority_receipt_key_version
        && old.authority_receipt_public_key_spki_sha256
            == new.authority_receipt_public_key_spki_sha256
        && old.authority_receipt_signature_algorithm == new.authority_receipt_signature_algorithm
        && old.authority_receipt_key_purpose == new.authority_receipt_key_purpose
        && old.verifier_key_id == new.verifier_key_id
        && old.verifier_key_version == new.verifier_key_version
        && old.verifier_public_key_spki_sha256 == new.verifier_public_key_spki_sha256
        && old.verifier_signature_algorithm == new.verifier_signature_algorithm
        && old.verifier_key_purpose == new.verifier_key_purpose
        && old.trust_revision == new.trust_revision;
    let monotonic = if old.lease_id == new.lease_id {
        old == new
    } else {
        new.fence > old.fence && new.issued_at_epoch_s >= old.issued_at_epoch_s
    };
    stable && monotonic
}
