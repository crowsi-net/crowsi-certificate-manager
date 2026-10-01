use crate::{
    AuditOperationState, CertificateMetadataV2, CertificateOperation, CertificateState,
    LifecycleReservationIntentV2, LifecycleReservationV2, LifecycleStateV2, ManagerError,
    OperationBeginV2, OperationReservationV2,
};

use super::common::{valid_digest, valid_id};

pub fn validate_operation_reservation(
    begin: &OperationBeginV2,
    value: &OperationReservationV2,
) -> Result<(), ManagerError> {
    let lifecycle = &value.lifecycle;
    let audit = &value.audit;
    let exact = lifecycle.intent == begin.lifecycle
        && begin.lifecycle.previous_lifecycle_revocation_epoch
            == begin
                .audit
                .authorization
                .previous_lifecycle_revocation_epoch
        && begin.lifecycle.lifecycle_revocation_epoch
            == begin.audit.authorization.lifecycle_revocation_epoch
        && lifecycle.reservation_id == begin.lifecycle.required_reservation_id
        && lifecycle.previous_fence == begin.lifecycle.previous_fence
        && lifecycle.current_fence == begin.lifecycle.current_fence
        && lifecycle.prior_resource_version == begin.lifecycle.expected_resource_version
        && lifecycle.prior_lifecycle_revocation_epoch
            == begin.lifecycle.previous_lifecycle_revocation_epoch
        && lifecycle.prior_lifecycle_revocation_epoch <= begin.lifecycle.lifecycle_revocation_epoch
        && audit.request_id == begin.request_id
        && audit.intent_digest_sha256 == begin.audit.digest_sha256()
        && audit.reservation_id == lifecycle.reservation_id;
    let version = match begin.lifecycle.operation {
        CertificateOperation::Status => Some(lifecycle.prior_resource_version),
        _ => lifecycle.prior_resource_version.checked_add(1),
    };
    let valid = matches!(
        value.phase,
        AuditOperationState::Reserved | AuditOperationState::Invoked
    ) && value.state_revision > 0
        && valid_id(&lifecycle.reservation_id)
        && match value.phase {
            AuditOperationState::Reserved => {
                value.invoked_authority_command_digest_sha256.is_none()
                    && value.invoked_at_epoch_s.is_none()
            }
            AuditOperationState::Invoked => {
                value
                    .invoked_authority_command_digest_sha256
                    .as_deref()
                    .is_some_and(valid_digest)
                    && value.invoked_at_epoch_s.is_some()
            }
            _ => false,
        }
        && Some(lifecycle.reserved_resource_version) == version
        && allowed_prior(&begin.lifecycle, lifecycle);
    (exact && valid)
        .then_some(())
        .ok_or(ManagerError::LifecycleRejected)
}

fn allowed_prior(intent: &LifecycleReservationIntentV2, value: &LifecycleReservationV2) -> bool {
    let target = intent.target_certificate_id.as_deref();
    match intent.operation {
        CertificateOperation::Issue => {
            value.prior_state == LifecycleStateV2::Absent
                && value.prior_certificate_id.is_none()
                && value.prior_metadata.is_none()
                && value.prior_resource_version == 0
                && value.prior_lifecycle_revocation_epoch == 0
        }
        CertificateOperation::Renew => {
            value.prior_state == LifecycleStateV2::Active
                && value.prior_certificate_id.as_deref() == target
                && value.prior_metadata.as_ref().is_some_and(|metadata| {
                    Some(metadata.certificate_id.as_str()) == target
                        && metadata.state == CertificateState::Active
                        && valid_prior_metadata(metadata)
                })
        }
        CertificateOperation::Revoke => {
            matches!(
                value.prior_state,
                LifecycleStateV2::Active | LifecycleStateV2::Expired
            ) && value.prior_certificate_id.as_deref() == target
                && value.prior_metadata.as_ref().is_some_and(|metadata| {
                    Some(metadata.certificate_id.as_str()) == target
                        && lifecycle_state(metadata.state) == value.prior_state
                        && valid_prior_metadata(metadata)
                })
        }
        CertificateOperation::Status => {
            value.prior_state != LifecycleStateV2::Absent
                && value.prior_certificate_id.as_deref() == target
                && value.prior_metadata.as_ref().is_some_and(|metadata| {
                    Some(metadata.certificate_id.as_str()) == target
                        && lifecycle_state(metadata.state) == value.prior_state
                        && valid_prior_metadata(metadata)
                })
        }
    }
}

fn valid_prior_metadata(value: &CertificateMetadataV2) -> bool {
    valid_id(&value.certificate_id)
        && !value.serial_number.is_empty()
        && valid_digest(&value.fingerprint_sha256)
        && valid_digest(&value.public_key_sha256)
        && value.expires_at_epoch_s >= value.not_before_epoch_s
}

pub const fn lifecycle_state(value: CertificateState) -> LifecycleStateV2 {
    match value {
        CertificateState::Active => LifecycleStateV2::Active,
        CertificateState::Revoked => LifecycleStateV2::Revoked,
        CertificateState::Expired => LifecycleStateV2::Expired,
        CertificateState::Unknown => LifecycleStateV2::Absent,
    }
}
