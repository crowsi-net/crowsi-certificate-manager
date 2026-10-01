use crate::VerifiedCertificateExecutionAuthorizationV2;

use super::{
    super::common::{valid_digest, valid_id},
    transition::requires_user_presence,
};

pub(super) fn separation_of_duties(value: &VerifiedCertificateExecutionAuthorizationV2) -> bool {
    if !valid_id(&value.requester_pairwise_subject) {
        return false;
    }
    let approver = (
        value.approver_pairwise_subject.as_deref(),
        value.approver_profile.as_deref(),
        value.approver_device.as_deref(),
        value.approver_actor.as_deref(),
        value.approver_proof_key_ref.as_deref(),
    );
    if requires_user_presence(value.action) {
        matches!(
            approver,
            (Some(subject), Some(profile), Some(device), Some(actor), Some(proof))
                if [subject, profile, device, actor, proof].into_iter().all(valid_id)
                    && subject != value.requester_pairwise_subject
        )
    } else {
        matches!(approver, (None, None, None, None, None))
    }
}

pub(super) fn valid_approval(
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> bool {
    let evidence = (
        value.approval_id.as_deref(),
        value.approval_evidence_digest_sha256.as_deref(),
        value.approval_method,
        value.approval_assurance,
        value.approval_verified_at_epoch_s,
        value.approval_issued_at_epoch_s,
        value.approval_expires_at_epoch_s,
    );
    if requires_user_presence(value.action) {
        matches!(
            evidence,
            (
                Some(id),
                Some(digest),
                Some(method),
                Some(_),
                Some(verified_at),
                Some(issued_at),
                Some(expires_at)
            )
                if valid_id(id)
                    && valid_digest(digest)
                    && method.has_user_presence()
                    && issued_at <= verified_at
                    && verified_at > 0
                    && verified_at <= now
                    && now.saturating_sub(verified_at) <= 60
                    && now < expires_at
                    && value.issued_at_epoch_s >= issued_at
                    && value.expires_at_epoch_s <= expires_at
        )
    } else {
        matches!(evidence, (None, None, None, None, None, None, None))
    }
}
