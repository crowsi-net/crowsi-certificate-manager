use crate::{
    CertificateManagerHandoffPort, HandoffError, ManagerHandoffReadbackV2, VerifiedManagerHandoffV2,
};

pub struct UnavailableCertificateManagerHandoff;

impl CertificateManagerHandoffPort for UnavailableCertificateManagerHandoff {
    fn accept(
        &mut self,
        _: &ManagerHandoffReadbackV2,
    ) -> Result<VerifiedManagerHandoffV2, HandoffError> {
        Err(HandoffError::Unavailable)
    }
}
