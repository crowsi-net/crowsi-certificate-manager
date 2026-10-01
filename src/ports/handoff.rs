use crate::{HandoffError, ManagerHandoffReadbackV2, VerifiedManagerHandoffV2};

pub trait CertificateManagerHandoffPort {
    /// Recovers or submits the exact durable operation-acceptance evidence.
    ///
    /// Implementations journal the signing attempt before hardware invocation,
    /// independently verify the signature, and retry the PA by operation and
    /// receipt ID. They return `ResultUnknown` until an exact PA ACK or a signed
    /// `NotAccepted` abandonment has been durably established.
    ///
    /// # Errors
    ///
    /// Rejects changed readback, signature/key substitution, or altered replay.
    fn accept(
        &mut self,
        readback: &ManagerHandoffReadbackV2,
    ) -> Result<VerifiedManagerHandoffV2, HandoffError>;
}
