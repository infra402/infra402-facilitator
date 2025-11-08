use crate::X402PaymentsError;
use infra402_facilitator::types::{PaymentPayload, PaymentRequirements};
use std::sync::Arc;

pub mod evm;
pub mod solana;

#[async_trait::async_trait]
pub trait SenderWallet: Send + Sync {
    fn can_handle(&self, requirements: &PaymentRequirements) -> bool;
    async fn payment_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError>;
}

pub trait IntoSenderWallet {
    fn into_sender_wallet(self) -> Arc<dyn SenderWallet>;
}
