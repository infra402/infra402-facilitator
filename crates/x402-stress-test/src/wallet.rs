//! Wallet adapter for EVM payment signing using upstream x402-chain-eip155.

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use infra402_facilitator::timestamp::UnixTimestamp;
use infra402_facilitator::types::{
    EvmAddress, EvmSignature, ExactEvmPayload, ExactEvmPayloadAuthorization, ExactPaymentPayload,
    HexEncodedNonce, MixedAddress, PaymentPayload, PaymentRequirements, Scheme, TokenAmount,
    X402Version,
};
use x402_chain_eip155::v1_eip155_exact::client::{sign_erc3009_authorization, Eip3009SigningParams};
use x402_chain_eip155::v1_eip155_exact::types::PaymentRequirementsExtra;

/// EVM wallet adapter that uses upstream x402 signing infrastructure.
#[derive(Clone)]
pub struct EvmSenderWallet {
    signer: PrivateKeySigner,
}

impl EvmSenderWallet {
    pub fn new(signer: PrivateKeySigner) -> Self {
        Self { signer }
    }

    /// Signs a payment using the upstream x402-chain-eip155 signing infrastructure.
    pub async fn payment_payload(
        &self,
        requirements: PaymentRequirements,
    ) -> Result<PaymentPayload> {
        // Extract chain ID from network
        let chain_id = requirements
            .network
            .evm_chain_id()
            .context("Network is not an EVM chain")?;

        // Extract addresses
        let asset_address = match &requirements.asset {
            MixedAddress::Evm(addr) => Address::from(*addr),
            _ => anyhow::bail!("Asset is not an EVM address"),
        };

        let pay_to = match &requirements.pay_to {
            MixedAddress::Evm(addr) => Address::from(*addr),
            _ => anyhow::bail!("pay_to is not an EVM address"),
        };

        // Extract extra (EIP-712 domain name/version)
        let extra = requirements.extra.as_ref().map(|e| PaymentRequirementsExtra {
            name: e
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            version: e
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        });

        // Create signing parameters
        let params = Eip3009SigningParams {
            chain_id,
            asset_address,
            pay_to,
            amount: requirements.max_amount_required.0,
            max_timeout_seconds: requirements.max_timeout_seconds,
            extra,
        };

        // Sign using upstream function
        let upstream_payload = sign_erc3009_authorization(&self.signer, &params)
            .await
            .map_err(|e| anyhow::anyhow!("Signing failed: {:?}", e))?;

        // Convert upstream types to infra402 types
        let authorization = ExactEvmPayloadAuthorization {
            from: EvmAddress::from(upstream_payload.authorization.from),
            to: EvmAddress::from(upstream_payload.authorization.to),
            value: TokenAmount(upstream_payload.authorization.value),
            valid_after: UnixTimestamp(upstream_payload.authorization.valid_after.as_secs()),
            valid_before: UnixTimestamp(upstream_payload.authorization.valid_before.as_secs()),
            nonce: HexEncodedNonce(upstream_payload.authorization.nonce.0),
        };

        let evm_payload = ExactEvmPayload {
            signature: EvmSignature(upstream_payload.signature.to_vec()),
            authorization,
        };

        Ok(PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: requirements.network,
            payload: ExactPaymentPayload::Evm(evm_payload),
        })
    }
}
