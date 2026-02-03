use anyhow::{Context, Result};
use infra402_facilitator::proto::v2::{
    ExactSchemePayload, PaymentPayload as PaymentPayloadV2,
    PaymentRequirements as PaymentRequirementsV2, VerifyRequest as VerifyRequestV2, X402Version2,
};
use infra402_facilitator::types::{
    ExactPaymentPayload, PaymentPayload, PaymentRequirements, SettleResponse, VerifyRequest,
    VerifyResponse,
};
use reqwest::Client;

/// HTTP client for interacting with the facilitator's /verify and /settle endpoints
#[derive(Clone)]
pub struct FacilitatorClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl FacilitatorClient {
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url,
            api_key,
        }
    }

    /// Call the /verify endpoint to validate a payment without settling
    pub async fn verify(
        &self,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> Result<VerifyResponse> {
        let url = format!("{}/verify", self.base_url);

        let request = VerifyRequest {
            x402_version: infra402_facilitator::types::X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        let mut req = self.client.post(&url).json(&request);

        if let Some(api_key) = &self.api_key {
            req = req.bearer_auth(api_key);
        }

        let response = req.send().await.context("Failed to send verify request")?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<could not read body>".to_string());
            anyhow::bail!("Verify request failed with status {}: {}", status, body);
        }

        let verify_response: VerifyResponse = response
            .json()
            .await
            .context("Failed to parse verify response")?;

        Ok(verify_response)
    }

    /// Call the /settle endpoint to execute a payment settlement
    pub async fn settle(
        &self,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> Result<SettleResponse> {
        let url = format!("{}/settle", self.base_url);

        let request = VerifyRequest {
            // SettleRequest is type alias for VerifyRequest
            x402_version: infra402_facilitator::types::X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        let mut req = self.client.post(&url).json(&request);

        if let Some(api_key) = &self.api_key {
            req = req.bearer_auth(api_key);
        }

        let response = req.send().await.context("Failed to send settle request")?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<could not read body>".to_string());
            anyhow::bail!("Settle request failed with status {}: {}", status, body);
        }

        let settle_response: SettleResponse = response
            .json()
            .await
            .context("Failed to parse settle response")?;

        Ok(settle_response)
    }

    /// Call the /verify endpoint with v2 protocol types
    pub async fn verify_v2(
        &self,
        payment_payload: PaymentPayloadV2<ExactPaymentPayload>,
        payment_requirements: PaymentRequirementsV2<ExactSchemePayload>,
    ) -> Result<VerifyResponse> {
        let url = format!("{}/verify", self.base_url);

        let request = VerifyRequestV2 {
            x402_version: X402Version2,
            payment_payload,
            payment_requirements,
        };

        let mut req = self.client.post(&url).json(&request);

        if let Some(api_key) = &self.api_key {
            req = req.bearer_auth(api_key);
        }

        let response = req.send().await.context("Failed to send verify request")?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<could not read body>".to_string());
            anyhow::bail!("Verify request failed with status {}: {}", status, body);
        }

        let verify_response: VerifyResponse = response
            .json()
            .await
            .context("Failed to parse verify response")?;

        Ok(verify_response)
    }

    /// Call the /settle endpoint with v2 protocol types
    pub async fn settle_v2(
        &self,
        payment_payload: PaymentPayloadV2<ExactPaymentPayload>,
        payment_requirements: PaymentRequirementsV2<ExactSchemePayload>,
    ) -> Result<SettleResponse> {
        let url = format!("{}/settle", self.base_url);

        let request = VerifyRequestV2 {
            x402_version: X402Version2,
            payment_payload,
            payment_requirements,
        };

        let mut req = self.client.post(&url).json(&request);

        if let Some(api_key) = &self.api_key {
            req = req.bearer_auth(api_key);
        }

        let response = req.send().await.context("Failed to send settle request")?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<could not read body>".to_string());
            anyhow::bail!("Settle request failed with status {}: {}", status, body);
        }

        let settle_response: SettleResponse = response
            .json()
            .await
            .context("Failed to parse settle response")?;

        Ok(settle_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = FacilitatorClient::new(
            "http://localhost:3000".to_string(),
            Some("test-key".to_string()),
        );
        assert_eq!(client.base_url, "http://localhost:3000");
        assert_eq!(client.api_key, Some("test-key".to_string()));
    }
}
