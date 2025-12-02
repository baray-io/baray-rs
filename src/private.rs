use reqwest::{
    header::{HeaderMap, InvalidHeaderValue},
    Client,
};
use serde_json::json;

use crate::{AbaQrResponse, AesCbc256Key, IntentDetail, IntentPayload};

pub struct PrivateClient {
    pub api_key: String,
    pub secret_key: String,
    pub iv_key: String,
}

impl PrivateClient {
    pub fn new(api_key: String, secret_key: String, iv_key: String) -> Result<Self, String> {
        if !(api_key.starts_with("pk_dev_")
            || api_key.starts_with("pk_uat_")
            || api_key.starts_with("pk_prod_"))
        {
            return Err("Invalid API Key".to_string());
        }

        if secret_key.len() != 44 {
            return Err("Invalid secret Key".to_string());
        }

        if iv_key.len() != 24 {
            return Err("Invalid iv Key".to_string());
        }

        Ok(Self {
            api_key,
            secret_key,
            iv_key,
        })
    }

    pub fn encrypt(&self, plain_text: &str) -> Result<String, String> {
        let key = AesCbc256Key {
            sk: self.secret_key.to_string(),
            iv: self.iv_key.to_string(),
        };

        key.encrypt(plain_text)
    }

    pub fn decrypt(&self, encrypted_text: &str) -> Result<String, String> {
        let key = AesCbc256Key {
            sk: self.secret_key.to_string(),
            iv: self.iv_key.to_string(),
        };

        key.decrypt(encrypted_text)
    }

    pub async fn create_intent(&self, intent: IntentPayload) -> Result<IntentDetail, String> {
        let url = "https://api.baray.io/pay";
        let client = Client::new();
        let mut headers = HeaderMap::new();

        headers.insert(
            "x-api-key",
            self.api_key
                .parse()
                .map_err(|e: InvalidHeaderValue| e.to_string())?,
        );
        headers.insert(
            "Content-Type",
            "application/json"
                .parse()
                .map_err(|e: InvalidHeaderValue| e.to_string())?,
        );

        let plain_text = serde_json::to_string(&intent).map_err(|e| e.to_string())?;
        let encrypted_intent = self.encrypt(&plain_text)?;

        let body = json!({
            "data": encrypted_intent
        });

        let res = client
            .post(url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let text = res.text().await.map_err(|e| e.to_string())?;

        let data = serde_json::from_str::<IntentDetail>(&text).map_err(|e| e.to_string())?;

        Ok(data)
    }

    pub async fn create_aba_qr(&self, intent: IntentPayload) -> Result<AbaQrResponse, String> {
        let url = "https://api.baray.io/payments/aba/pay_qr";
        let client = Client::new();
        let mut headers = HeaderMap::new();

        headers.insert(
            "x-api-key",
            self.api_key
                .parse()
                .map_err(|e: InvalidHeaderValue| e.to_string())?,
        );
        headers.insert(
            "Content-Type",
            "application/json"
                .parse()
                .map_err(|e: InvalidHeaderValue| e.to_string())?,
        );

        let plain_text = serde_json::to_string(&intent).map_err(|e| e.to_string())?;
        let encrypted_intent = self.encrypt(&plain_text)?;

        let body = json!({
            "data": encrypted_intent
        });

        let res = client
            .post(url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let text = res.text().await.map_err(|e| e.to_string())?;

        let data = serde_json::from_str::<AbaQrResponse>(&text).map_err(|e| e.to_string())?;

        Ok(data)
    }
}
