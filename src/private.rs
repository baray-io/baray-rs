use reqwest::{header::HeaderMap, Client};
use serde_json::json;

use crate::{AesCbc256Key, IntentDetail, IntentPayload, Key, WebhookKey};

pub struct PrivateClient {
    pub api_key: String,
    pub secret_key: String,
    pub iv_key: String,
    pub wh_secret_key: String,
    pub wh_iv_key: String,
}

impl PrivateClient {
    pub fn new(
        public_key: String,
        secret_key: String,
        iv_key: String,
        wh_secret_key: String,
        wh_iv_key: String,
    ) -> Result<Self, String> {
        let pk = Key::new(&public_key)?;
        let sk = Key::new(&secret_key)?;
        let wh_sk = WebhookKey::new(&wh_secret_key)?;
        let wh_iv = WebhookKey::new(&wh_iv_key)?;

        match pk.r#type {
            crate::KeyType::Pk => {}
            crate::KeyType::Sk => {
                return Err(String::from(
                    "Invalid public key. A public key must start with pk_***",
                ));
            }
        }

        match sk.r#type {
            crate::KeyType::Pk => {
                return Err(String::from(
                    "Invalid private key. A secret key must start with sk_***",
                ));
            }
            crate::KeyType::Sk => {}
        }

        match wh_sk.mode {
            crate::WhMode::Sk => {}
            crate::WhMode::Iv => {
                return Err(String::from(
                    "Invalid webhook secret key. A webhook secret key must start with wh_sk_***",
                ));
            }
        }

        match wh_iv.mode {
            crate::WhMode::Sk => {
                return Err(String::from(
                    "Invalid webhook IV key. A webhook IV key must start with wh_iv_***",
                ));
            }
            crate::WhMode::Iv => {}
        }

        Ok(Self {
            api_key: pk.key,
            secret_key: sk.key,
            iv_key,
            wh_secret_key: wh_sk.key,
            wh_iv_key: wh_iv.key,
        })
    }

    pub fn encrypt(&self, plain_text: &str) -> String {
        let key = AesCbc256Key {
            sk: self.secret_key.to_string(),
            iv: self.iv_key.to_string(),
        };

        key.encrypt(plain_text)
    }

    pub fn decrypt(&self, encrypted_text: &str) -> String {
        let key = AesCbc256Key {
            sk: self.wh_secret_key.to_string(),
            iv: self.wh_iv_key.to_string(),
        };

        key.decrypt(encrypted_text)
    }

    pub async fn create_intent(&self, intent: IntentPayload) -> Result<IntentDetail, String> {
        let url = "https://api.baray.io/pay";
        let client = Client::new();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", self.api_key.parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());

        let plain_text = serde_json::to_string(&intent).map_err(|e| e.to_string())?;
        let encrypted_intent = self.encrypt(&plain_text);
        println!("plain_text {}", plain_text);
        println!("encrypted {}", encrypted_intent);

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

        let text = res.text().await.unwrap();
        println!("res text {}", &text);
        let data = serde_json::from_str::<IntentDetail>(&text).map_err(|e| e.to_string())?;

        Ok(data)
    }
}
