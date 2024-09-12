use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntentPayload {
    pub amount: String,
    pub currency: String,
    pub order_id: String,
    pub tracking: Value,
    pub order_details: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntentDetail {
    pub _id: String,
    pub amount: String,
    pub currency: String,
    // pub items: Option<Vec<Value>>,
    // pub total_price: String,
    // pub total_discount: String,
    // pub grand_total: String,
    // pub order_date: String,
    // pub org_id: String,
    // pub customer_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Dev,
    Uat,
    Prod,
}

impl Mode {
    pub fn from_str(mode: &str) -> Result<Self, String> {
        match mode {
            "dev" => Ok(Self::Dev),
            "uat" => Ok(Self::Uat),
            "prod" => Ok(Self::Prod),
            _ => Err(String::from("Invalid mode")),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Pk,
    Sk,
}

impl KeyType {
    pub fn from_str(mode: &str) -> Result<Self, String> {
        match mode {
            "pk" => Ok(Self::Pk),
            "sk" => Ok(Self::Sk),
            _ => Err(String::from("Invalid key type")),
        }
    }
}
