pub enum WhMode {
    Sk,
    Iv,
}

impl WhMode {
    pub fn from_str(mode: &str) -> Result<Self, String> {
        match mode {
            "sk" => Ok(Self::Sk),
            "iv" => Ok(Self::Iv),
            _ => Err(String::from("Invalid webhook key mode")),
        }
    }
}

pub struct WebhookKey {
    pub r#type: String,
    pub mode: WhMode,
    pub key: String,
}

impl WebhookKey {
    pub fn new(key: &str) -> Result<Self, String> {
        let splited: Vec<&str> = key.split("_").collect();
        if splited.len() != 3 {
            return Err(String::from("Invalid key"));
        }

        let key_type = splited.get(0).unwrap().to_string();
        if key_type != "wh" {
            return Err(String::from("Invalid webhook key"));
        }

        let mode_str = splited.get(1).unwrap().to_string();
        let mode = WhMode::from_str(&mode_str)?;
        let actual = splited.get(2).unwrap().to_string();
        Ok(Self {
            r#type: key_type,
            key: actual,
            mode,
        })
    }
}
