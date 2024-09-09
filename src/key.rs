use crate::{KeyType, Mode};

pub struct Key {
    pub r#type: KeyType,
    pub mode: Mode,
    pub key: String,
}

impl Key {
    pub fn new(key: &str) -> Result<Self, String> {
        let splited: Vec<&str> = key.split("_").collect();
        if splited.len() != 3 {
            return Err(String::from("Invalid key"));
        }

        let key_type_str = splited.get(0).unwrap().to_string();
        let key_type = KeyType::from_str(&key_type_str)?;
        let mode_str = splited.get(1).unwrap().to_string();
        let mode = Mode::from_str(&mode_str)?;
        let actual = splited.get(2).unwrap().to_string();

        Ok(Self {
            r#type: key_type,
            key: actual,
            mode,
        })
    }
}
