use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};

use base64::prelude::*;
use rand::{rngs::OsRng, TryRngCore};
use serde::{Deserialize, Serialize};

pub type AesCbc256SK = [u8; 32];
pub type AesCbc256IV = [u8; 16];
pub type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
pub type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AesCbc256Key {
    pub sk: String,
    pub iv: String,
}

impl AesCbc256Key {
    pub fn new() -> Result<Self, String> {
        let mut sk_byte: AesCbc256SK = [0; 32];
        let mut iv_byte: AesCbc256IV = [0; 16];

        let mut rng = OsRng;
        rng.try_fill_bytes(&mut sk_byte)
            .map_err(|e| e.to_string())?;
        rng.try_fill_bytes(&mut iv_byte)
            .map_err(|e| e.to_string())?;

        let mut sk = String::new();
        let mut iv = String::new();

        BASE64_STANDARD.encode_string(sk_byte, &mut sk);
        BASE64_STANDARD.encode_string(iv_byte, &mut iv);

        Ok(Self { sk, iv })
    }

    pub fn encrypt(&self, plain_text: &str) -> Result<String, String> {
        let sk_bytes = BASE64_STANDARD
            .decode(self.sk.as_bytes())
            .map_err(|e| e.to_string())?;
        let iv_bytes = BASE64_STANDARD
            .decode(self.iv.as_bytes())
            .map_err(|e| e.to_string())?;
        let key = GenericArray::from_slice(sk_bytes.as_slice());
        let iv = GenericArray::from_slice(iv_bytes.as_slice());

        let pt_len = plain_text.len();
        let mut buf = [0u8; 8192];
        buf[..pt_len].copy_from_slice(plain_text.as_bytes());
        let ct = Aes256CbcEnc::new(key, iv)
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
            .map_err(|e| e.to_string())?;

        let mut encrypted_text = String::new();
        BASE64_STANDARD.encode_string(ct, &mut encrypted_text);
        Ok(encrypted_text)
    }

    pub fn decrypt(&self, encrypted_text: &str) -> Result<String, String> {
        let sk_bytes = BASE64_STANDARD
            .decode(self.sk.as_bytes())
            .map_err(|e| e.to_string())?;
        let iv_bytes = BASE64_STANDARD
            .decode(self.iv.as_bytes())
            .map_err(|e| e.to_string())?;
        let key = GenericArray::from_slice(sk_bytes.as_slice());
        let iv = GenericArray::from_slice(iv_bytes.as_slice());

        let mut bytes_vec = BASE64_STANDARD
            .decode(encrypted_text)
            .map_err(|e| e.to_string())?;
        let bytes_slice: &mut [u8] = bytes_vec.as_mut_slice();

        let pt = Aes256CbcDec::new(key, iv)
            .decrypt_padded_mut::<Pkcs7>(bytes_slice)
            .map_err(|e| e.to_string())?;

        Ok(String::from_utf8_lossy(pt).to_string())
    }
}
