use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};

use base64::prelude::*;
use rand::{rngs::OsRng, RngCore};
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
    pub fn new() -> Self {
        let mut sk_byte: AesCbc256SK = [0; 32];
        let mut iv_byte: AesCbc256IV = [0; 16];

        let mut rng = OsRng::default();
        rng.fill_bytes(&mut sk_byte);
        rng.fill_bytes(&mut iv_byte);

        let mut sk = String::new();
        let mut iv = String::new();

        BASE64_STANDARD.encode_string(&sk_byte, &mut sk);
        BASE64_STANDARD.encode_string(&iv_byte, &mut iv);

        Self { sk, iv }
    }

    pub fn encrypt(&self, plain_text: &str) -> String {
        let sk_bytes = BASE64_STANDARD.decode(self.sk.as_bytes()).unwrap();
        let iv_bytes = BASE64_STANDARD.decode(self.iv.as_bytes()).unwrap();
        let key = GenericArray::from_slice(sk_bytes.as_slice());
        let iv = GenericArray::from_slice(iv_bytes.as_slice());

        let pt_len = plain_text.len();
        let mut buf = [0u8; 8192];
        buf[..pt_len].copy_from_slice(plain_text.as_bytes());
        let ct = Aes256CbcEnc::new(&key, &iv)
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
            .unwrap();

        let mut encrypted_text = String::new();
        BASE64_STANDARD.encode_string(&ct, &mut encrypted_text);
        encrypted_text
    }

    pub fn decrypt(&self, encrypted_text: &str) -> String {
        let sk_bytes = BASE64_STANDARD.decode(self.sk.as_bytes()).unwrap();
        let iv_bytes = BASE64_STANDARD.decode(self.iv.as_bytes()).unwrap();
        let key = GenericArray::from_slice(sk_bytes.as_slice());
        let iv = GenericArray::from_slice(iv_bytes.as_slice());

        let mut bytes_vec = BASE64_STANDARD.decode(encrypted_text).unwrap();
        let bytes_slice: &mut [u8] = bytes_vec.as_mut_slice();

        let pt = Aes256CbcDec::new(&key, &iv)
            .decrypt_padded_mut::<Pkcs7>(bytes_slice)
            .unwrap();

        String::from_utf8_lossy(&pt).to_string()
    }
}
