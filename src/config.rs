use crate::encryption::hmac_gen_key;
use ring::hmac::Key;

#[derive(Clone)]
pub struct Config {
    pub difficulty_bytes: usize,
    pub expiry_seconds: u64,
    pub hmac_key: Key,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            difficulty_bytes: 2,
            expiry_seconds: 300,
            hmac_key: hmac_gen_key(),
        }
    }
}
