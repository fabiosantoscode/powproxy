use crate::config::Config;
use ring::{hmac, rand::SystemRandom};

static HMAC_ALGO: hmac::Algorithm = hmac::HMAC_SHA256;

// Can't be determined at compile-time but asserted in a test below
static HMAC_LENGTH: usize = 32;

pub fn hmac_sign(msg: &[u8], config: &Config) -> Vec<u8> {
    let sig = hmac::sign(&config.hmac_key, msg);

    vec![sig.as_ref(), msg].concat()
}

pub fn hmac_verify(signed_msg: &[u8], config: &Config) -> Option<Vec<u8>> {
    let tag = &signed_msg[0..HMAC_LENGTH];
    let msg = &signed_msg[HMAC_LENGTH..];

    hmac::verify(&config.hmac_key, msg, tag).ok()?;
    Some(Vec::from(msg))
}

pub fn hmac_gen_key() -> hmac::Key {
    let rng = SystemRandom::new();
    hmac::Key::generate(HMAC_ALGO, &rng).expect("generate random hmac key")
}

#[test]
fn test_hmac_algo_output_length() {
    assert_eq!(HMAC_ALGO.digest_algorithm().output_len, HMAC_LENGTH);
}

#[test]
fn test_can_sign() {
    let config: Config = Default::default();

    let msg = "hello, world";
    let signed = hmac_sign(msg.as_bytes(), &config);

    hmac_verify(&signed, &config).unwrap();

    // Ensure signature is stable
    assert_eq!(
        hmac_sign(msg.as_bytes(), &config),
        hmac_sign(msg.as_bytes(), &config)
    );
}
