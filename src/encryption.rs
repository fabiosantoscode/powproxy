use std::sync::Once;

use ring::{hmac, rand};

static INIT_AES_ONCE: Once = Once::new();
static HMAC_ALGO: hmac::Algorithm = hmac::HMAC_SHA256;
static mut HMAC_KEY: Option<hmac::Key> = None;

// Can't be determined at compile-time but asserted in prepare_encryption below
static HMAC_LENGTH: usize = 32;

pub fn hmac_sign(msg: &[u8]) -> Vec<u8> {
    let key = get_hmac_key();

    vec![hmac::sign(&key, msg).as_ref(), msg].concat()
}

pub fn hmac_verify(signed_msg: &[u8]) -> Option<Vec<u8>> {
    let key = get_hmac_key();
    let tag = &signed_msg[0..HMAC_LENGTH];
    let msg = &signed_msg[HMAC_LENGTH..];

    hmac::verify(&key, msg, tag).ok()?;
    Some(Vec::from(msg))
}

/** Internally unsafe. Call this before any calls to this module */
pub fn prepare_encryption() {
    INIT_AES_ONCE.call_once(|| {
        // Can't ensure this at the static level because of the function call
        assert_eq!(HMAC_ALGO.digest_algorithm().output_len, HMAC_LENGTH);

        unsafe {
            let rng = rand::SystemRandom::new();
            HMAC_KEY = Some(hmac::Key::generate(HMAC_ALGO, &rng).unwrap())
        }
    })
}

fn get_hmac_key() -> hmac::Key {
    unsafe {
        HMAC_KEY.clone().unwrap()
    }
}

#[test]
fn test_can_sign() {
    prepare_encryption();

    let msg = "hello, world";
    let signed = hmac_sign(msg.as_bytes());

    hmac_verify(&signed).unwrap();

    assert_eq!(hmac_sign(msg.as_bytes()), hmac_sign(msg.as_bytes()));
}
