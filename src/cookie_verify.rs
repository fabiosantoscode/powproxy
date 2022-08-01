use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::cookie_parse::parse_cookies;
use crate::encryption::{hmac_sign, hmac_verify};
use crate::pow::validate_work;
use crate::util::{quick_be_u64, round_time};

pub fn parse_and_verify_cookie(
    cookie_source: &[u8],
    correct_remote_addr_hash: u64,
    config: &Config,
) -> Option<bool> {
    let (hex_challenge, challenge_answer) = parse_cookies(cookie_source)?;
    let signed_challenge = hex::decode(hex_challenge).ok()?;

    let (expiry, remote_addr_hash) = {
        let chal = hmac_verify(&signed_challenge, config)?;

        let expiry = quick_be_u64(&chal[0..8])?;
        let expiry = UNIX_EPOCH + Duration::from_secs(expiry);

        let remote_addr_hash = quick_be_u64(&chal[8..])?;

        (expiry, remote_addr_hash)
    };

    let is_valid = correct_remote_addr_hash == remote_addr_hash
        && expiry >= SystemTime::now()
        && validate_work(&signed_challenge, challenge_answer, config.difficulty_bytes);

    Some(is_valid)
}

pub fn generate_challenge_cookie(remote_addr_hash: u64, config: &Config) -> Option<String> {
    let expiry = round_time() + Duration::from_secs(config.expiry_seconds);
    let epoch_seconds: u64 = expiry.duration_since(UNIX_EPOCH).ok()?.as_secs();

    let message = vec![epoch_seconds.to_be_bytes(), remote_addr_hash.to_be_bytes()].concat();
    Some(hex::encode(hmac_sign(&message, config)))
}

#[allow(unused)]
fn rust_work_1_byte(challenge: &str) -> Option<u32> {
    use sha2::{Digest, Sha256};

    for magic in 0_u32.. {
        let mut hasher = Sha256::new();
        hasher.update(
            [
                &magic.to_be_bytes(),
                hex::decode(challenge.as_bytes()).unwrap().as_slice(),
            ]
            .concat(),
        );
        let hash = hasher.finalize();

        if hash[0] == 0 {
            return Some(magic);
        }
    }

    unreachable!();
}

#[test]
fn test_parse_and_verify_cookie() {
    let config: Config = Config {
        difficulty_bytes: 1,
        ..Default::default()
    };

    let serialized = generate_challenge_cookie(2, &config).unwrap();

    let magic = rust_work_1_byte(&serialized).unwrap();
    let cookie = format!("pow_cchal={}; pow_magic={}", &serialized, magic);

    assert_eq!(
        parse_and_verify_cookie(cookie.as_bytes(), 2, &config),
        Some(true)
    );

    assert_eq!(
        parse_and_verify_cookie(cookie.as_bytes(), 1, &config),
        Some(false)
    );

    let cookie = format!("pow_cchal={}; pow_magic={}", &serialized, magic + 1);

    assert_eq!(
        parse_and_verify_cookie(cookie.as_bytes(), 2, &config),
        Some(false)
    );
}
