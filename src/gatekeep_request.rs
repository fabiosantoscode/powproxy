use std::time::Duration;
use std::convert::TryFrom;

use cookie::Cookie;
use hyper::{Body, Request, Response};
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(unused)]
use crate::encryption::{hmac_sign, hmac_verify};
use crate::forward_request::{forward_request};
use crate::pow::{validate_work};
use crate::constants;
use crate::config::Config;

pub async fn gatekeep_request(req: Request<Body>, remote_addr_hash: u64, config: std::sync::Arc<Config>) -> Result<Response<Body>, hyper::http::Error> {
    let can_pass = req.headers().get("cookie")
        .map(|h| h.to_str().unwrap_or_else(|_| ""))
        .and_then(|cookie| validate_cookie(cookie, remote_addr_hash, &config));

    let res = match can_pass {
        Some(()) => forward_request(req).await,
        None => get_challenge_page(remote_addr_hash, &config)
    };

    match res {
        Some(response) => Ok(response),
        _ => Response::builder().status(503).body("Error!\n".into())
    }
}

fn serialize_challenge(expiry: SystemTime, remote_addr_hash: u64, config: &Config) -> Option<String> {
    let epoch_seconds = expiry.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let message = vec![epoch_seconds.to_be_bytes(), remote_addr_hash.to_be_bytes()].concat();
    Some(hex::encode(hmac_sign(&message, config)))
}

fn deserialize_challenge(hex: &str, config: &Config) -> Option<(SystemTime, u64)> {
    let bytes = hex::decode(hex).ok()?;
    let bytes = hmac_verify(&bytes, config)?;
    let time_part = <[u8; 8]>::try_from(&bytes[0..8]).ok()?;
    let remote_addr_part = <[u8; 8]>::try_from(&bytes[8..]).ok()?;

    let time = UNIX_EPOCH + Duration::from_secs(u64::from_be_bytes(time_part));

    Some((time, u64::from_be_bytes(remote_addr_part)))
}

/** Round the time such that there's only one challenge every 30 seconds */
fn round_time() -> SystemTime {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let more_than_30 = seconds % 30;
    UNIX_EPOCH + Duration::from_secs(seconds - more_than_30)
}

fn get_challenge_page(remote_addr_hash: u64, config: &Config) -> Option<Response<Body>> {
    let expiry = round_time() + Duration::from_secs(config.expiry_seconds);
    let challenge_str = serialize_challenge(expiry, remote_addr_hash, config)?;

    Response::builder()
        .header("set-cookie", format!("{}{}; Path=/; Max-Age=300; SameSite=Strict", "pow_chal=", challenge_str))
        .body(constants::CHALLENGE_PAGE.into())
        .ok()
}

fn validate_cookie(cookies: &str, remote_addr_hash: u64, config: &Config) -> Option<()> {
    let chal = get_cookie(cookies, "pow_resp=")?;
    let pow_magic = get_cookie(cookies, "pow_magic=")?.parse::<u32>().ok()?;

    let (given_expiry, given_remote_addr) = deserialize_challenge(&chal, config)?;

    if
        given_remote_addr == remote_addr_hash
        && given_expiry > SystemTime::now()
        && validate_work(&hex::decode(&chal).ok()?, pow_magic, config.difficulty_bytes)
    {
        Some(())
    } else {
        None
    }
}

fn get_cookie(cookie_header: &str, cookie_eq: &str) -> Option<String> {
    let mut split_iter = cookie_header.split("; ").into_iter();

    let cookie = split_iter.find(|cookie| {
        if cookie.len() > cookie_eq.len() {
            &cookie[0..cookie_eq.len()] == cookie_eq
        } else {
            false
        }
    })?;

    let cookie = Cookie::parse_encoded(cookie).ok()?;
    Some(cookie.value().into())
}

#[test]
fn test_get_cookie() {
    let cookie = get_cookie("hello=world; HttpOnly", "hello=");
    assert_eq!(cookie, Some(String::from("world")));

    let cookie = get_cookie("other=cookie; hello=world; HttpOnly", "hello=");
    assert_eq!(cookie, Some(String::from("world")));

    let missing = get_cookie("hello=world; other=cookie", "missing_cookie=");
    assert_eq!(missing, None);
}

#[test]
fn test_deserialize_challenge() {
    let instant = round_time();
    let config: Config = Default::default();

    let serialized = serialize_challenge(instant, 2, &config).unwrap();
    assert_eq!(deserialize_challenge(&serialized, &config), Some((instant, 2)));
}

#[test]
fn test_get_challenge_page() {
    let config: Config = Default::default();

    let get_page = || {
        let page = get_challenge_page(10, &config).unwrap();
        let page = page.headers().get("set-cookie").unwrap();
        String::from(page.to_str().unwrap())
    };

    assert_eq!(get_page().len() > 60, true);

    assert_eq!(
        // Just in case we go over a timestamp slice while comparing
        get_page() == get_page() || get_page() == get_page(),
        true
    );
}
