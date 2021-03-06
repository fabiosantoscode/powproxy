use std::time::Duration;
use std::convert::TryFrom;

use cookie::Cookie;
use hyper::{Body, Request, Response};
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(unused)]
use crate::encryption::{hmac_sign, hmac_verify, prepare_encryption};
use crate::forward_request::{forward_request};
use crate::pow::{validate_work};
use crate::constants;

pub async fn gatekeep_request(req: Request<Body>, remote_addr_hash: u64) -> Result<Response<Body>, hyper::http::Error> {
    let can_pass = req.headers().get("cookie")
        .map(|h| h.to_str().unwrap_or_else(|_| ""))
        .and_then(|cookie| validate_cookie(cookie, remote_addr_hash));

    let res = match can_pass {
        Some(_) => forward_request(req).await,
        _ => get_challenge_page(remote_addr_hash)
    };

    match res {
        Some(response) => Ok(response),
        _ => Response::builder().status(503).body("Error!\n".into())
    }
}

fn serialize_challenge(expiry: SystemTime, remote_addr_hash: u64) -> Option<String> {
    let epoch_seconds = expiry.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let message = vec![epoch_seconds.to_be_bytes(), remote_addr_hash.to_be_bytes()].concat();
    Some(hex::encode(hmac_sign(&message)))
}

fn deserialize_challenge(hex: &str) -> Option<(SystemTime, u64)> {
    let bytes = hex::decode(hex).ok()?;
    let bytes = hmac_verify(&bytes)?;
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

fn get_challenge_page(remote_addr_hash: u64) -> Option<Response<Body>> {
    let expiry = round_time() + Duration::from_secs(constants::EXPIRY_SECONDS);
    let challenge_str = serialize_challenge(expiry, remote_addr_hash)?;

    Response::builder()
        .header("set-cookie", format!("{}{}; Path=/; Max-Age=300; SameSite=Strict", "pow_chal=", challenge_str))
        .body(constants::CHALLENGE_PAGE.into())
        .ok()
}

fn validate_cookie(cookies: &str, remote_addr_hash: u64) -> Option<()> {
    let chal = get_cookie(cookies, "pow_resp=")?;
    let pow_magic = get_cookie(cookies, "pow_magic=")?.parse::<u32>().ok()?;

    let (given_expiry, given_remote_addr) = deserialize_challenge(&chal)?;

    if
        given_remote_addr == remote_addr_hash
        && given_expiry > SystemTime::now()
        && validate_work(&hex::decode(&chal).ok()?, pow_magic, constants::DIFFICULTY_BITS)
    {
        Some(())
    } else {
        None
    }
}

fn get_cookie(cookies: &str, cookie_eq: &str) -> Option<String> {
    let cookie = cookies.split("; ").into_iter().find(|cookie| &cookie[0..cookie_eq.len()] == cookie_eq)?;
    let cookie = Cookie::parse_encoded(cookie).ok()?;
    Some(cookie.value().into())
}

#[test]
fn test_deserialize_challenge() {
    prepare_encryption();

    let instant = round_time();
    
    let serialized = serialize_challenge(instant, 2).unwrap();
    assert_eq!(deserialize_challenge(&serialized), Some((instant, 2)));
}