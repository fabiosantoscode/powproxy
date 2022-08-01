use std::sync::Arc;

use hyper::http::Uri;
use hyper::{Body, Client, Request, Response};

use crate::config::Config;
use crate::constants;
use crate::cookie_verify::{generate_challenge_cookie, parse_and_verify_cookie};

type HttpResult = Result<Response<Body>, hyper::http::Error>;

pub async fn gatekeep_request(req: Request<Body>, ip_hash: u64, config: Arc<Config>) -> HttpResult {
    let can_pass = req.headers().get("cookie").and_then(|header| {
        if header.len() > constants::MAX_COOKIE_HEADER_SIZE {
            None
        } else {
            parse_and_verify_cookie(header.as_bytes(), ip_hash, &config)
        }
    });

    let res = match can_pass {
        Some(true) => forward_request(req).await,
        _ => get_challenge_page(ip_hash, &config),
    };

    match res {
        Some(response) => Ok(response),
        _ => Response::builder().status(503).body("Error!\n".into()),
    }
}

pub async fn forward_request(mut req: Request<Body>) -> Option<Response<Body>> {
    req.headers_mut().remove("host");
    *req.uri_mut() = get_upstream_url(&req.uri())?;

    Client::new().request(req).await.ok()
}

fn get_upstream_url(old_uri: &Uri) -> Option<Uri> {
    let old_path = old_uri.path_and_query()?.as_str();

    make_url("127.0.0.1:8080", old_path)
}

fn make_url(authority: &str, path_and_query: &str) -> Option<Uri> {
    Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .ok()
}

fn get_challenge_page(remote_addr_hash: u64, config: &Config) -> Option<Response<Body>> {
    let challenge_str = generate_challenge_cookie(remote_addr_hash, config)?;

    Response::builder()
        .header(
            "set-cookie",
            format!(
                "pow_chal={}; Path=/; Max-Age={}; SameSite=Strict",
                challenge_str, config.expiry_seconds,
            ),
        )
        .body(constants::CHALLENGE_PAGE.into())
        .ok()
}

#[test]
fn test_get_challenge_page() {
    let config: Config = Default::default();

    let get_page_cookie = || {
        let page = get_challenge_page(10, &config).unwrap();
        let page = page.headers().get("set-cookie").unwrap();
        String::from(page.to_str().unwrap())
    };

    assert_eq!(get_page_cookie().len() > 60, true);

    assert_eq!(
        // Just in case we go over a timestamp slice while comparing
        get_page_cookie() == get_page_cookie() || get_page_cookie() == get_page_cookie(),
        true
    );
}

#[test]
fn test_change_url() {
    assert_eq!(
        get_upstream_url(&make_url("example.com", "path?query").unwrap()),
        make_url("127.0.0.1:8080", "path?query")
    );
}
