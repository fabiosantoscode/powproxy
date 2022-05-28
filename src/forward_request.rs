#[allow(unused)]
use core::str::FromStr;

use hyper::{Body, Request, Response, Client};
use hyper::http::Uri;

pub async fn forward_request(mut req: Request<Body>) -> Option<Response<Body>> {
    req.headers_mut().remove("host");
    *req.uri_mut() = get_upstream_url(req.uri().clone());

    Client::new().request(req).await.ok()
}

fn get_upstream_url(old_uri: Uri) -> Uri {
    let old_path = old_uri.path_and_query().unwrap().as_str();

    Uri::builder()
        .scheme("http")
        .authority("127.0.0.1:8080")
        .path_and_query(old_path)
        .build()
        .unwrap()
}

#[test]
fn test_change_url() {
    assert_eq!(
        get_upstream_url(FromStr::from_str("https://example.com/path?query").unwrap())
            .to_string(),
        String::from("http://127.0.0.1:8080/path?query")
    );
    assert_eq!(
        get_upstream_url(FromStr::from_str("https://example.com/path?query").unwrap())
            .to_string(),
        String::from("http://127.0.0.1:8080/path?query")
    );
}
