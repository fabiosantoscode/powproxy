extern crate atoi;
extern crate bitvec;
extern crate hex;
extern crate hyper;
extern crate ring;
extern crate sha2;
extern crate siphasher;
extern crate tokio;

mod config;
mod constants;
mod cookie_parse;
mod cookie_verify;
mod encryption;
mod gatekeep_request;
mod pow;
mod util;

use crate::gatekeep_request::gatekeep_request;

use std::collections::hash_map::DefaultHasher;
use std::convert::Infallible;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;

use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;

#[tokio::main]
async fn main() {
    let config: std::sync::Arc<config::Config> = Default::default();

    // A `Service` is needed for every connection, so this
    // creates one from our `gatekeep_request` function.
    let make_svc = make_service_fn(|socket: &AddrStream| {
        let config_clone = config.clone();

        // service_fn converts our function into a `Service`
        let remote_addr = hash_remote_addr(socket);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                gatekeep_request(req, remote_addr, config_clone.clone())
            }))
        }
    });

    // We'll bind to 0.0.0.0:3000
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let server = Server::bind(&addr).serve(make_svc);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

fn hash_remote_addr(socket: &AddrStream) -> u64 {
    let mut hasher = DefaultHasher::new();
    socket.remote_addr().ip().hash(&mut hasher);
    hasher.finish()
}
