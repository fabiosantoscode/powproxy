# powproxy

Experimental reverse proxy that demands proof-of-work (in the form of an HTML file with a script tag that computes hashes) before it lets a request through.

The purpose is to deter DOS attacks by making them computationally expensive.

## How to run

 - Start your server on localhost:8080. Requests that pass the challenge will be proxied there.
 - Start `cargo run`, which will bind to localhost:3000
 - Visit localhost:3000. The challenge page is blank but after a second or two, the challenge is solved by your browser and you can go through.

## Roadmap

 - Only demand proof-of-work if enough requests per second are coming in
 - Research if it's possible to cheaply rate-limit requests after they're through the proxy
