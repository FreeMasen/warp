#![deny(warnings)]
extern crate warp;
extern crate headers_ext;

use warp::Filter;

fn main() {
    // require Basic authentication
    let routes = warp::any()
        .and(warp::authorization::basic("my-realm"))
        .map(|credentials: headers_ext::Basic| format!("Hello, {}!",
                                                       credentials.username()));

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030));
}