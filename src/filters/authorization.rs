//! Authorization Filters
//!
//! This module provides header filter for a couple of commonly used
//! HTTP authenticationn schemes, such as `Basic` and `Bearer`. The filters
//! all extract a scheme specific data structure if an Authorization header
//! is found and has the proper scheme. Otherwise they reject.
//!
//! TODO Rejection should be a 401 with the additional challange properties
//! such as realm.
//!
//! ## Bearer token usage
//!
//! ```
//! let route = warp::path("protected").
//!     and(warp::authorization::bearer())
//!     .map(|token: warp::authorization::BearerToken| {
//!          format!("Your token is: {}", token.0)
//!     });
//!
//! ```
use http::header::HeaderValue;

use ::filter::{Filter, One};
use ::reject::Rejection;
use super::header;
use base64;

/// Represents the Authorization header credentials part of the `Basic` authentication
/// scheme as defined in RFC 2617 (https://tools.ietf.org/html/rfc2617#section-2)
#[derive(Debug)]
pub struct BasicCredentials {
    /// The authenticating user
    pub user: String,
    /// The credentials supplied
    pub password: String,
}

/// Creates a `Filter` that requires an Authorization header with `Basic` scheme.
///
/// If found, extracts and base64 decodes the Basic credentials otherwise rejects.
pub fn basic() -> impl Filter<Extract=One<BasicCredentials>, Error=Rejection> + Copy
{
    header::value(&::http::header::AUTHORIZATION, move |val| {
        // TODO: This is a first shot at splitting and isn't proper yet.
        parse("Basic", val).and_then(|s: String| {
            match base64::decode(s.as_bytes()) {
                Ok(ref d) => {
                    let mut split_n = d.splitn(2, |b| *b == b':');
                    let u = split_n.next();
                    let p = split_n.next();
                    u.and_then( |u| {
                        println!("U {:?}",u);
                        p.map( |p| BasicCredentials { user: String::from_utf8_lossy(u).into(), password: String::from_utf8_lossy(p).into() })
                    })
                },
                _ => None
            }
        })
    })

}

/// Represents the credentials part of the `Bearer` token authenticationn scheme as
/// defined in RFC 6750 (https://tools.ietf.org/html/rfc6750#section-2.1)
#[derive(Debug)]
pub struct BearerToken(pub String);

/// Creates a `Filter` that requires an Authorization header with `Bearer` scheme.
///
/// If found, extracts the bearer token, otherwise rejects.
pub fn bearer() -> impl Filter<Extract=One<BearerToken>, Error=Rejection> + Copy
{
    header::value(&::http::header::AUTHORIZATION, move |val| {
        parse("Bearer",val).map(|s: String| {
            BearerToken(s)
        })
    })

}

// Returns credentials part of header value if scheme matches the
// desired scheme.
fn parse(scheme: &'static str, value: &HeaderValue) -> Option<String> {
        value
        .to_str()
        .ok()
        .and_then(|val| {
            let mut parts = val.split_whitespace();
            parts.next().and_then(|s| {
                if s == scheme {
                    println!("MATCH {}",s);
                    Some(())
                } else {
                    None
                }
            }).and_then(|_| {
                parts.next()
            }).map(|z: &str| String::from(z))
        })
}

