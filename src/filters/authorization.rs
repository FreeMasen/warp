//! Authorization Filters
//!
//! This module provides header filter for a couple of commonly used
//! HTTP authentication schemes, such as `Basic` and `Bearer`. The filters
//! all extract a scheme specific data structure if an Authorization header
//! is found and has the proper scheme. Otherwise they reject.
//!
//! TODO Rejection should be a 401 with the additional challenge properties
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

use std::{convert::Infallible, future};

use headers::{Authorization, authorization::{Basic, Bearer}};

use crate::filter::{Filter, One};
use super::header;
use crate::reject::Rejection;

/// Creates a `Filter` that requires an Authorization header with `Basic` scheme.
///
/// If found, extracts and base64 decodes the Basic credentials otherwise rejects.
pub fn basic(realm: &'static str) -> impl Filter<Extract=One<Basic>, Error=Rejection> + Copy
{
    header::header2().and_then(move |auth: Authorization<Basic>| {
        future::ready(Result::<_, Infallible>::Ok(auth.0))
    })
    .or_else(move |_| {
        future::ready(Err(crate::reject::unauthorized("Basic", realm)))
    })

}

/// Creates a `Filter` that requires an Authorization header with `Bearer` scheme.
///
/// If found, extracts the bearer token, otherwise rejects.
pub fn bearer(realm: &'static str) -> impl Filter<Extract=One<Bearer>, Error=Rejection> + Copy {
    header::header2().and_then(move |auth: Authorization<Bearer>| {
        future::ready(Result::<_, Infallible>::Ok(auth.0))
    })
    .or_else(move |_| {
        future::ready(Err(crate::reject::unauthorized("Bearer", realm)))
    })
}
