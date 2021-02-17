//! Auth Filters
use std::sync::Arc;

use headers::{authorization::Basic, authorization::Bearer};

use crate::{Filter, Rejection, Reply, filter::WrapSealed, reject::CombineRejection};
use internal::AuthFilter;

/// Wrap routes with basic authentication
pub fn basic<A: Authorizer+'static>(realm: &'static str, authorizer: A) -> Authed {
    auth("Basic", realm, authorizer)
}

/// Wrap routes with bearer authentication
pub fn bearer<A: Authorizer+'static>(realm: &'static str, authorizer: A) -> Authed {
    auth("Bearer", realm, authorizer)
}

/// Authentication middleware
pub fn auth<A: Authorizer+'static>(scheme: &'static str, realm: &'static str, authorizer: A) -> Authed {
    Authed {
        scheme,
        realm,
        authorizer: Arc::new(authorizer),
    }
}

impl<F> WrapSealed<F> for Authed
where
    F: Filter + Clone + Send + Sync + 'static,
    F::Extract: Reply,
    F::Error: CombineRejection<Rejection>,
    <F::Error as CombineRejection<Rejection>>::One: CombineRejection<Rejection>,
{
    type Wrapped = AuthFilter<F>;

    fn wrap(&self, inner: F) -> Self::Wrapped {
        

        AuthFilter { inner, authorizer: self.authorizer.clone(), scheme: self.scheme, realm: self.realm }
    }
}

/// Authentication middleware
pub struct Authed {
    scheme: &'static str,
    realm: &'static str,
    authorizer: Arc<dyn Authorizer>,
}

impl std::fmt::Debug for Authed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Authed")
            .finish()
    }
}

/// Authentication Challenge Rejection
#[derive(Debug)]
pub struct Challenge {
    /// Authentication scheme
    ///
    /// Currently Supported
    /// - Basic
    /// - Bearer
    pub scheme: &'static str,
    /// Authentication realm, this value will be provided
    /// in the WWW-Authenticate header
    pub realm: &'static str,
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} Challenge for realm {}", self.scheme, self.realm)
    }
}

/// A trait that defines user authorization
pub trait Authorizer: Send + Sync {
    /// Authorize this request's bearer token
    fn bearer(&self, _cred: &Bearer) -> Result<(), ()> {
        Err(())
    }
    /// Authorize this request's basic credentials
    fn basic(&self, _cred: &Basic) -> Result<(), ()> {
        Err(())
    }
}

mod internal {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use futures::{future, ready, TryFuture};
    use headers::{Authorization, HeaderValue, authorization::{Basic, Bearer}};
    use pin_project::pin_project;

    use crate::filter::{Filter, FilterBase, Internal, One};
    use crate::reject::{CombineRejection, Rejection};
    use crate::route;

    use super::Authorizer;

    #[derive(Clone)]
    pub struct AuthFilter<F> {
        pub(super) authorizer: Arc<dyn Authorizer>,
        pub(super) scheme: &'static str,
        pub(super) realm: &'static str,
        pub(super) inner: F,
    }
    impl<F> std::fmt::Debug for AuthFilter<F> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("AuthFilter")
                .field("scheme", &self.scheme)
                .field("realm", &self.realm)
                .finish()
        }
    }
    impl<F> FilterBase for AuthFilter<F>
    where
        F: Filter,
        F::Extract: Send,
        F::Future: Future,
        F::Error: CombineRejection<Rejection>,
    {
        type Extract = One<Wrapped<F::Extract>>;
        type Error = <F::Error as CombineRejection<Rejection>>::One;
        type Future = future::Either<future::Ready<Result<Self::Extract, Self::Error>>, WrappedFuture<F::Future>>;

        fn filter(&self, _: Internal) -> Self::Future {
            use headers::HeaderMapExt;
            let validated = route::with(|route| {
                    let hv = route.headers().get(http::header::AUTHORIZATION).cloned();
                    if let Ok(Some(header)) = route.headers().typed_try_get::<Authorization<Basic>>() {
                        Some((self.authorizer.basic(&header.0), hv))
                    } else if let Ok(Some(header)) = route.headers().typed_try_get::<Authorization<Bearer>>() {
                        Some((self.authorizer.bearer(&header.0), hv))
                    } else {
                        None
                    }
                });
            match validated {
                Some((Ok(_), auth)) => {
                    let wrapped = WrappedFuture {
                        inner: self.inner.filter(Internal),
                        wrapped: (self.authorizer.clone(), auth.unwrap().clone())
                    };
                    future::Either::Right(wrapped)
                },
                Some((Err(_), _)) => {
                    let rejection = crate::reject::forbidden();
                    future::Either::Left(future::err(rejection.into()))
                }
                None => {
                    let rejection = crate::reject::unauthorized_challenge(self.scheme, self.realm);
                    future::Either::Left(future::err(rejection.into()))
                }
            }
        }
    }
    pub struct Wrapped<R> {
        authorizer: Arc<dyn Authorizer>,
        inner: R,
        header: HeaderValue,
    }

    impl<F> std::fmt::Debug for Wrapped<F> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("Wrapped")
                .field("header", &self.header)
                .finish()
        }
    }

    impl<R> crate::reply::Reply for Wrapped<R>
    where
        R: crate::reply::Reply,
    {
        fn into_response(self) -> crate::reply::Response {
            self.inner.into_response()
        }
    }

    #[pin_project]
    pub struct WrappedFuture<F> {
        #[pin]
        inner: F,
        wrapped: (Arc<dyn Authorizer>, HeaderValue),
    }

    impl<F> std::fmt::Debug for WrappedFuture<F> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("WrappedFuture")
                .field("header", &self.wrapped.1)
                .finish()
        }
    }

    impl<F> Future for WrappedFuture<F>
    where
        F: TryFuture,
        F::Error: CombineRejection<Rejection>, 
    {
        type Output = Result<
            One<Wrapped<F::Ok>>,
            <F::Error as CombineRejection<Rejection>>::One,
        >;
        
        

        fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
            let pin = self.project();
            match ready!(pin.inner.try_poll(cx)) {
                Ok(inner) => {
                    let (authorizer, header) = pin.wrapped;
                    let item = (Wrapped {
                        authorizer: authorizer.clone(),
                        inner,
                        header: header.clone(),
                    },);
                    
                    Poll::Ready(Ok(item))
                }
                Err(err) => Poll::Ready(Err(err.into())),
            }
        }
    }
}