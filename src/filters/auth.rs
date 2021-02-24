//! Auth Filters
use std::sync::Arc;

use futures::Future;
use headers::{Authorization, HeaderMap, HeaderMapExt, authorization::Basic, authorization::Bearer};

use crate::{Filter, Rejection, Reply, filter::WrapSealed, reject::CombineRejection};
use internal::AuthFilter;



/// Wrap routes with basic authentication
pub fn basic<F, A>(realm: &'static str, f: F) -> Authed<A> 
where F: Clone + 'static + Fn(AuthHeader) -> A + Send + Sync,
    A: Future<Output = Result<(), Rejection>> + Send + Sync, {
    auth("Basic", realm, f)
}

// /// Wrap routes with bearer authentication
// pub fn bearer<T: Future<Output = Result<(), ()>>, A: Authorizer<T> + 'static>(realm: &'static str, authorizer: A) -> Authed<T> {
//     auth("Bearer", realm, authorizer)
// }

/// Authentication middleware
pub fn auth<F, A>(
    scheme: &'static str,
    realm: &'static str,
    authorizer: F,
) -> Authed<A> 
where F: 'static + Fn(AuthHeader) -> A + Send + Sync,
A: Future<Output = Result<(), Rejection>> + Send + Sync, {
    let authorizer = Authorizer {
        scheme,
        realm,
        handler: Arc::new(authorizer)
    };
    Authed {
        scheme,
        realm,
        authorizer: authorizer,
    }
}

impl<F, A> WrapSealed<F> for Authed<A>
where
    F: Filter + Clone + Send + Sync + 'static,
    F::Extract: Reply + Send,
    F::Error: CombineRejection<Rejection>,
    <F::Error as CombineRejection<Rejection>>::One: CombineRejection<Rejection>,
    A: Future<Output = Result<(), Rejection>> + Clone + Send,
{
    type Wrapped = AuthFilter<F, A>;

    fn wrap(&self, inner: F) -> Self::Wrapped {
        AuthFilter {
            inner,
            authorizer: Arc::new(self.authorizer.clone()),
            scheme: self.scheme,
            realm: self.realm,
        }
    }
}

/// Authentication middleware
pub struct Authed<A> {
    scheme: &'static str,
    realm: &'static str,
    authorizer: Authorizer<A>,
}

impl<A> std::fmt::Debug for Authed<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Authed").finish()
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

/// Authorization handler
#[derive(Clone)]
pub struct Authorizer<A> {
    scheme: &'static str,
    realm: &'static str,
    handler: Arc<dyn Fn(AuthHeader) -> A + 'static + Send + Sync>,
}

impl<A> std::fmt::Debug for Authorizer<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Authorizer").field("scheme", &self.scheme)
            .field("realm", &self.realm)
            .finish()
    }
}

impl<A> Authorizer<A> 
where A: Future<Output = Result<(), Rejection>>, {
    
    fn handle_request(&self, header: AuthHeader) -> A {
        (self.handler)(header)
    }

    fn extract_header(&self, headers: &HeaderMap) -> Option<AuthHeader> {
        if let Ok(Some(header)) = headers.typed_try_get::<Authorization<Basic>>() {
            Some(AuthHeader::Basic(header.0))
        } else if let Ok(Some(header)) = headers.typed_try_get::<Authorization<Bearer>>() {
            Some(AuthHeader::Bearer(header.0))
        } else {
            None
        }
    }
}
/// Authorization Header's inner value
#[derive(Clone, PartialEq, Debug)]
pub enum AuthHeader {
    /// Basic Authentication header 
    Basic(Basic),
    /// Bearer Authentication header
    Bearer(Bearer),
}

mod internal {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use futures::{TryFuture, future, ready};
    
    use pin_project::pin_project;

    use crate::filter::{Filter, FilterBase, Internal, One};
    use crate::reject::{CombineRejection, Rejection};
    use crate::route;

    use super::{Authorizer, AuthHeader};

    #[derive(Clone)]
    pub struct AuthFilter<F, A> {
        pub(super) authorizer: Arc<Authorizer<A>>,
        pub(super) scheme: &'static str,
        pub(super) realm: &'static str,
        pub(super) inner: F,
    }
    impl<F, A> std::fmt::Debug for AuthFilter<F, A> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("AuthFilter")
                .field("scheme", &self.scheme)
                .field("realm", &self.realm)
                .finish()
        }
    }
    

    impl<F, A> FilterBase for AuthFilter<F, A>
    where
        F: Filter + Send,
        F::Extract: Send,
        F::Future: Future,
        F::Error: CombineRejection<Rejection>,
        A: Send + Sync + Future<Output = Result<(), Rejection>>,
    {
        type Extract =
            One<crate::generic::Either<One<WrappedPendingFuture<F::Extract, A>>, F::Extract>>;
        type Error = <F::Error as CombineRejection<Rejection>>::One;
        type Future = future::Either<
            future::Ready<Result<Self::Extract, Self::Error>>,
            WrappedPendingFuture<F, A>,
        >;

        fn filter(&self, _: Internal) -> Self::Future {
            let header = route::with(|route| {
                self.authorizer.extract_header(route.headers())
            });
            match header {
                Some(header) => {
                    future::Either::Right(
                    WrappedPendingFuture {
                        inner: self.inner,
                        auth: self.authorizer.handle_request(header),
                        wrapped: (self.authorizer.clone(), header),
                    })
                }
                None => {
                    let rejection = crate::reject::unauthorized_challenge(self.scheme, self.realm);
                    future::Either::Left(future::err(rejection.into()))
                }
            }
        }
    }
    pub struct Wrapped<F, A> {
        wrapped: (Arc<Authorizer<A>>, AuthHeader),
        inner: F,
    }

    impl<F, A> std::fmt::Debug for Wrapped<F, A> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("Wrapped")
                .finish()
        }
    }

    impl<R, A> crate::reply::Reply for Wrapped<R, A>
    where
        R: crate::reply::Reply,
    {
        fn into_response(self) -> crate::reply::Response {
            self.inner.into_response()
        }
    }

    #[pin_project]
    pub struct WrappedPendingFuture<F, A> {
        #[pin]
        inner: F,
        #[pin]
        auth: A,
        wrapped: (Arc<Authorizer<A>>, AuthHeader),
    }

    impl<F, A> std::fmt::Debug for WrappedPendingFuture<F, A> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("WrappedPendingFuture")
                .finish()
        }
    }

    impl<A, F> Future for WrappedPendingFuture<F, A>
    where
        F: Filter,
        F::Extract: Send,
        F::Future: Future,
        F::Error: CombineRejection<Rejection>,
        A: TryFuture,
        A::Error: CombineRejection<Rejection>,
    {
        type Output = Result<One<WrappedAuthedFuture<F::Future, A>>, <A::Error as CombineRejection<Rejection>>::One>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
            let pin = self.project();
            match ready!(pin.auth.try_poll(cx)) {
                Ok(_) => {
                    let (authorizer, header) = pin.wrapped;
                    let item = (WrappedAuthedFuture {
                        wrapped: (authorizer.clone(), header.clone()),
                        inner: pin.inner.filter(Internal),
                    },);
                    Poll::Ready(Ok(item))
                }
                Err(err) => Poll::Ready(Err(crate::reject::forbidden().into())),
            }
        }
    }
    #[pin_project]
    pub struct WrappedAuthedFuture<F, A> {
        #[pin]
        inner: F,
        wrapped: (Arc<Authorizer<A>>, AuthHeader),
    }

    impl<F, A> std::fmt::Debug for WrappedAuthedFuture<F, A> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("WrappedAuthedFuture")
                .finish()
        }
    }

    impl<A, F> Future for WrappedAuthedFuture<F, A>
    where
        F: TryFuture,
        F::Error: CombineRejection<Rejection>,
    {
        type Output = Result<One<Wrapped<F::Ok, A>>, <F::Error as CombineRejection<Rejection>>::One>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
            let pin = self.project();
            match ready!(pin.inner.try_poll(cx)) {
                Ok(inner) => {
                    let (authorizer, header) = pin.wrapped;
                    let item = (Wrapped {
                        wrapped: (authorizer.clone(), header.clone()),
                        inner: inner,
                    },);
                    Poll::Ready(Ok(item))
                }
                Err(err) => Poll::Ready(Err(err.into())),
            }
        }
    }
}
