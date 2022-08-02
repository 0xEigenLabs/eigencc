//! Contains types that set the status code and corresponding headers of a
//! response.
//!
//! These types are designed to make it easier to respond correctly with a given
//! status code. Each type takes in the minimum number of parameters required to
//! construct a proper response with that status code. Some types take in
//! responders; when they do, the responder finalizes the response by writing
//! out additional headers and, importantly, the body of the response.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::borrow::Cow;

use crate::request::Request;
use crate::response::{Responder, Response};
use crate::http::Status;

/// Sets the status of the response to 201 (Created).
///
/// Sets the `Location` header and optionally the `ETag` header in the response.
/// The body of the response, which identifies the created resource, can be set
/// via the builder methods [`Created::body()`] and [`Created::tagged_body()`].
/// While both builder methods set the responder, the [`Created::tagged_body()`]
/// additionally computes a hash for the responder which is used as the value of
/// the `ETag` header when responding.
///
/// # Example
///
/// ```rust
/// use rocket::response::status;
///
/// let response = status::Created::new("http://myservice.com/resource.json")
///     .tagged_body("{ 'resource': 'Hello, world!' }");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Created<R>(Cow<'static, str>, Option<R>, Option<u64>);

impl<'r, R> Created<R> {
    /// Constructs a `Created` response with a `location` and no body.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #![feature(proc_macro_hygiene)]
    /// # use rocket::{get, routes, local::Client};
    /// use rocket::response::status;
    ///
    /// #[get("/")]
    /// fn create() -> status::Created<&'static str> {
    ///     status::Created::new("http://myservice.com/resource.json")
    /// }
    ///
    /// # let rocket = rocket::ignite().mount("/", routes![create]);
    /// # let client = Client::new(rocket).unwrap();
    /// let mut response = client.get("/").dispatch();
    ///
    /// let loc = response.headers().get_one("Location");
    /// assert_eq!(loc, Some("http://myservice.com/resource.json"));
    /// assert!(response.body().is_none());
    /// ```
    pub fn new<L: Into<Cow<'static, str>>>(location: L) -> Self {
        Created(location.into(), None, None)
    }

    /// Adds `responder` as the body of `self`.
    ///
    /// Unlike [`tagged_body()`](self::Created::tagged_body()), this method
    /// _does not_ result in an `ETag` header being set in the response.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #![feature(proc_macro_hygiene)]
    /// # use rocket::{get, routes, local::Client};
    /// use rocket::response::status;
    ///
    /// #[get("/")]
    /// fn create() -> status::Created<&'static str> {
    ///     status::Created::new("http://myservice.com/resource.json")
    ///         .body("{ 'resource': 'Hello, world!' }")
    /// }
    ///
    /// # let rocket = rocket::ignite().mount("/", routes![create]);
    /// # let client = Client::new(rocket).unwrap();
    /// let mut response = client.get("/").dispatch();
    ///
    /// let body = response.body_string();
    /// assert_eq!(body.unwrap(), "{ 'resource': 'Hello, world!' }");
    ///
    /// let loc = response.headers().get_one("Location");
    /// assert_eq!(loc, Some("http://myservice.com/resource.json"));
    ///
    /// let etag = response.headers().get_one("ETag");
    /// assert_eq!(etag, None);
    /// ```
    pub fn body(mut self, responder: R) -> Self
        where R: Responder<'r>
    {
        self.1 = Some(responder);
        self
    }

    /// Adds `responder` as the body of `self`. Computes a hash of the
    /// `responder` to be used as the value of the `ETag` header.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #![feature(proc_macro_hygiene)]
    /// # use rocket::{get, routes, local::Client};
    /// use rocket::response::status;
    ///
    /// #[get("/")]
    /// fn create() -> status::Created<&'static str> {
    ///     status::Created::new("http://myservice.com/resource.json")
    ///         .tagged_body("{ 'resource': 'Hello, world!' }")
    /// }
    ///
    /// # let rocket = rocket::ignite().mount("/", routes![create]);
    /// # let client = Client::new(rocket).unwrap();
    /// let mut response = client.get("/").dispatch();
    ///
    /// let body = response.body_string();
    /// assert_eq!(body.unwrap(), "{ 'resource': 'Hello, world!' }");
    ///
    /// let loc = response.headers().get_one("Location");
    /// assert_eq!(loc, Some("http://myservice.com/resource.json"));
    ///
    /// let etag = response.headers().get_one("ETag");
    /// assert_eq!(etag, Some(r#""13046220615156895040""#));
    /// ```
    pub fn tagged_body(mut self, responder: R) -> Self
        where R: Responder<'r> + Hash
    {
        let mut hasher = &mut DefaultHasher::default();
        responder.hash(&mut hasher);
        let hash = hasher.finish();
        self.1 = Some(responder);
        self.2 = Some(hash);
        self
    }
}

/// Sets the status code of the response to 201 Created. Sets the `Location`
/// header to the parameter in the [`Created::new()`] constructor.
///
/// The optional responder, set via [`Created::body()`] or
/// [`Created::tagged_body()`] finalizes the response if it exists. The wrapped
/// responder should write the body of the response so that it contains
/// information about the created resource. If no responder is provided, the
/// response body will be empty.
///
/// In addition to setting the status code, `Location` header, and finalizing
/// the response with the `Responder`, the `ETag` header is set conditionally if
/// a hashable `Responder` is provided via [`Created::tagged_body()`]. The `ETag`
/// header is set to a hash value of the responder.
impl<'r, R: Responder<'r>> Responder<'r> for Created<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
       let mut response = Response::build();
       if let Some(responder) = self.1 {
           response.merge(responder.respond_to(req)?);
       }

       if let Some(hash) = self.2 {
           response.raw_header("ETag", format!(r#""{}""#, hash));
       }

       response.status(Status::Created)
           .raw_header("Location", self.0)
           .ok()
    }
}

/// Sets the status of the response to 202 (Accepted).
///
/// If a responder is supplied, the remainder of the response is delegated to
/// it. If there is no responder, the body of the response will be empty.
///
/// # Examples
///
/// A 202 Accepted response without a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Accepted::<()>(None);
/// ```
///
/// A 202 Accepted response _with_ a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Accepted(Some("processing"));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Accepted<R>(pub Option<R>);

/// Sets the status code of the response to 202 Accepted. If the responder is
/// `Some`, it is used to finalize the response.
impl<'r, R: Responder<'r>> Responder<'r> for Accepted<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
        let mut build = Response::build();
        if let Some(responder) = self.0 {
            build.merge(responder.respond_to(req)?);
        }

        build.status(Status::Accepted).ok()
    }
}

/// Sets the status of the response to 204 (No Content).
///
/// The response body will be empty.
///
/// # Example
///
/// A 204 No Content response:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::NoContent;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NoContent;

/// Sets the status code of the response to 204 No Content.
impl<'r> Responder<'r> for NoContent {
    fn respond_to(self, _: &Request<'_>) -> Result<Response<'r>, Status> {
        let mut build = Response::build();
        build.status(Status::NoContent).ok()
    }
}

/// Sets the status of the response to 400 (Bad Request).
///
/// If a responder is supplied, the remainder of the response is delegated to
/// it. If there is no responder, the body of the response will be empty.
///
/// # Examples
///
/// A 400 Bad Request response without a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::BadRequest::<()>(None);
/// ```
///
/// A 400 Bad Request response _with_ a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::BadRequest(Some("error message"));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct BadRequest<R>(pub Option<R>);

/// Sets the status code of the response to 400 Bad Request. If the responder is
/// `Some`, it is used to finalize the response.
impl<'r, R: Responder<'r>> Responder<'r> for BadRequest<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
        let mut build = Response::build();
        if let Some(responder) = self.0 {
            build.merge(responder.respond_to(req)?);
        }

        build.status(Status::BadRequest).ok()
    }
}

/// Sets the status of the response to 401 (Unauthorized).
///
/// If a responder is supplied, the remainder of the response is delegated to
/// it. If there is no responder, the body of the response will be empty.
///
/// # Examples
///
/// A 401 Unauthorized response without a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Unauthorized::<()>(None);
/// ```
///
/// A 401 Unauthorized response _with_ a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Unauthorized(Some("error message"));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Unauthorized<R>(pub Option<R>);

/// Sets the status code of the response to 401 Unauthorized. If the responder is
/// `Some`, it is used to finalize the response.
impl<'r, R: Responder<'r>> Responder<'r> for Unauthorized<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
        let mut build = Response::build();
        if let Some(responder) = self.0 {
            build.merge(responder.respond_to(req)?);
        }

        build.status(Status::Unauthorized).ok()
    }
}

/// Sets the status of the response to 403 (Forbidden).
///
/// If a responder is supplied, the remainder of the response is delegated to
/// it. If there is no responder, the body of the response will be empty.
///
/// # Examples
///
/// A 403 Forbidden response without a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Forbidden::<()>(None);
/// ```
///
/// A 403 Forbidden response _with_ a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Forbidden(Some("error message"));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Forbidden<R>(pub Option<R>);

/// Sets the status code of the response to 403 Forbidden. If the responder is
/// `Some`, it is used to finalize the response.
impl<'r, R: Responder<'r>> Responder<'r> for Forbidden<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
        let mut build = Response::build();
        if let Some(responder) = self.0 {
            build.merge(responder.respond_to(req)?);
        }

        build.status(Status::Forbidden).ok()
    }
}

/// Sets the status of the response to 404 (Not Found).
///
/// The remainder of the response is delegated to the wrapped `Responder`.
///
/// # Example
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::NotFound("Sorry, I couldn't find it!");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NotFound<R>(pub R);

/// Sets the status code of the response to 404 Not Found.
impl<'r, R: Responder<'r>> Responder<'r> for NotFound<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
        Response::build_from(self.0.respond_to(req)?)
            .status(Status::NotFound)
            .ok()
    }
}


/// Sets the status of the response to 409 (Conflict).
///
/// If a responder is supplied, the remainder of the response is delegated to
/// it. If there is no responder, the body of the response will be empty.
///
/// # Examples
///
/// A 409 Conflict response without a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Conflict::<()>(None);
/// ```
///
/// A 409 Conflict response _with_ a body:
///
/// ```rust
/// use rocket::response::status;
///
/// # #[allow(unused_variables)]
/// let response = status::Conflict(Some("error message"));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Conflict<R>(pub Option<R>);

/// Sets the status code of the response to 409 Conflict. If the responder is
/// `Some`, it is used to finalize the response.
impl<'r, R: Responder<'r>> Responder<'r> for Conflict<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
        let mut build = Response::build();
        if let Some(responder) = self.0 {
            build.merge(responder.respond_to(req)?);
        }

        build.status(Status::Conflict).ok()
    }
}

/// Creates a response with the given status code and underlying responder.
///
/// # Example
///
/// ```rust
/// use rocket::response::status;
/// use rocket::http::Status;
///
/// # #[allow(unused_variables)]
/// let response = status::Custom(Status::ImATeapot, "Hi!");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Custom<R>(pub Status, pub R);

/// Sets the status code of the response and then delegates the remainder of the
/// response to the wrapped responder.
impl<'r, R: Responder<'r>> Responder<'r> for Custom<R> {
    fn respond_to(self, req: &Request<'_>) -> Result<Response<'r>, Status> {
        Response::build_from(self.1.respond_to(req)?)
            .status(self.0)
            .ok()
    }
}

// The following are unimplemented.
// 206 Partial Content (variant), 203 Non-Authoritative Information (headers).
