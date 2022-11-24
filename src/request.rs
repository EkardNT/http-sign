/// This trait exposes all of the information about a HTTP request that is required to
/// produce the signature header.
///
/// The [OwnedHttpRequest] and [BorrowedHttpRequest] types are provided for simple use
/// cases where you do not have preexisting structs representing HTTP requests that you
/// can use. In addition to those two convenience types, support for other common
/// community crates can be enabled by turning on the following **features**, all of which
/// are off by default.
/// - `http`: Enables support for the [http](https://crates.io/crates/http) crate's
///   Request and HeaderMap types.
pub trait HttpRequest {
    /// The type of HTTP headers object.
    type Headers: Headers;

    /// Returns a shared reference to the HTTP request headers.
    fn headers(&self) -> &Self::Headers;

    /// Returns a unique reference to the HTTP request headers. This is used by the
    /// [sign](super::sign) function to insert the signature header according to the
    /// chosen [algorithm](super::SignatureAlgorithm).
    fn headers_mut(&mut self) -> &mut Self::Headers;

    /// The path component, excluding any query string components.
    fn path(&self) -> &str;

    /// The query string component, if any. There must not be a leading `'?'`.
    fn query_string(&self) -> Option<&str>;

    /// The HTTP method.
    fn method(&self) -> Method;

    /// The body data. If the request does not contain a body, this function should return
    /// a 0-length slice.
    fn body(&self) -> &[u8];
}

/// This is a simple implementation of [HttpRequest] that does not depend on any external
/// library. It owns all of the request data.
#[derive(Debug)]
pub struct OwnedHttpRequest<H> {
    headers: H,
    path: String,
    query_string: Option<String>,
    method: Method,
    body: Vec<u8>
}

impl<H> OwnedHttpRequest<H> {
    /// Build a new [OwnedHttpRequest] from owned components.
    pub fn new(
            method: Method,
            path: String,
            query_string: Option<String>,
            headers: H,
            body: Vec<u8>,) -> Self {
        Self {
            headers,
            path,
            query_string,
            method,
            body,
        }
    }
}

impl<H: Headers> HttpRequest for OwnedHttpRequest<H> {
    type Headers = H;

    fn headers(&self) -> &Self::Headers {
        &self.headers
    }

    fn headers_mut(&mut self) -> &mut Self::Headers {
        &mut self.headers
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn query_string(&self) -> Option<&str> {
        self.query_string.as_ref().map(|str| str.as_str())
    }

    fn method(&self) -> Method {
        self.method
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}


/// This is a simple implementation of [HttpRequest] that does not depend on any external
/// library. It borrows all of the request data.
pub struct BorrowedHttpRequest<'request, H> {
    headers: &'request mut H,
    path: &'request str,
    query_string: Option<&'request str>,
    method: Method,
    body: &'request [u8]
}

impl<'request, H> BorrowedHttpRequest<'request, H> {
    /// Build a new [BorrowedHttpRequest] from borrowed components.
    pub fn new(
            method: Method,
            path: &'request str,
            query_string: Option<&'request str>,
            headers: &'request mut H,
            body: &'request [u8]) -> Self {
        Self {
            headers,
            path,
            query_string,
            method,
            body
        }
    }
}

impl<'request, H: Headers> HttpRequest for BorrowedHttpRequest<'request, H> {
    type Headers = H;

    fn headers(&self) -> &Self::Headers {
        self.headers
    }

    fn headers_mut(&mut self) -> &mut Self::Headers {
        self.headers
    }

    fn path(&self) -> &str {
        self.path
    }

    fn query_string(&self) -> Option<&str> {
        self.query_string
    }

    fn method(&self) -> Method {
        self.method
    }

    fn body(&self) -> &[u8] {
        self.body
    }
}

/// An HTTP method such as GET, POST, etc.
#[derive(Copy, Clone, Debug)]
pub enum Method {
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
}

impl Method {
    /// Returns the lowercase representation of the [Method].
    pub fn lowercase(&self) -> &'static [u8] {
        match self {
            Self::Get => b"get",
            Self::Post => b"post",
            Self::Put => b"put",
            Self::Delete => b"delete",
            Self::Head => b"head",
            Self::Options => b"options",
            Self::Connect => b"connect",
            Self::Patch => b"patch",
            Self::Trace => b"trace",
        }
    }
}

/// This trait allows the signature generation logic both read and write access to the
/// HTTP headers contained within a [HTTP request](HttpRequest).
pub trait Headers {
    /// Iterator over header names. This library can only work with header names that are
    /// valid UTF-8 (and by extension, all ASCII-only headers).
    type NameIter<'a> : Iterator<Item = &'a str> where Self: 'a;
    /// Iterator over header values. Header values are allowed to be arbitrary byte
    /// strings in any encoding.
    type ValueIter<'a> : Iterator<Item = &'a [u8]> where Self: 'a;

    /// Returns an iterator over all the header names defined for the HTTP request.
    fn header_names<'this>(&'this self) -> Self::NameIter<'this>;

    /// Returns true if the HTTP request contains a header with the given `name`, or false
    /// if no such header is present. It is up to the implementor of this trait whether
    /// header names are case sensitive.
    fn contains_header(&self, name: &str) -> bool;

    /// Returns an iterator over all the values present for the header with the given
    /// `name`. It is up to the implementor of this trait whether header names are
    /// case sensitive.
    fn header_values<'this>(&'this self, name: &str) -> Self::ValueIter<'this>;

    /// Inserts a new header with the given `name` and `value`. This will be used to
    /// insert the computed Authorization or Signature header.
    fn insert_header(&mut self, name: &str, value: &[u8]);
}

/// Support for representing [Headers] as a [HashMap](std::collections::HashMap).
mod hash_map {
    impl super::Headers for std::collections::HashMap<String, String> {
        type NameIter<'a> = NameIter<'a>;

        type ValueIter<'a> = ValueIter<'a>;

        fn header_names<'this>(&'this self) -> Self::NameIter<'this> {
            NameIter { iter: self.keys() }
        }

        fn contains_header(&self, name: &str) -> bool {
            self.contains_key(name)
        }

        fn header_values<'this>(&'this self, name: &str) -> Self::ValueIter<'this> {
            ValueIter { value: self.get(name).map(|val| val.as_ref()) }
        }

        fn insert_header(&mut self, name: &str, value: &[u8]) {
            self.insert(name.into(), String::from_utf8_lossy(value).into_owned());
        }
    }

    /// Iterator over all the keys in the hash map as header names.
    pub struct NameIter<'a> {
        iter: std::collections::hash_map::Keys<'a, String, String>
    }

    impl<'a> Iterator for NameIter<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.next().map(|str| str.as_ref())
        }
    }

    /// Iterator over all the values in the hash map as header values.
    pub struct ValueIter<'a> {
        value: Option<&'a [u8]>
    }

    impl<'a> Iterator for ValueIter<'a> {
        type Item = &'a [u8];

        fn next(&mut self) -> Option<Self::Item> {
            self.value.take()
        }
    }
}

/// Support for representing [Headers] as a [HashMap](std::collections::BTreeMap).
mod btree_map {
    impl super::Headers for std::collections::BTreeMap<String, String> {
        type NameIter<'a> = NameIter<'a>;

        type ValueIter<'a> = ValueIter<'a>;

        fn header_names<'this>(&'this self) -> Self::NameIter<'this> {
            NameIter { iter: self.keys() }
        }

        fn contains_header(&self, name: &str) -> bool {
            self.contains_key(name)
        }

        fn header_values<'this>(&'this self, name: &str) -> Self::ValueIter<'this> {
            ValueIter { value: self.get(name).map(|val| val.as_bytes()) }
        }

        fn insert_header(&mut self, name: &str, value: &[u8]) {
            self.insert(name.into(), String::from_utf8_lossy(value).into_owned());
        }
    }

    pub struct NameIter<'a> {
        iter: std::collections::btree_map::Keys<'a, String, String>
    }

    impl<'a> Iterator for NameIter<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.next().map(|str| str.as_ref())
        }
    }

    pub struct ValueIter<'a> {
        value: Option<&'a [u8]>
    }

    impl<'a> Iterator for ValueIter<'a> {
        type Item = &'a [u8];

        fn next(&mut self) -> Option<Self::Item> {
            self.value.take()
        }
    }
}

/// Adds support for using types from the [http](https://crates.io/crates/http) crate
/// as implementations of [HttpRequest] and [Headers].
///
/// Requires the `http` feature to be enabled.
#[cfg(feature = "http")]
mod http {
    use http::{HeaderMap, HeaderValue, header::HeaderName};

    use super::{HttpRequest, Method};

    impl<Body: AsRef<[u8]>> HttpRequest for ::http::Request<Body> {
        type Headers = ::http::HeaderMap;

        fn headers(&self) -> &Self::Headers {
            self.headers()
        }

        fn headers_mut(&mut self) -> &mut Self::Headers {
            self.headers_mut()
        }

        fn path(&self) -> &str {
            self.uri().path()
        }

        fn query_string(&self) -> Option<&str> {
            self.uri().query()
        }

        fn method(&self) -> Method {
            match self.method() {
                &::http::Method::OPTIONS => Method::Options,
                &::http::Method::GET => Method::Get,
                &::http::Method::POST => Method::Post,
                &::http::Method::PUT => Method::Put,
                &::http::Method::DELETE => Method::Delete,
                &::http::Method::HEAD => Method::Head,
                &::http::Method::TRACE => Method::Trace,
                &::http::Method::CONNECT => Method::Connect,
                &::http::Method::PATCH => Method::Patch,
                _ => panic!("Unrecognized HTTP method"),
            }
        }

        fn body(&self) -> &[u8] {
            self.body().as_ref()
        }
    }

    impl super::Headers for HeaderMap<HeaderValue> {
        type NameIter<'a> = NameIter<'a, HeaderValue>;

        type ValueIter<'a> = ValueIter<'a, HeaderValue>;

        fn header_names<'this>(&'this self) -> Self::NameIter<'this> {
            NameIter { iter: self.keys() }
        }

        fn contains_header(&self, name: &str) -> bool {
            self.contains_key(name)
        }

        fn header_values<'this>(&'this self, name: &str) -> Self::ValueIter<'this> {
            ValueIter { iter: Some(self.get_all(name).into_iter()) }
        }

        fn insert_header(&mut self, name: &str, value: &[u8]) {
            self.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("Invalid header name"),
                HeaderValue::from_bytes(value).expect("Invalid header value")
            );
        }
    }

    pub struct NameIter<'a, T> {
        iter: http::header::Keys<'a, T>
    }

    impl<'a, T> Iterator for NameIter<'a, T> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.next().map(|name| name.as_ref())
        }
    }

    pub struct ValueIter<'a, T> {
        iter: Option<http::header::ValueIter<'a, T>>
    }

    impl<'a, T: AsRef<[u8]>> Iterator for ValueIter<'a, T> {
        type Item = &'a [u8];

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.as_mut().and_then(|iter| iter.next().map(|val| val.as_ref()))
        }
    }
}
