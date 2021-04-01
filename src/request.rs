pub trait Request {
    type Headers: Headers;

    fn headers(&self) -> &Self::Headers;
    fn headers_mut(&mut self) -> &mut Self::Headers;
    fn path(&self) -> &str;
    fn query_string(&self) -> Option<&str>;
    fn method(&self) -> Method;
    fn body(&self) -> &[u8];
}

pub struct SimpleRequest<H> {
    headers: H,
    path: String,
    query_string: Option<String>,
    method: Method,
    body: Vec<u8>
}

impl<H> SimpleRequest<H> {
    pub fn new(
            method: Method,
            path: impl Into<String>,
            query_string: Option<impl Into<String>>,
            headers: H,
            body: impl Into<Vec<u8>>) -> Self {
        Self {
            headers,
            path: path.into(),
            query_string: query_string.map(Into::into),
            method,
            body: body.into()
        }
    }
}

impl<H: Headers> Request for SimpleRequest<H> {
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

impl<Body: AsRef<[u8]>> Request for ::http::Request<Body> {
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

#[derive(Copy, Clone)]
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

pub trait Headers {
    type NameIter<'a> : Iterator<Item = &'a str>;
    type ValueIter<'a> : Iterator<Item = &'a [u8]>;

    fn header_names<'this>(&'this self) -> Self::NameIter<'this>;
    fn contains_header(&self, name: &str) -> bool;
    fn header_values<'this>(&'this self, name: &str) -> Self::ValueIter<'this>;
    fn insert_header(&mut self, name: &str, value: &[u8]);
}

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

    pub struct NameIter<'a> {
        iter: std::collections::hash_map::Keys<'a, String, String>
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

mod http {
    use http::{HeaderMap, HeaderValue, header::HeaderName};

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