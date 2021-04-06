extern crate http_sign;

use std::collections::HashMap;

use bytes::BytesMut;
use http_sign::*;
use http_sign::request::{BorrowedHttpRequest, Method};
use ring::{rand::SystemRandom, signature::RsaKeyPair};

static KEY: &'static [u8] = include_bytes!("example-rsa-2048-key.pk8");

fn main() {
    let mut headers = HashMap::new();
    headers.insert("x-foo".to_string(), "bar".to_string());
    let mut request = http_sign::request::OwnedHttpRequest::new(
        Method::Get,
        "/foo/bar".to_string(),
        Some("foo=bar".to_string()),
        headers,
        b"{\"hello\":\"world\"}".to_vec());
    let mut temporary_buffer = BytesMut::with_capacity(4096);
    let key = RsaKeyPair::from_pkcs8(KEY).expect("Failed to load RSA key pair");
    let random = SystemRandom::new();
    sign(
        &mut temporary_buffer,
        SignatureScheme::AuthorizationHeader,
        &RsaSha256::new("my_key_id", key, random),
        &mut request,
        std::time::Duration::from_secs(60),
        &[SignatureElement::Header("x-foo")]).expect("Failed to sign");
    println!("{:?}", request);
}