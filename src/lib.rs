#![forbid(unsafe_code)]

mod algorithm;
pub mod request;
mod signature;

#[allow(deprecated)]
pub use algorithm::{
    SignatureAlgorithm,
    hs::Hs2019,
    rsa::RsaSha256,
    hmac::HmacSha256,
    ecdsa::EcdsaSha256,
};

pub use signature::{
    SignError,
    SignatureElement,
    SignatureScheme,
    sign,
};
