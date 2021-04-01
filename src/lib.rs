#![forbid(unsafe_code)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]

mod algorithm;
pub mod request;
mod signature;

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