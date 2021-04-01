use std::{fmt::Debug, io::Write};

use ring::{rand::{SecureRandom}, signature::RsaKeyPair};

/// The signature algorithm used to generate the HTTP message signature. The signature
/// algorithm determines determines the hashing and signing algorithms used in computing
/// the signature. Technically, it also determines the canonicalization algorithm used to
/// build the string to sign, but as all signature algorithms share the same
/// canonicalization algorithm, this trait does not include that feature.
pub trait SignatureAlgorithm {
    /// The name which will be used for the "algorithm" signature parameter.
    fn name(&self) -> &str;

    /// The id of the key, which will be used for the "keyId" signature parameter.
    fn key_id(&self) -> &str;

    /// Is the (created) signature element allowed?
    fn allows_created(&self) -> bool;

    /// Hash a block of data.
    fn hash(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()>;

    /// Digitally sign a block of data.
    fn sign(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()>;
}

pub struct RsaSha256<Rand> {
    key_id: String,
    key: RsaKeyPair,
    random: Rand,
}

impl<Rand> RsaSha256<Rand> {
    pub fn new(key_id: impl Into<String>, key: RsaKeyPair, random: Rand) -> Self {
        Self {
            key_id: key_id.into(),
            key,
            random
        }
    }
}

impl<Rand: SecureRandom> SignatureAlgorithm for RsaSha256<Rand> {
    fn name(&self) -> &str {
        "rsa-sha256"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn allows_created(&self) -> bool {
        false
    }

    fn hash(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()> {
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        output.write_all(digest.as_ref())
    }

    fn sign(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()> {
        // 1024 bytes is enough for RSA-8192 keys.
        let mut signature = [0u8; 1024];
        let signature = &mut signature[..self.key.public_modulus_len()];
        self.key.sign(&ring::signature::RSA_PKCS1_SHA256, &self.random, data, signature)
            .expect("Failed to compute RSA_PKCS1_SHA256");
        output.write_all(signature)
    }
}

impl<Rand> Debug for RsaSha256<Rand> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaSha256")
            .field("key_id", &self.key_id)
            .field("key", &self.key)
            .finish()
    }
}