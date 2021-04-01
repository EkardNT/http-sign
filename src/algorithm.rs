use std::io::Write;

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

    /// Digitally sign a block of data.
    fn sign(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()>;
}

pub mod hs {
    use std::io::Write;

    use ring::{hmac::Key, rand::SecureRandom, signature::{RsaEncoding, RsaKeyPair}};

    use super::SignatureAlgorithm;

    pub struct Hs2019<Rand>(Inner<Rand>);

    enum Inner<Rand> {
        RsaPkcs1 {
            key_id: String,
            key: RsaKeyPair,
            random: Rand,
        },
        RsaPss {
            key_id: String,
            key: RsaKeyPair,
            random: Rand,
        },
        Hmac {
            key_id: String,
            key: Key
        }
    }

    impl<Rand> Hs2019<Rand> {
        pub fn new_rsa_pkcs1(key_id: impl Into<String>, key: RsaKeyPair, random: Rand) -> Self {
            Self(Inner::RsaPkcs1 {
                key_id: key_id.into(),
                key,
                random
            })
        }

        pub fn new_rsa_pss(key_id: impl Into<String>, key: RsaKeyPair, random: Rand) -> Self {
            Self(Inner::RsaPss {
                key_id: key_id.into(),
                key,
                random
            })
        }

        /// Constructs a new Hs2019 using HMAC with SHA-512 from the supplied HMAC key
        /// data. See the documentation of `ring::hmac::Key::new` for a discussion of the
        /// length of `key_value`.
        pub fn new_hmac(key_id: impl Into<String>, key_value: &[u8]) -> Self {
            let key = Key::new(ring::hmac::HMAC_SHA512, key_value);
            Self(Inner::Hmac {
                key_id: key_id.into(),
                key
            })
        }
    }

    impl<Rand: SecureRandom> SignatureAlgorithm for Hs2019<Rand> {
        fn name(&self) -> &str {
            "hs2019"
        }

        fn key_id(&self) -> &str {
            match &self.0 {
                Inner::RsaPkcs1 { key_id, .. } => key_id,
                Inner::RsaPss { key_id, .. } => key_id,
                Inner::Hmac { key_id, .. } => key_id,
            }
        }

        fn allows_created(&self) -> bool {
            true
        }

        fn sign(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()> {
            match &self.0 {
                Inner::RsaPkcs1 { key, random, .. } => {
                    // 1024 bytes is enough for RSA-8192 keys.
                    let mut signature = [0u8; 1024];
                    let signature = &mut signature[..key.public_modulus_len()];
                    key.sign(&ring::signature::RSA_PKCS1_SHA512, random, data, signature)
                        .expect("Failed to compute RSA_PKCS1_SHA512 signature");
                    output.write_all(signature)
                }
                Inner::RsaPss { key, random, .. } => {
                    // 1024 bytes is enough for RSA-8192 keys.
                    let mut signature = [0u8; 1024];
                    let signature = &mut signature[..key.public_modulus_len()];
                    key.sign(&ring::signature::RSA_PSS_SHA512, random, data, signature)
                        .expect("Failed to compute RSA_PSS_SHA512 signature");
                    output.write_all(signature)
                }
                Inner::Hmac { key, .. } => {
                    let tag = ring::hmac::sign(key, data);
                    output.write_all(tag.as_ref())
                }
            }
        }
    }
}

pub mod rsa {
    use std::fmt::Debug;
    use std::io::Write;

    use ring::{rand::SecureRandom, signature::RsaKeyPair};

    use super::SignatureAlgorithm;

    #[deprecated]
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
}

pub mod hmac {
    use std::fmt::Debug;
    use std::io::Write;

    use ring::{rand::SecureRandom, hmac::Key};

    use super::SignatureAlgorithm;

    #[deprecated]
    pub struct HmacSha256 {
        key_id: String,
        key: Key,
    }

    impl HmacSha256 {
        /// Constructs a new `HmacSha256` from the supplied HMAC key data. See the
        /// documentation of `ring::hmac::Key::new` for a discussion of the length of `key_value`.
        pub fn new(key_id: impl Into<String>, key_value: &[u8]) -> Self {
            let key = Key::new(ring::hmac::HMAC_SHA256, key_value);
            Self {
                key_id: key_id.into(),
                key,
            }
        }
    }

    impl SignatureAlgorithm for HmacSha256 {
        fn name(&self) -> &str {
            "rsa-sha256"
        }

        fn key_id(&self) -> &str {
            &self.key_id
        }

        fn allows_created(&self) -> bool {
            false
        }

        fn sign(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()> {
            let tag = ring::hmac::sign(&self.key, data);
            output.write_all(tag.as_ref())
        }
    }

    impl Debug for HmacSha256 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HmacSha256")
                .field("key_id", &self.key_id)
                .field("key", &self.key)
                .finish()
        }
    }
}

pub mod ecdsa {
    use std::fmt::Debug;
    use std::io::Write;

    use ring::{rand::SecureRandom, signature::EcdsaKeyPair};

    use super::SignatureAlgorithm;

    #[deprecated]
    pub struct EcdsaSha256<Rand> {
        key_id: String,
        key: EcdsaKeyPair,
        random: Rand,
    }

    impl<Rand> EcdsaSha256<Rand> {
        /// Construct a new EcdsaSha256 from the specified key. The key should of
        /// algorithm ECDSA_P256_SHA256_ASN1_SIGNING, but there is no way to verify that
        /// from ring's current API.
        pub fn new(key_id: impl Into<String>, key: EcdsaKeyPair, random: Rand) -> Self {
            Self {
                key_id: key_id.into(),
                key,
                random,
            }
        }
    }

    impl<Rand: SecureRandom> SignatureAlgorithm for EcdsaSha256<Rand> {
        fn name(&self) -> &str {
            "ecdsa-sha256"
        }

        fn key_id(&self) -> &str {
            &self.key_id
        }

        fn allows_created(&self) -> bool {
            false
        }

        fn sign(&self, data: &[u8], output: &mut dyn Write) -> std::io::Result<()> {
            let signature = self.key.sign(&self.random, data)
                .expect("Failed to sign message in EcdsaSha256");
            output.write_all(signature.as_ref())
        }
    }

    impl<Rand> Debug for EcdsaSha256<Rand> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("EcdsaSha256")
                .field("key_id", &self.key_id)
                .field("key", &self.key)
                .finish()
        }
    }

}