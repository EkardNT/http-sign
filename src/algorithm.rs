use std::fmt::Display;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Algorithm {
    HS2019,
    RSA_SHA1,
    RSA_SHA256,
    HMAC_SHA256,
    ECDSA_SHA256
}

impl Algorithm {
    fn name(&self) -> &'static str {
        match self {
            Algorithm::HS2019 => "hs2019",
            Algorithm::RSA_SHA1 => "rsa-sha1",
            Algorithm::RSA_SHA256 => "rsa-sha256",
            Algorithm::HMAC_SHA256 => "hmac-sha256",
            Algorithm::ECDSA_SHA256 => "ecdsa-sha256",
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::HS2019
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}