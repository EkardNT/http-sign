use std::{io::Write, time::{Duration, UNIX_EPOCH}};
use std::time::SystemTime;

use crate::{algorithm::SignatureAlgorithm, message::{Headers, HttpMessage}};

/// An element that contributes to the signature calculation. Standard HTTP headers may
/// be included in the signature, as well as special non-header fields such as
/// `(request-target)`, `(created)`, and `(expires)`. The list of signature elements
/// determines which parts of the HTTP message are protected by the signature. The order
/// of signature elements that is chosen is also important in that it determines the
/// order in which the signature input string is formed.
#[derive(Debug, Eq, PartialEq)]
pub enum SignatureElement<'a> {
    /// The `(request-target)` special field. Results in the concatenation of the lowercase
    /// request method, an ASCII space, and the request path. Can be used with any
    /// algorithm.
    ///
    /// RECOMMENDED.
    RequestTarget,

    /// The `(created)` special field, indicating when the signature was created.
    /// Expressed as a Unix timestamp (at seconds granularity). Cannot be used with RSA,
    /// HMAC, or ECDSA algorithms.
    ///
    /// OPTIONAL.
    Created,

    /// The `(expires)` special field, indicating when the signature will expire.
    /// Expressed as a Unix timestamp (at seconds granularity). Can be used with any
    /// algorithm.
    ///
    /// OPTIONAL.
    Expires,

    /// A standard HTTP header element. Results in the header name being concatenated with
    /// the literal string ": ", followed by every corresponding value for the header
    /// being concatenated by ", ". The names of the headers specified must be all lower
    /// case.
    Header(&'a str),
}

/// Which of the two signature schemes defined by the standard will be used. The signature
/// scheme determines which HTTP header the signature will be placed into, as well as the
/// format of that header.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum SignatureScheme {
    /// The `Authorization: Signature <signatureParams` scheme.
    AuthorizationHeader,

    /// The `Signature: <signatureParams>` scheme.
    SignatureHeader,
}

impl SignatureScheme {
    fn header_prefix(&self) -> &str {
        match self {
            SignatureScheme::AuthorizationHeader => "Signature ",
            SignatureScheme::SignatureHeader => "",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SignError {
    /// No signature elements were provided.
    EmptySignatureElements,

    /// The (created) signature element was requested, but the SignatureAlgorithm does not
    /// allow it to be used.
    CreatedNotAllowed,

    /// A SignatureElement::Header was specified, but the named header was not present in
    /// the request.
    MissingHeader(String),

    /// A SignatureElement was specified more than once.
    DuplicateElement(String),

    /// A SignatureElement was specified with a non-lowercase header name.
    NotLowercaseHeader(String),

    /// An unexpected internal error.
    Internal(&'static str)
}

pub fn sign<'sig_elems, SigAlg, Msg, IntoSigElements>(
        scheme: SignatureScheme,
        sig_alg: &SigAlg,
        message: &mut Msg,
        expiration: Duration,
        signature_elements: &[SignatureElement<'_>],
    ) -> Result<(), SignError>
    where
        SigAlg: SignatureAlgorithm,
        Msg: HttpMessage,
{
    validate_signature_elements(sig_alg, message, signature_elements)?;
    let now = SystemTime::now();
    let created = now.duration_since(UNIX_EPOCH)
        .map_err(|_err| SignError::Internal("Unable to determine (created) Unix timestamp"))?
        .as_secs();
    let expires = (now + expiration).duration_since(UNIX_EPOCH)
        .map_err(|_err| SignError::Internal("Unable to determine (expires) Unix timestamp"))?
        .as_secs();
    let signature_input = build_canonical_signature_input(
        sig_alg, message, created, expires, signature_elements)?;
    let encoded_signature = get_encoded_signature(sig_alg, signature_input)?;
    let signature_header = build_final_header(scheme, sig_alg, encoded_signature, created, expires, signature_elements)?;
    match scheme {
        SignatureScheme::AuthorizationHeader => message.headers_mut().insert_header("authorization", signature_header.as_slice()),
        SignatureScheme::SignatureHeader => message.headers_mut().insert_header("signature", signature_header.as_slice())
    }
    Ok(())
}

fn validate_signature_elements<SigAlg: SignatureAlgorithm, Msg: HttpMessage>(
        sig_alg: &SigAlg,
        message: &mut Msg,
        signature_elements: &[SignatureElement<'_>],
    ) -> Result<(), SignError> {
    if signature_elements.is_empty() {
        return Err(SignError::EmptySignatureElements);
    }

    for element in signature_elements {
        if let SignatureElement::Header(header) = element {
            // Make sure header is all lowercase.
            if !header.chars().all(|c| !c.is_alphabetic() || c.is_lowercase()) {
                return Err(SignError::NotLowercaseHeader(header.to_string()));
            }

            // Make sure referenced header exists.
            if !message.headers().contains_header(header) {
                return Err(SignError::MissingHeader(header.to_string()));
            }
        }

        // Created can only be specified for certain algorithms.
        if let (SignatureElement::Created, false) = (element, sig_alg.allows_created()) {
            return Err(SignError::CreatedNotAllowed);
        }

        // Check for duplicates. Use an O(n^2) loop instead of a HashSet to save allocations.
        // There isn't expected to be a large number of elements.
        let occurrences = signature_elements.iter().filter(|elem| *elem == element).count();
        if occurrences > 1 {
            return Err(SignError::DuplicateElement(match element {
                SignatureElement::RequestTarget => "(request-target)".to_string(),
                SignatureElement::Created => "(created)".to_string(),
                SignatureElement::Expires => "(expires)".to_string(),
                SignatureElement::Header(name) => name.to_string()
            }));
        }
    }
    Ok(())
}

fn build_canonical_signature_input<'sig_elems, SigAlg, Msg>(
        sig_alg: &SigAlg,
        message: &mut Msg,
        created: u64,
        expires: u64,
        signature_elements: &[SignatureElement<'_>],
    ) -> Result<Vec<u8>, SignError>
    where
        SigAlg: SignatureAlgorithm,
        Msg: HttpMessage,
{
    let mut canonical = Vec::with_capacity(1024);
    for element in signature_elements {
        match element {
            SignatureElement::RequestTarget => {
                canonical.extend_from_slice(b"(request-target): ");
                canonical.extend_from_slice(message.method().lowercase());
                canonical.push(b' ');
                // TODO: url-encode the path and query string?
                canonical.extend_from_slice(message.path().as_bytes());
                if let Some(query) = message.query_string() {
                    canonical.push(b'?');
                    canonical.extend_from_slice(query.as_bytes());
                }
                canonical.push(b'\n');
            }
            SignatureElement::Created => {
                write!(canonical, "(created): {}\n", created)
                    .map_err(|_err| SignError::Internal("Failed to format (created) canonical entry"))?;
            }
            SignatureElement::Expires => {
                write!(canonical, "(expires): {}\n", expires)
                    .map_err(|_err| SignError::Internal("Failed to format (expires) canonical entry"))?;
            }
            SignatureElement::Header(name) => {
                canonical.extend_from_slice(name.as_bytes());
                canonical.extend_from_slice(b": ");
                if message.headers().header_values(name).any(|_| true) {
                    for value in message.headers().header_values(name) {
                        // If header value is a valid UTF-8 string, then trim it, otherwise use the raw bytes
                        if let Ok(value_str) = std::str::from_utf8(value) {
                            canonical.extend_from_slice(value_str.trim().as_bytes());
                        } else {
                            canonical.extend_from_slice(value);
                        }
                        canonical.extend_from_slice(b", ");
                    }
                    // remove last ", ". We know there is at least one.
                    assert_eq!(Some(b' '), canonical.pop());
                    assert_eq!(Some(b','), canonical.pop());
                }
                canonical.push(b'\n');
            }
        }
    }
    Ok(canonical)
}

fn get_encoded_signature<SigAlg: SignatureAlgorithm>(
        sig_alg: &SigAlg,
        mut signature_input: Vec<u8>,
    ) -> Result<String, SignError> {
    let mut signature = Vec::new();
    sig_alg.sign(signature_input.as_slice(), &mut signature)
        .map_err(|_err| SignError::Internal("IO error when signing"))?;
    // Reuse the signature_input for the base64 output, since we're not using it anymore.
    signature_input.clear();
    let mut encoded = String::from_utf8(signature_input)
        .map_err(|_err| SignError::Internal("Unable to resuse siganture_input allocation for base64 output"))?;
    base64::encode_config_buf(signature, base64::STANDARD, &mut encoded);
    Ok(encoded)
}

fn build_final_header<SigAlg: SignatureAlgorithm>(
        scheme: SignatureScheme,
        sig_alg: &SigAlg,
        encoded_signature: String,
        created: u64,
        expires: u64,
        signature_elements: &[SignatureElement<'_>],
    ) -> Result<Vec<u8>, SignError> {
    let mut header = Vec::new();

    header.extend_from_slice(scheme.header_prefix().as_bytes());
    header.extend_from_slice(b"keyId=\"");
    header.extend_from_slice(sig_alg.key_id().as_bytes());
    header.extend_from_slice(b"\",algorithm=\"");
    header.extend_from_slice(sig_alg.name().as_bytes());
    write!(header, "\",created={},expires={},headers=\"", created, expires)
        .map_err(|_err| SignError::Internal("Unable to write to final header buffer"))?;
    for element in signature_elements {
        header.extend_from_slice(match element {
            SignatureElement::RequestTarget => b"(request-target)",
            SignatureElement::Created => b"(created)",
            SignatureElement::Expires => b"(expires)",
            SignatureElement::Header(name) => name.as_bytes()
        });
        header.push(b' ');
    }
    assert_eq!(Some(b' '), header.pop());
    header.extend_from_slice(b"\",signature=\"");
    header.extend_from_slice(encoded_signature.as_bytes());
    header.push(b'"');

    Ok(header)
}