use std::{io::Write, time::{Duration, UNIX_EPOCH}};
use std::time::SystemTime;

use bytes::{BufMut, BytesMut};

use crate::{algorithm::SignatureAlgorithm, message::{Headers, HttpRequest}};

/// An element that contributes to the signature calculation. Standard HTTP headers may
/// be included in the signature, as well as special non-header fields such as
/// `(request-target)`, `(created)`, and `(expires)`. The list of signature elements
/// passed to the [sign] function determines which parts of the HTTP message are protected
/// by the signature. The order of signature elements that is chosen is also important in
/// that it determines the order in which the signature input string is formed.
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

pub fn sign<'sig_elems, SigAlg, Msg>(
        temporary_buffer: &mut BytesMut,
        scheme: SignatureScheme,
        sig_alg: &SigAlg,
        message: &mut Msg,
        expiration: Duration,
        signature_elements: &[SignatureElement<'_>],
    ) -> Result<(), SignError>
    where
        SigAlg: SignatureAlgorithm,
        Msg: HttpRequest,
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
        temporary_buffer, message, created, expires, signature_elements)?;
    let encoded_signature = get_encoded_signature(temporary_buffer, sig_alg, signature_input)?;
    let signature_header = build_final_header(temporary_buffer, scheme, sig_alg, encoded_signature, created, expires, signature_elements)?;
    match scheme {
        SignatureScheme::AuthorizationHeader => message.headers_mut().insert_header("authorization", &signature_header),
        SignatureScheme::SignatureHeader => message.headers_mut().insert_header("signature", &signature_header)
    }
    Ok(())
}

fn validate_signature_elements<SigAlg: SignatureAlgorithm, Msg: HttpRequest>(
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

fn build_canonical_signature_input<'sig_elems, Msg>(
        temporary_buffer: &mut BytesMut,
        message: &mut Msg,
        created: u64,
        expires: u64,
        signature_elements: &[SignatureElement<'_>],
    ) -> Result<BytesMut, SignError>
    where
        Msg: HttpRequest,
{
    temporary_buffer.clear();
    for element in signature_elements {
        match element {
            SignatureElement::RequestTarget => {
                temporary_buffer.extend_from_slice(b"(request-target): ");
                temporary_buffer.extend_from_slice(message.method().lowercase());
                temporary_buffer.extend_from_slice(b" ");
                // TODO: url-encode the path and query string?
                temporary_buffer.extend_from_slice(message.path().as_bytes());
                if let Some(query) = message.query_string() {
                    temporary_buffer.extend_from_slice(b"?");
                    temporary_buffer.extend_from_slice(query.as_bytes());
                }
                temporary_buffer.extend_from_slice(b"\n");
            }
            SignatureElement::Created => {
                temporary_buffer.extend_from_slice(b"(created): ");
                created.as_display(|displayed| temporary_buffer.extend_from_slice(displayed));
                // .map_err(|_err| SignError::Internal("Failed to format (created) canonical entry"))?
                temporary_buffer.extend_from_slice(b"\n");
            }
            SignatureElement::Expires => {
                temporary_buffer.extend_from_slice(b"(expires): ");
                expires.as_display(|displayed| temporary_buffer.extend_from_slice(displayed));
                    // .map_err(|_err| SignError::Internal("Failed to format (expires) canonical entry"))?;
                temporary_buffer.extend_from_slice(b"\n");
            }
            SignatureElement::Header(name) => {
                temporary_buffer.extend_from_slice(name.as_bytes());
                temporary_buffer.extend_from_slice(b": ");
                if message.headers().header_values(name).any(|_| true) {
                    for value in message.headers().header_values(name) {
                        // If header value is a valid UTF-8 string, then trim it, otherwise use the raw bytes
                        if let Ok(value_str) = std::str::from_utf8(value) {
                            temporary_buffer.extend_from_slice(value_str.trim().as_bytes());
                        } else {
                            temporary_buffer.extend_from_slice(value);
                        }
                        temporary_buffer.extend_from_slice(b", ");
                    }
                    // remove last ", ". We know there is at least one.
                    assert_eq!(&b", "[..], temporary_buffer.split_off(temporary_buffer.len() - 2));
                }
                temporary_buffer.extend_from_slice(b"\n");
            }
        }
    }
    Ok(temporary_buffer.split())
}

fn get_encoded_signature<SigAlg: SignatureAlgorithm>(
        temporary_buffer: &mut BytesMut,
        sig_alg: &SigAlg,
        signature_input: BytesMut,
    ) -> Result<BytesMut, SignError> {
    temporary_buffer.clear();
    sig_alg.sign(&signature_input, &mut temporary_buffer.writer())
        .map_err(|_err| SignError::Internal("IO error when signing"))?;
    // Reuse the signature_input for the base64 output, since we're not using it anymore.
    let signature = temporary_buffer.split();
    base64::write::EncoderWriter::new(temporary_buffer.writer(), base64::STANDARD).write_all(&signature)
        .map_err(|_err| SignError::Internal("IO error when base64-encoding signature"))?;
    Ok(temporary_buffer.split())
}

fn build_final_header<SigAlg: SignatureAlgorithm>(
        temporary_buffer: &mut BytesMut,
        scheme: SignatureScheme,
        sig_alg: &SigAlg,
        encoded_signature: BytesMut,
        created: u64,
        expires: u64,
        signature_elements: &[SignatureElement<'_>],
    ) -> Result<BytesMut, SignError> {
    temporary_buffer.clear();
    temporary_buffer.extend_from_slice(scheme.header_prefix().as_bytes());
    temporary_buffer.extend_from_slice(b"keyId=\"");
    temporary_buffer.extend_from_slice(sig_alg.key_id().as_bytes());
    temporary_buffer.extend_from_slice(b"\",algorithm=\"");
    temporary_buffer.extend_from_slice(sig_alg.name().as_bytes());
    temporary_buffer.extend_from_slice(b"\",created=");
    created.as_display(|displayed| temporary_buffer.extend_from_slice(displayed));
    temporary_buffer.extend_from_slice(b",expires=");
    expires.as_display(|displayed| temporary_buffer.extend_from_slice(displayed));
    temporary_buffer.extend_from_slice(b",headers=\"");
    debug_assert!(!signature_elements.is_empty());
    for element in signature_elements {
        temporary_buffer.extend_from_slice(match element {
            SignatureElement::RequestTarget => b"(request-target)",
            SignatureElement::Created => b"(created)",
            SignatureElement::Expires => b"(expires)",
            SignatureElement::Header(name) => name.as_bytes()
        });
        temporary_buffer.extend_from_slice(b" ");
    }
    assert_eq!(&b" "[..], temporary_buffer.split_off(temporary_buffer.len() - 1));
    temporary_buffer.extend_from_slice(b"\",signature=\"");
    temporary_buffer.extend_from_slice(&encoded_signature);
    temporary_buffer.extend_from_slice(b"\"");
    Ok(temporary_buffer.split())
}


trait AsDisplay {
    fn as_display<Receiver>(&self, f: Receiver)
        where Receiver : FnOnce(&[u8]);
}

impl AsDisplay for usize {
    fn as_display<Receiver>(&self, f: Receiver)
        where Receiver : FnOnce(&[u8]) {
        let mut array = [0u8; 20];
        write!(&mut array[..], "{}", self).expect("Failed to format usize as string");
        match array.iter().position(|byte| *byte == 0) {
            Some(end) => f(&array[..end]),
            None => f(&array)
        }
    }
}

impl AsDisplay for u64 {
    fn as_display<Receiver>(&self, f: Receiver)
        where Receiver : FnOnce(&[u8]) {
        let mut array = [0u8; 20];
        write!(&mut array[..], "{}", self).expect("Failed to format u64 as string");
        match array.iter().position(|byte| *byte == 0) {
            Some(end) => f(&array[..end]),
            None => f(&array)
        }
    }
}