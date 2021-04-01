use crate::{request::{Headers, Method, Request}};

use std::{borrow::Cow, sync::Arc};
use std::io::Write;

use base64::write::EncoderWriter;
use chrono::Utc;
use marching_buffer::*;
use ring::rand::SecureRandom;
use ring::signature::RsaKeyPair;

trait MethodExt {
    fn lowercase(&self) -> &'static [u8];
    fn is_body_mandatory(&self) -> bool;
    fn required_object_storage_signing_elements(self) -> &'static [SignatureElement<'static>];
    fn required_non_object_storage_signing_elements(&self) -> &'static [SignatureElement<'static>];
}

impl MethodExt for Method {
    fn lowercase(&self) -> &'static [u8] {
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

    fn is_body_mandatory(&self) -> bool {
        match self {
            Self::Put | Self::Patch | Self::Post => true,
            _ => false
        }
    }

    fn required_object_storage_signing_elements(self) -> &'static [SignatureElement<'static>] {
        match self {
            Self::Get | Self::Head | Self::Delete | Self::Put | Self::Post | Self::Patch => &BASIC_SIGNATURE_ELEMENTS[..],
            _ => &[]
        }
    }

    fn required_non_object_storage_signing_elements(&self) -> &'static [SignatureElement<'static>] {
        match self {
            Self::Get | Self::Head | Self::Delete => &BASIC_SIGNATURE_ELEMENTS[..],
            Self::Put | Self::Post | Self::Patch => &EXTENDED_SIGNATURE_ELEMENTS[..],
            _ => &[]
        }
    }
}

static BASIC_SIGNATURE_ELEMENTS: [SignatureElement<'static>; 2] = [
    SignatureElement::Date,
    SignatureElement::RequestTarget
];

static EXTENDED_SIGNATURE_ELEMENTS: [SignatureElement<'static>; 5] = [
    SignatureElement::Date,
    SignatureElement::RequestTarget,
    SignatureElement::StandardHeader("content-length"),
    SignatureElement::StandardHeader("content-type"),
    SignatureElement::XContentSHA256
];

#[derive(Clone, Debug)]
enum SignatureElement<'header> {
    Date,
    StandardHeader(&'header str),
    XContentSHA256,
    RequestTarget
}

impl<'header> SignatureElement<'header> {
    fn eq_header(&self, header_name: &str) -> bool {
        match self {
            &SignatureElement::Date => header_name == "date" || header_name == "x-date",
            &SignatureElement::StandardHeader(this_name) => this_name == header_name,
            &SignatureElement::XContentSHA256 => header_name == "x-content-sha256",
            &Self::RequestTarget => false
        }
    }
}

#[derive(Debug)]
pub enum SignError {
    BodyNotExpected,
    InternalError(&'static str),
    MissingContentType,
    MultivaluedHeader(Cow<'static, str>),
    MissingAdditionalHeader(Cow<'static, str>),
}

pub struct Signer {
    binary_buffer: MarchingBuffer<u8>,
    key_id: String,
    key: RsaKeyPair,
    rng: Arc<dyn SecureRandom>
}

impl Signer {
    pub fn new(key_id: String, key: RsaKeyPair, rng: Arc<dyn SecureRandom>) -> Self {
        Self {
            binary_buffer: MarchingBuffer::new(),
            key_id,
            key,
            rng
        }
    }

    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#canonicalization
    pub fn sign<'additional_headers, R: Request>(
            &mut self,
            request: &mut R,
            additional_headers_to_sign: impl IntoIterator<Item = &'additional_headers str>,
            ignore_body_for_signing: bool,
            allow_body_for_get: bool) -> Result<(), SignError> {
        inject_missing_headers(&self.binary_buffer, request, ignore_body_for_signing, allow_body_for_get)?;
        let mut signature_element_buffer = Vec::with_capacity(128);
        let signature_elements = get_signature_elements(
            &mut signature_element_buffer,
            request,
            additional_headers_to_sign.into_iter(),
            ignore_body_for_signing,
            allow_body_for_get)?;
        let signature_input = calculate_signature_input(
            &self.binary_buffer,
            &signature_elements,
            request)?;
        let base64_signature = sign_and_base64_encode(&self.binary_buffer, signature_input, self.rng.as_ref(), &self.key)?;
        let authorization_header = build_authorization_header(&self.binary_buffer, base64_signature, request, signature_elements, &self.key_id)?;
        request.headers_mut().insert_header("authorization", authorization_header.access().as_slice());
        Ok(())
    }
}

fn inject_missing_headers<R: Request>(
        binary_buffer: &MarchingBuffer<u8>,
        request: &mut R,
        ignore_body_for_signing: bool,
        allow_body_for_get: bool
    ) -> Result<(), SignError> {
    {
        let mut buffer = binary_buffer.get_writer();
        if !request.headers().contains_header("date") && !request.headers().contains_header("x-date") {
            write!(buffer.access(), "{}", Utc::now().format("%a, %d %b %Y %H:%M:%S %Z"))
                .map_err(|_err| SignError::InternalError("Failed to format Date header value"))?;
            request.headers_mut().insert_header("date", buffer.access().as_slice());
        } else {
            if request.headers().header_values("date").count() > 1 {
                return Err(SignError::MultivaluedHeader(Cow::Borrowed("date")));
            }
            if request.headers().header_values("x-date").count() > 1 {
                return Err(SignError::MultivaluedHeader(Cow::Borrowed("x-date")));
            }
        }
    }

    let has_body = request.body().len() > 0;

    if request.method().is_body_mandatory() {
        if !ignore_body_for_signing || has_body {
            set_body_headers(binary_buffer, request)?;
        }
    } else {
        match (has_body, allow_body_for_get) {
            (true, true) => set_body_headers(binary_buffer, request)?,
            (true, false) => return Err(SignError::BodyNotExpected),
            (_, _) => {}
        }
    }

    Ok(())
}

fn set_body_headers<R: Request>(
        binary_buffer: &MarchingBuffer<u8>,
        request: &mut R
    ) -> Result<(), SignError> {
    {
        let mut buffer = binary_buffer.get_writer();
        if !request.headers().contains_header("content-length") {
            write!(buffer.access(), "{}", request.body().len())
                .map_err(|_err| SignError::InternalError("Failed to format Content-Length header value"))?;
            request.headers_mut().insert_header("content-length", buffer.access().as_slice());
        } else if request.headers().header_values("content-length").count() > 1 {
            return Err(SignError::MultivaluedHeader(Cow::Borrowed("content-length")));
        }
    }

    {
        if !request.headers().contains_header("x-content-sha256") {
            let encoded_hash = calculate_sha256_base64(request.body(), binary_buffer)?;
            request.headers_mut().insert_header("x-content-sha256", encoded_hash.access().as_slice());
        } else if request.headers().header_values("x-content-sha256").count() > 1 {
            return Err(SignError::MultivaluedHeader(Cow::Borrowed("x-content-sha256")));
        }
    }

    if !request.headers().contains_header("content-type") {
        return Err(SignError::MissingContentType);
    } else if request.headers().header_values("content-type").count() > 1 {
        return Err(SignError::MultivaluedHeader(Cow::Borrowed("content-type")));
    }

    Ok(())
}

fn calculate_sha256_base64(
        data_to_hash: &[u8],
        binary_buffer: &MarchingBuffer<u8>
    ) -> Result<Reader<u8>, SignError> {
    let mut buffer = binary_buffer.get_writer();
    let digest = ring::digest::digest(&ring::digest::SHA256, data_to_hash);
    {
        let mut encoder = EncoderWriter::new(buffer.access(), base64::STANDARD);
        encoder.write_all(digest.as_ref())
            .map_err(|_err| SignError::InternalError("Failed to base64-encode SHA256 hash"))?;
    }
    Ok(buffer.finish())
}

fn get_signature_elements<'additional_headers, 'buffer, R: Request>(
        buffer: &'buffer mut Vec<SignatureElement<'additional_headers>>,
        request: &mut R,
        additional_headers_to_sign: impl Iterator<Item = &'additional_headers str>,
        ignore_body_for_signing: bool,
        allow_body_for_get: bool) -> Result<&'buffer [SignatureElement<'additional_headers>], SignError> {
    if request.method().is_body_mandatory() {
        if ignore_body_for_signing {
            buffer.extend_from_slice(request.method().required_object_storage_signing_elements());
        } else {
            buffer.extend_from_slice(request.method().required_non_object_storage_signing_elements());
        }
    } else {
        buffer.extend_from_slice(&BASIC_SIGNATURE_ELEMENTS[..]);
        if allow_body_for_get {
            buffer.extend_from_slice(&[
                SignatureElement::StandardHeader("content-length"),
                SignatureElement::StandardHeader("content-type"),
                SignatureElement::XContentSHA256
            ]);
        }
    }

    for name in additional_headers_to_sign {
        // Note that eq_header treats Date and X-Date as identical.
        let already_added = buffer.iter().any(|elem| elem.eq_header(name));
        if already_added {
            continue;
        }
        let value_count = request.headers().header_values(name).count();
        if value_count > 1 {
            return Err(SignError::MultivaluedHeader(Cow::Owned(name.to_string())));
        }
        if value_count == 0 {
            return Err(SignError::MissingAdditionalHeader(Cow::Owned(name.to_string())));
        }
        buffer.push(SignatureElement::StandardHeader(name));
    }

    Ok(buffer.as_slice())
}

fn append_concatenated_headers<H: Headers>(buffer: &mut Writer<u8>, header_name: &str, headers: &H) {
    buffer.access().extend_from_slice(header_name.as_bytes());
    buffer.access().extend_from_slice(b": ");
    if headers.header_values(header_name).any(|_| true) {
        for value in headers.header_values(header_name) {
            // If header value is a valid UTF-8 string, then trim it, otherwise use the raw bytes
            if let Ok(value_str) = std::str::from_utf8(value) {
                buffer.access().extend_from_slice(value_str.trim().as_bytes());
            } else {
                buffer.access().extend_from_slice(value);
            }
            buffer.access().extend_from_slice(b", ");
        }
        // remove last ", ". We know there is at least one.
        buffer.access().pop();
        buffer.access().pop();
        buffer.access().push(b'\n');
    }
}

fn calculate_signature_input<'buffer, R: Request>(
        buffer: &MarchingBuffer<u8>,
        signature_elements: &[SignatureElement],
        request: &mut R,
    ) -> Result<Reader<u8>, SignError> {
    let mut writer = buffer.get_writer();
    for element in signature_elements {
        match element {
            SignatureElement::Date => {
                if request.headers().contains_header("x-date") {
                    append_concatenated_headers(&mut writer, "x-date", request.headers());
                } else if request.headers().contains_header("date") {
                    append_concatenated_headers(&mut writer, "date", request.headers());
                } else {
                    return Err(SignError::InternalError("Neither Date nor X-Date header found, should have been added by inject_missing_headers"));
                }
                writer.access().push(b'\n');
            }
            SignatureElement::StandardHeader(name) => {
                append_concatenated_headers(&mut writer, name, request.headers());
                writer.access().push(b'\n');
            }
            SignatureElement::XContentSHA256 => {
                append_concatenated_headers(&mut writer, "x-content-sha256", request.headers());
                writer.access().push(b'\n');
            }
            SignatureElement::RequestTarget => {
                // TODO: url-encode the path and query string?
                writer.access().extend_from_slice(b"(request-target): ");
                writer.access().extend_from_slice(request.method().lowercase());
                writer.access().push(b' ');
                writer.access().extend_from_slice(request.path().as_bytes());
                if let Some(query) = request.query_string() {
                    writer.access().push(b'?');
                    writer.access().extend_from_slice(query.as_bytes());
                }
                writer.access().push(b'\n');
            }
        }
    }
    Ok(writer.finish())
}

fn build_authorization_header<R: Request>(
        buffer: &MarchingBuffer<u8>,
        base64_signature: Reader<u8>,
        request: &R,
        signature_elements: &[SignatureElement],
        key_id: &str
    ) -> Result<Reader<u8>, SignError> {
    let mut writer = buffer.get_writer();
    writer.access().extend_from_slice(b"Signature headers=\"");
    for element in signature_elements {
        match element {
            SignatureElement::Date => {
                if request.headers().contains_header("x-date") {
                    writer.access().extend_from_slice(b"x-date ");
                } else {
                    writer.access().extend_from_slice(b"date ");
                }
            }
            SignatureElement::StandardHeader(header_name) => {
                writer.access().extend_from_slice(header_name.as_bytes());
                writer.access().push(b' ');
            }
            SignatureElement::XContentSHA256 => {
                writer.access().extend_from_slice(b"x-content-sha256 ");
            }
            SignatureElement::RequestTarget => {
                writer.access().extend_from_slice(b"(request-target) ");
            }
        }
    }
    if !signature_elements.is_empty() {
        if writer.access().pop() != Some(b' ') {
            return Err(SignError::InternalError("Popped byte should have been a space"));
        }
    }
    writer.access().extend_from_slice(b"\",keyId=\"");
    writer.access().extend_from_slice(key_id.as_bytes());
    writer.access().extend_from_slice(b"\",algorithm=\"rsa-sha256\",signature=\"");
    writer.copy_from::<4096>(&base64_signature);
    writer.access().extend_from_slice(b"\",version=\"1\"");
    Ok(writer.finish())
}

fn sign_and_base64_encode(
        binary_buffer: &MarchingBuffer<u8>,
        signature_input: Reader<u8>,
        rng: &dyn ring::rand::SecureRandom,
        key: &ring::signature::RsaKeyPair) -> Result<Reader<u8>, SignError> {
    // 1024 bytes is enough for RSA-8192.
    let mut signature = [0u8; 1024];
    let signature = &mut signature[..key.public_modulus_len()];
    key.sign(&ring::signature::RSA_PKCS1_SHA256, rng, signature_input.access().as_slice(), signature)
        .map_err(|_| SignError::InternalError("Failed to compute RSA_PKCS1_SHA256 signature"))?;
    let mut writer = binary_buffer.get_writer();
    {
        let mut encoder = EncoderWriter::new(writer.access(), base64::STANDARD);
        encoder.write_all(signature)
            .map_err(|_err| SignError::InternalError("Failed to base64-encode the signature"))?;
    }
    Ok(writer.finish())
}