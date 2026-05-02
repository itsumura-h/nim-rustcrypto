use core::ffi::c_int;
use digest::Digest;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit as AeadKeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use hkdf::Hkdf;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use sha2::Sha256;
use sha3::{Keccak256, Sha3_256};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

mod aead_common;
mod ed25519_ops;
mod ed25519_pkcs8;
mod ed25519_pem;
mod oid;

pub const RUSTCRYPTO_OK: c_int = 0;
pub const RUSTCRYPTO_ERR_NULL_OUTPUT: c_int = 1;
pub const RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT: c_int = 2;
pub const RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA: c_int = 3;
pub const RUSTCRYPTO_ERR_INVALID_SECRET_KEY: c_int = 4;
pub const RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT: c_int = 5;
pub const RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST: c_int = 6;
pub const RUSTCRYPTO_ERR_INVALID_SIGNATURE: c_int = 7;
pub const RUSTCRYPTO_ERR_VERIFICATION_FAILED: c_int = 8;
pub const RUSTCRYPTO_ERR_INVALID_LENGTH: c_int = 9;
pub const RUSTCRYPTO_ERR_INVALID_PRK_LENGTH: c_int = 10;
pub const RUSTCRYPTO_ERR_AUTHENTICATION_FAILED: c_int = 11;
pub const RUSTCRYPTO_ERR_INVALID_KEY_LENGTH: c_int = 12;
pub const RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH: c_int = 13;
pub const RUSTCRYPTO_ERR_INVALID_TAG_LENGTH: c_int = 14;
pub const RUSTCRYPTO_ERR_INVALID_PARAMETER: c_int = 15;
pub const RUSTCRYPTO_ERR_PANIC: c_int = -1;

pub const SHA256_DIGEST_LEN: usize = 32;
pub const HMAC_SHA256_MAC_LEN: usize = 32;
pub const HKDF_SHA256_PRK_LEN: usize = SHA256_DIGEST_LEN;
pub const HKDF_SHA256_MAX_OKM_LEN: usize = SHA256_DIGEST_LEN * 255;
pub const CHACHA20POLY1305_KEY_LEN: usize = 32;
pub const CHACHA20POLY1305_NONCE_LEN: usize = 12;
pub const CHACHA20POLY1305_TAG_LEN: usize = 16;
pub const SHA3_256_DIGEST_LEN: usize = 32;
pub const KECCAK_256_DIGEST_LEN: usize = 32;
pub const SECP256K1_SECRET_KEY_LEN: usize = 32;
pub const SECP256K1_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
pub const SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
pub const SECP256K1_SIGNATURE_LEN: usize = 64;
pub const SECP256K1_SIGNATURE_DER_MAX_LEN: usize = 72;
pub const SECP256K1_MESSAGE_DIGEST_LEN: usize = 32;
pub const ED25519_PRIVATE_KEY_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const ED25519_PRIVATE_KEY_DER_MAX_LEN: usize = 48;
pub const ED25519_PUBLIC_KEY_DER_MAX_LEN: usize = 44;
pub const ED25519_PRIVATE_KEY_PEM_MAX_LEN: usize = 119;
pub const ED25519_PUBLIC_KEY_PEM_MAX_LEN: usize = 113;

fn hash_one_shot<D>(input: &[u8], output: &mut [u8]) -> c_int
where
    D: Digest,
{
    let mut hasher = D::new();
    hasher.update(input);
    let digest = hasher.finalize();
    output.copy_from_slice(digest.as_ref());
    RUSTCRYPTO_OK
}

fn hash_impl<D>(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    digest_len: usize,
) -> c_int
where
    D: Digest,
{
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < digest_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let input = if input_len == 0 {
        &[][..]
    } else {
        if input.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }

        unsafe { slice::from_raw_parts(input, input_len) }
    };

    let output = unsafe { slice::from_raw_parts_mut(output, digest_len) };

    hash_one_shot::<D>(input, output)
}

fn sha256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    hash_impl::<Sha256>(input, input_len, output, output_len, SHA256_DIGEST_LEN)
}

fn hmac_sha256_impl(
    key: *const u8,
    key_len: usize,
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < HMAC_SHA256_MAC_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let key = if key_len == 0 {
        &[][..]
    } else {
        if key.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }

        unsafe { slice::from_raw_parts(key, key_len) }
    };

    let message = if message_len == 0 {
        &[][..]
    } else {
        if message.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }

        unsafe { slice::from_raw_parts(message, message_len) }
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return RUSTCRYPTO_ERR_PANIC,
    };

    mac.update(message);
    let mac_bytes = mac.finalize().into_bytes();
    let output = unsafe { slice::from_raw_parts_mut(output, HMAC_SHA256_MAC_LEN) };
    output.copy_from_slice(mac_bytes.as_ref());
    RUSTCRYPTO_OK
}

fn hkdf_optional_slice<'a>(
    input: *const u8,
    input_len: usize,
) -> Result<Option<&'a [u8]>, c_int> {
    if input_len == 0 {
        Ok(None)
    } else if input.is_null() {
        Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(Some(unsafe { slice::from_raw_parts(input, input_len) }))
    }
}

fn hkdf_input_slice<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], c_int> {
    if input_len == 0 {
        Ok(&[])
    } else if input.is_null() {
        Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(unsafe { slice::from_raw_parts(input, input_len) })
    }
}

fn hkdf_prk_slice<'a>(prk: *const u8, prk_len: usize) -> Result<&'a [u8], c_int> {
    if prk_len < HKDF_SHA256_PRK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_PRK_LENGTH);
    }

    if prk.is_null() {
        Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(unsafe { slice::from_raw_parts(prk, prk_len) })
    }
}

fn hkdf_extract_impl(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < HKDF_SHA256_PRK_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let salt = match hkdf_optional_slice(salt, salt_len) {
        Ok(salt) => salt,
        Err(err) => return err,
    };
    let ikm = match hkdf_input_slice(ikm, ikm_len) {
        Ok(ikm) => ikm,
        Err(err) => return err,
    };

    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    let output = unsafe { slice::from_raw_parts_mut(output, HKDF_SHA256_PRK_LEN) };
    output.copy_from_slice(prk.as_ref());
    RUSTCRYPTO_OK
}

fn hkdf_expand_impl(
    prk: *const u8,
    prk_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len > HKDF_SHA256_MAX_OKM_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    let prk = match hkdf_prk_slice(prk, prk_len) {
        Ok(prk) => prk,
        Err(err) => return err,
    };
    let info = match hkdf_input_slice(info, info_len) {
        Ok(info) => info,
        Err(err) => return err,
    };

    let hkdf = match Hkdf::<Sha256>::from_prk(prk) {
        Ok(hkdf) => hkdf,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PRK_LENGTH,
    };

    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match hkdf.expand(info, output) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_LENGTH,
    }
}

fn hkdf_derive_impl(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len > HKDF_SHA256_MAX_OKM_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    let salt = match hkdf_optional_slice(salt, salt_len) {
        Ok(salt) => salt,
        Err(err) => return err,
    };
    let ikm = match hkdf_input_slice(ikm, ikm_len) {
        Ok(ikm) => ikm,
        Err(err) => return err,
    };
    let info = match hkdf_input_slice(info, info_len) {
        Ok(info) => info,
        Err(err) => return err,
    };

    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match hkdf.expand(info, output) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_LENGTH,
    }
}

fn chacha20poly1305_key(bytes: &[u8]) -> Key {
    bytes.iter().copied().collect()
}

fn chacha20poly1305_nonce(bytes: &[u8]) -> Nonce {
    bytes.iter().copied().collect()
}

fn chacha20poly1305_tag(bytes: &[u8]) -> Tag {
    bytes.iter().copied().collect()
}

fn chacha20poly1305_encrypt_impl(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: usize,
    tag: *mut u8,
    tag_len: usize,
) -> c_int {
    let key = match aead_common::fixed_input(
        key,
        key_len,
        CHACHA20POLY1305_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    ) {
        Ok(key) => key.to_vec(),
        Err(err) => return err,
    };

    let nonce = match aead_common::fixed_input(
        nonce,
        nonce_len,
        CHACHA20POLY1305_NONCE_LEN,
        RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH,
    ) {
        Ok(nonce) => nonce.to_vec(),
        Err(err) => return err,
    };

    let aad = match aead_common::optional_input(aad, aad_len) {
        Ok(aad) => aad.to_vec(),
        Err(err) => return err,
    };

    let plaintext = match aead_common::optional_input(plaintext, plaintext_len) {
        Ok(plaintext) => plaintext.to_vec(),
        Err(err) => return err,
    };

    let ciphertext = match aead_common::output_buffer(ciphertext, ciphertext_len, plaintext_len) {
        Ok(ciphertext) => ciphertext,
        Err(err) => return err,
    };

    let tag = match aead_common::output_buffer(tag, tag_len, CHACHA20POLY1305_TAG_LEN) {
        Ok(tag) => tag,
        Err(err) => return err,
    };

    let key = chacha20poly1305_key(&key);
    let nonce = chacha20poly1305_nonce(&nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    ciphertext.copy_from_slice(&plaintext);

    let tag_bytes = match cipher.encrypt_in_place_detached(&nonce, &aad, ciphertext) {
        Ok(tag_bytes) => tag_bytes,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };

    tag.copy_from_slice(&tag_bytes);
    RUSTCRYPTO_OK
}

fn chacha20poly1305_decrypt_impl(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    tag_len: usize,
    plaintext: *mut u8,
    plaintext_len: usize,
) -> c_int {
    let key = match aead_common::fixed_input(
        key,
        key_len,
        CHACHA20POLY1305_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    ) {
        Ok(key) => key.to_vec(),
        Err(err) => return err,
    };

    let nonce = match aead_common::fixed_input(
        nonce,
        nonce_len,
        CHACHA20POLY1305_NONCE_LEN,
        RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH,
    ) {
        Ok(nonce) => nonce.to_vec(),
        Err(err) => return err,
    };

    let aad = match aead_common::optional_input(aad, aad_len) {
        Ok(aad) => aad.to_vec(),
        Err(err) => return err,
    };

    let ciphertext = match aead_common::optional_input(ciphertext, ciphertext_len) {
        Ok(ciphertext) => ciphertext.to_vec(),
        Err(err) => return err,
    };

    let tag = match aead_common::fixed_input(
        tag,
        tag_len,
        CHACHA20POLY1305_TAG_LEN,
        RUSTCRYPTO_ERR_INVALID_TAG_LENGTH,
    ) {
        Ok(tag) => tag.to_vec(),
        Err(err) => return err,
    };

    let plaintext = match aead_common::output_buffer(plaintext, plaintext_len, ciphertext_len) {
        Ok(plaintext) => plaintext,
        Err(err) => return err,
    };

    let key = chacha20poly1305_key(&key);
    let nonce = chacha20poly1305_nonce(&nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    plaintext.copy_from_slice(&ciphertext);

    let tag = chacha20poly1305_tag(&tag);
    match cipher.decrypt_in_place_detached(&nonce, &aad, plaintext, &tag) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_AUTHENTICATION_FAILED,
    }
}

fn sha3_256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    hash_impl::<Sha3_256>(input, input_len, output, output_len, SHA3_256_DIGEST_LEN)
}

fn keccak_256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    hash_impl::<Keccak256>(input, input_len, output, output_len, KECCAK_256_DIGEST_LEN)
}

fn secp256k1_public_key_from_secret_key_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    let compressed = match compressed {
        0 => false,
        1 => true,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let required_len = if compressed {
        SECP256K1_PUBLIC_KEY_COMPRESSED_LEN
    } else {
        SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN
    };

    if output_len < required_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    if input_len == 0 {
        return RUSTCRYPTO_ERR_INVALID_SECRET_KEY;
    }

    if input.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }

    if input_len != SECP256K1_SECRET_KEY_LEN {
        return RUSTCRYPTO_ERR_INVALID_SECRET_KEY;
    }

    let secret_key_bytes = unsafe { slice::from_raw_parts(input, input_len) };
    let secret_key = match SecretKey::from_slice(secret_key_bytes) {
        Ok(secret_key) => secret_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(compressed);
    let encoded_bytes = encoded_point.as_bytes();
    let output = unsafe { slice::from_raw_parts_mut(output, required_len) };

    output.copy_from_slice(encoded_bytes);
    RUSTCRYPTO_OK
}

fn secp256k1_ecdsa_sign_prehash_impl(
    message_digest: *const u8,
    message_digest_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < SECP256K1_SIGNATURE_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    if message_digest_len != SECP256K1_MESSAGE_DIGEST_LEN {
        return RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST;
    }

    if message_digest.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }

    if secret_key_len != SECP256K1_SECRET_KEY_LEN {
        return RUSTCRYPTO_ERR_INVALID_SECRET_KEY;
    }

    if secret_key.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }

    let message_digest = unsafe { slice::from_raw_parts(message_digest, message_digest_len) };
    let secret_key_bytes = unsafe { slice::from_raw_parts(secret_key, secret_key_len) };
    let signing_key = match SigningKey::from_slice(secret_key_bytes) {
        Ok(signing_key) => signing_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let signature: Signature = match signing_key.sign_prehash(message_digest) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    };

    let output = unsafe { slice::from_raw_parts_mut(output, SECP256K1_SIGNATURE_LEN) };
    let signature_bytes = signature.to_bytes();
    output.copy_from_slice(signature_bytes.as_ref());
    RUSTCRYPTO_OK
}

fn secp256k1_ecdsa_verify_prehash_impl(
    message_digest: *const u8,
    message_digest_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    if message_digest_len != SECP256K1_MESSAGE_DIGEST_LEN {
        return RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST;
    }

    if message_digest.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }

    let public_key_format = match public_key_format {
        0 => SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN,
        1 => SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    if public_key_len != public_key_format {
        return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT;
    }

    if public_key.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }

    if signature_len != SECP256K1_SIGNATURE_LEN {
        return RUSTCRYPTO_ERR_INVALID_SIGNATURE;
    }

    if signature.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }

    let message_digest = unsafe { slice::from_raw_parts(message_digest, message_digest_len) };
    let public_key_bytes = unsafe { slice::from_raw_parts(public_key, public_key_len) };
    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key_bytes) {
        Ok(verifying_key) => verifying_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let signature_bytes = unsafe { slice::from_raw_parts(signature, signature_len) };
    let signature = match Signature::from_slice(signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    match verifying_key.verify_prehash(message_digest, &signature) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

fn secp256k1_ecdsa_signature_to_der_impl(
    signature: *const u8,
    signature_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let signature = match aead_common::fixed_input(
        signature,
        signature_len,
        SECP256K1_SIGNATURE_LEN,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let signature = match Signature::from_slice(signature) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    let der = signature.to_der();
    let der_bytes = der.as_bytes();
    let output = match aead_common::output_buffer(output, output_len, der_bytes.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };

    output.copy_from_slice(der_bytes);
    unsafe {
        *written_len = der_bytes.len();
    }
    RUSTCRYPTO_OK
}

fn secp256k1_ecdsa_signature_from_der_impl(
    der_signature: *const u8,
    der_signature_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let der_signature = match aead_common::optional_input(der_signature, der_signature_len) {
        Ok(der_signature) => der_signature,
        Err(err) => return err,
    };

    let signature = match Signature::from_der(der_signature) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    let output = match aead_common::output_buffer(output, output_len, SECP256K1_SIGNATURE_LEN) {
        Ok(output) => output,
        Err(err) => return err,
    };

    let raw_bytes = signature.to_bytes();
    output.copy_from_slice(raw_bytes.as_ref());
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_sha256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| sha256_impl(input, input_len, output, output_len)))
        .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hmac_sha256(
    key: *const u8,
    key_len: usize,
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hmac_sha256_impl(key, key_len, message, message_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hkdf_sha256_extract(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hkdf_extract_impl(salt, salt_len, ikm, ikm_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hkdf_sha256_expand(
    prk: *const u8,
    prk_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hkdf_expand_impl(prk, prk_len, info, info_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hkdf_sha256_derive(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hkdf_derive_impl(
            salt, salt_len, ikm, ikm_len, info, info_len, output, output_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_chacha20poly1305_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: usize,
    tag: *mut u8,
    tag_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        chacha20poly1305_encrypt_impl(
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            plaintext,
            plaintext_len,
            ciphertext,
            ciphertext_len,
            tag,
            tag_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_chacha20poly1305_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    tag_len: usize,
    plaintext: *mut u8,
    plaintext_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        chacha20poly1305_decrypt_impl(
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            tag,
            tag_len,
            plaintext,
            plaintext_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_sha3_256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| sha3_256_impl(input, input_len, output, output_len)))
        .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_keccak_256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| keccak_256_impl(input, input_len, output, output_len)))
        .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_public_key_from_secret_key(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_public_key_from_secret_key_impl(input, input_len, output, output_len, compressed)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_prehash(
    message_digest: *const u8,
    message_digest_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_prehash_impl(
            message_digest,
            message_digest_len,
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_prehash(
    message_digest: *const u8,
    message_digest_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_prehash_impl(
            message_digest,
            message_digest_len,
            public_key,
            public_key_len,
            public_key_format,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_signature_to_der(
    signature: *const u8,
    signature_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_signature_to_der_impl(signature, signature_len, output, output_len, written_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_signature_from_der(
    der_signature: *const u8,
    der_signature_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_signature_from_der_impl(der_signature, der_signature_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_private_key_to_pkcs8_der(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pkcs8::private_key_to_pkcs8_der_impl(
            private_key,
            private_key_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_private_key_from_pkcs8_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pkcs8::private_key_from_pkcs8_der_impl(der, der_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_to_spki_der(
    public_key: *const u8,
    public_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pkcs8::public_key_to_spki_der_impl(
            public_key,
            public_key_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_from_spki_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pkcs8::public_key_from_spki_der_impl(der, der_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_from_secret_key(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_ops::public_key_from_secret_key_impl(
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_sign(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_ops::sign_impl(
            message,
            message_len,
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_verify(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_ops::verify_impl(
            message,
            message_len,
            public_key,
            public_key_len,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_private_key_to_pkcs8_pem(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pem::private_key_to_pkcs8_pem_impl(
            private_key,
            private_key_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_private_key_from_pkcs8_pem(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pem::private_key_from_pkcs8_pem_impl(pem, pem_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_to_spki_pem(
    public_key: *const u8,
    public_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pem::public_key_to_spki_pem_impl(
            public_key,
            public_key_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_from_spki_pem(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ed25519_pem::public_key_from_spki_pem_impl(pem, pem_len, output, output_len)
    }))
    .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_hex(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut hex, "{:02x}", byte).expect("write to string");
        }
        hex
    }

    #[test]
    fn sha256_abc_matches_known_vector() {
        let input = b"abc";
        let mut output = [0u8; SHA256_DIGEST_LEN];

        let status = rustcrypto_sha256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty_matches_known_vector() {
        let mut output = [0u8; SHA256_DIGEST_LEN];

        let status = rustcrypto_sha256(
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_rejects_null_output() {
        let input = b"abc";

        let status = rustcrypto_sha256(input.as_ptr(), input.len(), core::ptr::null_mut(), 32);

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
    }

    #[test]
    fn sha256_rejects_short_output_buffer() {
        let input = b"abc";
        let mut output = [0u8; SHA256_DIGEST_LEN - 1];

        let status = rustcrypto_sha256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn sha256_rejects_null_input_with_data() {
        let mut output = [0u8; SHA256_DIGEST_LEN];

        let status = rustcrypto_sha256(
            core::ptr::null(),
            1,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn hmac_sha256_empty_key_and_message_matches_known_vector() {
        let mut output = [0u8; HMAC_SHA256_MAC_LEN];

        let status = rustcrypto_hmac_sha256(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }

    #[test]
    fn hmac_sha256_rfc_4231_case_1_matches_known_vector() {
        let key = [0x0b; 20];
        let message = b"Hi There";
        let mut output = [0u8; HMAC_SHA256_MAC_LEN];

        let status = rustcrypto_hmac_sha256(
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_rfc_4231_case_2_matches_known_vector() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let mut output = [0u8; HMAC_SHA256_MAC_LEN];

        let status = rustcrypto_hmac_sha256(
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_rejects_null_output() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";

        let status = rustcrypto_hmac_sha256(
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            core::ptr::null_mut(),
            HMAC_SHA256_MAC_LEN,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
    }

    #[test]
    fn hmac_sha256_rejects_short_output_buffer() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let mut output = [0u8; HMAC_SHA256_MAC_LEN - 1];

        let status = rustcrypto_hmac_sha256(
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn hmac_sha256_rejects_null_key_with_data() {
        let message = b"what do ya want for nothing?";
        let mut output = [0u8; HMAC_SHA256_MAC_LEN];

        let status = rustcrypto_hmac_sha256(
            core::ptr::null(),
            1,
            message.as_ptr(),
            message.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn hmac_sha256_rejects_null_message_with_data() {
        let key = b"Jefe";
        let mut output = [0u8; HMAC_SHA256_MAC_LEN];

        let status = rustcrypto_hmac_sha256(
            key.as_ptr(),
            key.len(),
            core::ptr::null(),
            1,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn hkdf_sha256_extract_matches_rfc_5869_case_1_prk() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let mut output = [0u8; HKDF_SHA256_PRK_LEN];

        let status = rustcrypto_hkdf_sha256_extract(
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
    }

    #[test]
    fn hkdf_sha256_expand_matches_rfc_5869_case_1_okm() {
        let prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];
        let mut output = [0u8; 42];

        let status = rustcrypto_hkdf_sha256_expand(
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha256_derive_matches_rfc_5869_case_3_okm() {
        let ikm = [0x0bu8; 22];
        let mut output = [0u8; 42];

        let status = rustcrypto_hkdf_sha256_derive(
            core::ptr::null(),
            0,
            ikm.as_ptr(),
            ikm.len(),
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_sha256_extract_rejects_short_output_buffer() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let mut output = [0u8; HKDF_SHA256_PRK_LEN - 1];

        let status = rustcrypto_hkdf_sha256_extract(
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn hkdf_sha256_expand_rejects_short_prk() {
        let prk = [0x07u8; HKDF_SHA256_PRK_LEN - 1];
        let info = [0xf0u8; 10];
        let mut output = [0u8; 42];

        let status = rustcrypto_hkdf_sha256_expand(
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PRK_LENGTH);
    }

    #[test]
    fn hkdf_sha256_derive_rejects_invalid_length() {
        let ikm = [0x0bu8; 22];
        let mut output = [0u8; 1];

        let status = rustcrypto_hkdf_sha256_derive(
            core::ptr::null(),
            0,
            ikm.as_ptr(),
            ikm.len(),
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            HKDF_SHA256_MAX_OKM_LEN + 1,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    #[test]
    fn hkdf_sha256_derive_rejects_null_ikm_with_data() {
        let mut output = [0u8; 42];

        let status = rustcrypto_hkdf_sha256_derive(
            core::ptr::null(),
            0,
            core::ptr::null(),
            1,
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit"),
            }
        }

        assert_eq!(hex.len() % 2, 0);
        let bytes = hex.as_bytes();
        let mut output = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0;
        while index < bytes.len() {
            output.push((nibble(bytes[index]) << 4) | nibble(bytes[index + 1]));
            index += 2;
        }
        output
    }

    #[test]
    fn chacha20poly1305_encrypt_matches_rfc_8439_vector() {
        let key = hex_bytes(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        let nonce = hex_bytes("070000004041424344454647");
        let aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; CHACHA20POLY1305_TAG_LEN];

        let status = rustcrypto_chacha20poly1305_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            tag.as_mut_ptr(),
            tag.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&ciphertext),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(digest_hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");
    }

    #[test]
    fn chacha20poly1305_decrypt_matches_rfc_8439_vector() {
        let key = hex_bytes(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        let nonce = hex_bytes("070000004041424344454647");
        let aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
        let ciphertext = hex_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let tag = hex_bytes("1ae10b594f09e26a7e902ecbd0600691");
        let mut plaintext = vec![0u8; ciphertext.len()];

        let status = rustcrypto_chacha20poly1305_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.as_ptr(),
            tag.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            plaintext,
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        );
    }

    #[test]
    fn chacha20poly1305_decrypt_rejects_tampered_tag() {
        let key = hex_bytes(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        let nonce = hex_bytes("070000004041424344454647");
        let aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
        let ciphertext = hex_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let mut tag = hex_bytes("1ae10b594f09e26a7e902ecbd0600691");
        let mut plaintext = vec![0u8; ciphertext.len()];
        tag[0] ^= 0x01;

        let status = rustcrypto_chacha20poly1305_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.as_ptr(),
            tag.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_AUTHENTICATION_FAILED);
    }

    #[test]
    fn chacha20poly1305_encrypt_rejects_short_output_buffer() {
        let key = hex_bytes(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        let nonce = hex_bytes("070000004041424344454647");
        let aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ciphertext = vec![0u8; plaintext.len() - 1];
        let mut tag = [0u8; CHACHA20POLY1305_TAG_LEN];

        let status = rustcrypto_chacha20poly1305_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            tag.as_mut_ptr(),
            tag.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn sha3_256_abc_matches_known_vector() {
        let input = b"abc";
        let mut output = [0u8; SHA3_256_DIGEST_LEN];

        let status = rustcrypto_sha3_256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn sha3_256_empty_matches_known_vector() {
        let mut output = [0u8; SHA3_256_DIGEST_LEN];

        let status = rustcrypto_sha3_256(
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn sha3_256_rejects_null_output() {
        let input = b"abc";

        let status = rustcrypto_sha3_256(input.as_ptr(), input.len(), core::ptr::null_mut(), 32);

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
    }

    #[test]
    fn sha3_256_rejects_null_input_with_data() {
        let mut output = [0u8; SHA3_256_DIGEST_LEN];

        let status = rustcrypto_sha3_256(
            core::ptr::null(),
            1,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn keccak_256_abc_matches_known_vector() {
        let input = b"abc";
        let mut output = [0u8; KECCAK_256_DIGEST_LEN];

        let status = rustcrypto_keccak_256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn keccak_256_empty_matches_known_vector() {
        let mut output = [0u8; KECCAK_256_DIGEST_LEN];

        let status = rustcrypto_keccak_256(
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn keccak_256_rejects_short_output_buffer() {
        let input = b"abc";
        let mut output = [0u8; KECCAK_256_DIGEST_LEN - 1];

        let status = rustcrypto_keccak_256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn secp256k1_public_key_from_secret_key_compressed_matches_known_vector() {
        let mut secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        secret_key[31] = 1;
        let mut output = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];

        let status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
            1,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn secp256k1_public_key_from_secret_key_uncompressed_matches_known_vector() {
        let mut secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        secret_key[31] = 1;
        let mut output = [0u8; SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN];

        let status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
            0,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
    }

    #[test]
    fn secp256k1_public_key_from_secret_key_rejects_null_output() {
        let mut secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        secret_key[31] = 1;

        let status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            core::ptr::null_mut(),
            SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
            1,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
    }

    #[test]
    fn secp256k1_public_key_from_secret_key_rejects_short_output_buffer() {
        let mut secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        secret_key[31] = 1;
        let mut output = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN - 1];

        let status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
            1,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn secp256k1_public_key_from_secret_key_rejects_null_input_with_data() {
        let mut output = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];

        let status = rustcrypto_secp256k1_public_key_from_secret_key(
            core::ptr::null(),
            SECP256K1_SECRET_KEY_LEN,
            output.as_mut_ptr(),
            output.len(),
            1,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn secp256k1_public_key_from_secret_key_rejects_invalid_secret_key() {
        let secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        let mut output = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];

        let status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
            1,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_SECRET_KEY);
    }

    #[test]
    fn secp256k1_public_key_from_secret_key_rejects_invalid_format_flag() {
        let mut secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        secret_key[31] = 1;
        let mut output = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];

        let status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
            2,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT);
    }

    #[test]
    fn secp256k1_ecdsa_sign_prehash_matches_known_vector() {
        let secret_key = {
            let mut bytes = [0u8; SECP256K1_SECRET_KEY_LEN];
            bytes[31] = 1;
            bytes
        };
        let message_digest = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let mut output = [0u8; SECP256K1_SIGNATURE_LEN];

        let status = rustcrypto_secp256k1_ecdsa_sign_prehash(
            message_digest.as_ptr(),
            message_digest.len(),
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "75601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c28ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"
        );
    }

    #[test]
    fn secp256k1_ecdsa_verify_prehash_accepts_valid_signature() {
        let secret_key = {
            let mut bytes = [0u8; SECP256K1_SECRET_KEY_LEN];
            bytes[31] = 1;
            bytes
        };
        let message_digest = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let mut public_key = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];
        let mut signature = [0u8; SECP256K1_SIGNATURE_LEN];

        let sign_status = rustcrypto_secp256k1_ecdsa_sign_prehash(
            message_digest.as_ptr(),
            message_digest.len(),
            secret_key.as_ptr(),
            secret_key.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );

        assert_eq!(sign_status, RUSTCRYPTO_OK);

        let public_key_status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            1,
        );

        assert_eq!(public_key_status, RUSTCRYPTO_OK);

        let verify_status = rustcrypto_secp256k1_ecdsa_verify_prehash(
            message_digest.as_ptr(),
            message_digest.len(),
            public_key.as_ptr(),
            public_key.len(),
            1,
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(verify_status, RUSTCRYPTO_OK);
    }

    #[test]
    fn secp256k1_ecdsa_verify_prehash_rejects_tampered_signature() {
        let secret_key = {
            let mut bytes = [0u8; SECP256K1_SECRET_KEY_LEN];
            bytes[31] = 1;
            bytes
        };
        let message_digest = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let mut public_key = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];
        let mut signature = [0u8; SECP256K1_SIGNATURE_LEN];

        let sign_status = rustcrypto_secp256k1_ecdsa_sign_prehash(
            message_digest.as_ptr(),
            message_digest.len(),
            secret_key.as_ptr(),
            secret_key.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );

        assert_eq!(sign_status, RUSTCRYPTO_OK);

        let public_key_status = rustcrypto_secp256k1_public_key_from_secret_key(
            secret_key.as_ptr(),
            secret_key.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            1,
        );

        assert_eq!(public_key_status, RUSTCRYPTO_OK);

        signature[0] ^= 0x01;

        let verify_status = rustcrypto_secp256k1_ecdsa_verify_prehash(
            message_digest.as_ptr(),
            message_digest.len(),
            public_key.as_ptr(),
            public_key.len(),
            1,
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(verify_status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);
    }
}
