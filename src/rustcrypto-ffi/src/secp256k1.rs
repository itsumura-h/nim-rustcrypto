use crate::{
    RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST, RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    RUSTCRYPTO_ERR_INVALID_SECRET_KEY, RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_NULL_OUTPUT,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
    SECP256K1_MESSAGE_DIGEST_LEN, SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
    SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN, SECP256K1_SECRET_KEY_LEN, SECP256K1_SIGNATURE_LEN,
    aead_common,
};
use ::digest::Digest;
use ::k256::SecretKey;
use ::k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ::k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ::k256::elliptic_curve::sec1::ToEncodedPoint;
use ::sha2::Sha256;
use ::sha3::{Keccak256, Sha3_256};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) fn public_key_from_secret_key_impl(
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

    let secret_key_bytes = unsafe { core::slice::from_raw_parts(input, input_len) };
    let secret_key = match SecretKey::from_slice(secret_key_bytes) {
        Ok(secret_key) => secret_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(compressed);
    let encoded_bytes = encoded_point.as_bytes();
    let output = unsafe { core::slice::from_raw_parts_mut(output, required_len) };

    output.copy_from_slice(encoded_bytes);
    RUSTCRYPTO_OK
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
        public_key_from_secret_key_impl(input, input_len, output, output_len, compressed)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn secp256k1_ecdsa_sign_message_impl<D: Digest>(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let message_digest = D::digest(message);
    let message_digest: &[u8] = message_digest.as_ref();

    secp256k1_ecdsa_sign_prehash_impl(
        message_digest.as_ptr(),
        message_digest.len(),
        secret_key,
        secret_key_len,
        output,
        output_len,
    )
}

fn secp256k1_ecdsa_verify_message_impl<D: Digest>(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let message_digest = D::digest(message);
    let message_digest: &[u8] = message_digest.as_ref();

    secp256k1_ecdsa_verify_prehash_impl(
        message_digest.as_ptr(),
        message_digest.len(),
        public_key,
        public_key_len,
        public_key_format,
        signature,
        signature_len,
    )
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

    let message_digest = match aead_common::fixed_input(
        message_digest,
        message_digest_len,
        SECP256K1_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let secret_key_bytes = match aead_common::fixed_input(
        secret_key,
        secret_key_len,
        SECP256K1_SECRET_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    ) {
        Ok(secret_key_bytes) => secret_key_bytes,
        Err(err) => return err,
    };

    let signing_key = match SigningKey::from_slice(secret_key_bytes) {
        Ok(signing_key) => signing_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let signature: Signature = match signing_key.sign_prehash(message_digest) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    };

    let output = unsafe { core::slice::from_raw_parts_mut(output, SECP256K1_SIGNATURE_LEN) };
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
    let message_digest = match aead_common::fixed_input(
        message_digest,
        message_digest_len,
        SECP256K1_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let public_key_format = match public_key_format {
        0 => SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN,
        1 => SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let public_key_bytes = match aead_common::fixed_input(
        public_key,
        public_key_len,
        public_key_format,
        RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    ) {
        Ok(public_key_bytes) => public_key_bytes,
        Err(err) => return err,
    };

    let signature = match aead_common::fixed_input(
        signature,
        signature_len,
        SECP256K1_SIGNATURE_LEN,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key_bytes) {
        Ok(verifying_key) => verifying_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let signature = match Signature::from_slice(signature) {
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
        return crate::RUSTCRYPTO_ERR_INVALID_PARAMETER;
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
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_sha256(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_message_impl::<Sha256>(
            message,
            message_len,
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_sha3_256(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_message_impl::<Sha3_256>(
            message,
            message_len,
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_keccak_256(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_message_impl::<Keccak256>(
            message,
            message_len,
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
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
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_sha256(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_message_impl::<Sha256>(
            message,
            message_len,
            public_key,
            public_key_len,
            public_key_format,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_sha3_256(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_message_impl::<Sha3_256>(
            message,
            message_len,
            public_key,
            public_key_len,
            public_key_format,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_keccak_256(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_message_impl::<Keccak256>(
            message,
            message_len,
            public_key,
            public_key_len,
            public_key_format,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
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
        secp256k1_ecdsa_signature_to_der_impl(
            signature,
            signature_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_signature_from_der(
    der_signature: *const u8,
    der_signature_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_signature_from_der_impl(
            der_signature,
            der_signature_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}
