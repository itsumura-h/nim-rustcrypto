use core::ffi::c_int;
use digest::Digest;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use sha2::Sha256;
use sha3::{Keccak256, Sha3_256};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

pub const RUSTCRYPTO_OK: c_int = 0;
pub const RUSTCRYPTO_ERR_NULL_OUTPUT: c_int = 1;
pub const RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT: c_int = 2;
pub const RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA: c_int = 3;
pub const RUSTCRYPTO_ERR_INVALID_SECRET_KEY: c_int = 4;
pub const RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT: c_int = 5;
pub const RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST: c_int = 6;
pub const RUSTCRYPTO_ERR_INVALID_SIGNATURE: c_int = 7;
pub const RUSTCRYPTO_ERR_VERIFICATION_FAILED: c_int = 8;
pub const RUSTCRYPTO_ERR_PANIC: c_int = -1;

pub const SHA256_DIGEST_LEN: usize = 32;
pub const SHA3_256_DIGEST_LEN: usize = 32;
pub const KECCAK_256_DIGEST_LEN: usize = 32;
pub const SECP256K1_SECRET_KEY_LEN: usize = 32;
pub const SECP256K1_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
pub const SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
pub const SECP256K1_SIGNATURE_LEN: usize = 64;
pub const SECP256K1_MESSAGE_DIGEST_LEN: usize = 32;

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
