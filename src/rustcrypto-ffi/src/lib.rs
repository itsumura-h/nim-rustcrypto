use core::ffi::c_int;
use digest::Digest;
use sha2::Sha256;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

pub const RUSTCRYPTO_OK: c_int = 0;
pub const RUSTCRYPTO_ERR_NULL_OUTPUT: c_int = 1;
pub const RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT: c_int = 2;
pub const RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA: c_int = 3;
pub const RUSTCRYPTO_ERR_PANIC: c_int = -1;

pub const SHA256_DIGEST_LEN: usize = 32;

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

fn sha256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < SHA256_DIGEST_LEN {
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

    let output = unsafe { slice::from_raw_parts_mut(output, SHA256_DIGEST_LEN) };

    hash_one_shot::<Sha256>(input, output)
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
}
