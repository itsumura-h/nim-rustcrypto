//! BLS12-381 curve operations and `bls-signatures`-style signing APIs (FFI implementation).
//!
//! Scalar encoding matches `bls12_381::Scalar` / `bls-signatures`: 32-byte **little-endian**
//! canonical field element representation.

use crate::{
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_ERR_RANDOM_FAILED, RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_OK, aead_common,
};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{
    multi_miller_loop, pairing, Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
    Scalar,
};
use ff::{Field, PrimeField};
use group::Curve;
use hkdf::Hkdf;
use pairing::MultiMillerLoop;
#[cfg(not(target_arch = "wasm32"))]
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use sha2_htc::Sha256 as Sha256Htc;
use core::ffi::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const BLS12_381_SCALAR_LEN: usize = 32;
pub const BLS12_381_G1_COMPRESSED_LEN: usize = 48;
pub const BLS12_381_G1_UNCOMPRESSED_LEN: usize = 96;
pub const BLS12_381_G2_COMPRESSED_LEN: usize = 96;
pub const BLS12_381_G2_UNCOMPRESSED_LEN: usize = 192;

const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const KEYGEN_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

fn compressed_flag(compressed: c_int) -> Result<bool, c_int> {
    match compressed {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
    }
}

fn read_scalar(bytes: &[u8; BLS12_381_SCALAR_LEN]) -> Result<Scalar, c_int> {
    Option::from(Scalar::from_bytes(bytes)).ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)
}

fn hash_to_g2(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256Htc>>>::hash_to_curve(msg, CSUITE)
}

fn key_gen_from_ikm(ikm: &[u8]) -> Result<Scalar, c_int> {
    if ikm.len() < 32 {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut msg = ikm.to_vec();
    msg.push(0);
    let hk = Hkdf::<Sha256>::new(Some(KEYGEN_SALT), &msg);
    let mut okm = [0u8; 48];
    hk.expand(&[0u8, 48u8], &mut okm)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)?;
    let mut wide = [0u8; 64];
    wide[16..].copy_from_slice(&okm);
    wide.reverse();
    Ok(Scalar::from_bytes_wide(&wide))
}

fn g1_decode(point: &[u8], compressed: bool) -> Result<G1Affine, c_int> {
    if compressed {
        if point.len() != BLS12_381_G1_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let mut arr = [0u8; BLS12_381_G1_COMPRESSED_LEN];
        arr.copy_from_slice(point);
        Option::from(G1Affine::from_compressed(&arr)).ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    } else if point.len() == BLS12_381_G1_UNCOMPRESSED_LEN {
        let mut arr = [0u8; BLS12_381_G1_UNCOMPRESSED_LEN];
        arr.copy_from_slice(point);
        Option::from(G1Affine::from_uncompressed(&arr)).ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    } else {
        Err(RUSTCRYPTO_ERR_INVALID_LENGTH)
    }
}

fn g2_decode(point: &[u8], compressed: bool) -> Result<G2Affine, c_int> {
    if compressed {
        if point.len() != BLS12_381_G2_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let mut arr = [0u8; BLS12_381_G2_COMPRESSED_LEN];
        arr.copy_from_slice(point);
        Option::from(G2Affine::from_compressed(&arr)).ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    } else if point.len() == BLS12_381_G2_UNCOMPRESSED_LEN {
        let mut arr = [0u8; BLS12_381_G2_UNCOMPRESSED_LEN];
        arr.copy_from_slice(point);
        Option::from(G2Affine::from_uncompressed(&arr)).ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    } else {
        Err(RUSTCRYPTO_ERR_INVALID_LENGTH)
    }
}

fn g1_encode_affine(p: &G1Affine, compressed: bool, out: &mut [u8]) -> Result<(), c_int> {
    if compressed {
        if out.len() < BLS12_381_G1_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        out[..BLS12_381_G1_COMPRESSED_LEN].copy_from_slice(&p.to_compressed());
    } else {
        if out.len() < BLS12_381_G1_UNCOMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        out[..BLS12_381_G1_UNCOMPRESSED_LEN].copy_from_slice(&p.to_uncompressed());
    }
    Ok(())
}

fn g2_encode_affine(p: &G2Affine, compressed: bool, out: &mut [u8]) -> Result<(), c_int> {
    if compressed {
        if out.len() < BLS12_381_G2_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        out[..BLS12_381_G2_COMPRESSED_LEN].copy_from_slice(&p.to_compressed());
    } else {
        if out.len() < BLS12_381_G2_UNCOMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        out[..BLS12_381_G2_UNCOMPRESSED_LEN].copy_from_slice(&p.to_uncompressed());
    }
    Ok(())
}

fn verify_aggregate_impl(
    signature: &G2Affine,
    hashes: &[G2Projective],
    public_keys: &[G1Projective],
) -> c_int {
    if hashes.is_empty() || public_keys.is_empty() {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    if hashes.len() != public_keys.len() {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    if hashes.len() == 1 && bool::from(public_keys[0].is_identity()) {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            if hashes[i] == hashes[j] {
                return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
            }
        }
    }

    let mut ml = bls12_381::MillerLoopResult::default();
    let mut ok = true;
    for (pk, h) in public_keys.iter().zip(hashes.iter()) {
        if bool::from(pk.is_identity()) {
            ok = false;
        }
        let pk_a = pk.to_affine();
        let h_prep = G2Prepared::from(G2Affine::from(h));
        ml = ml + Bls12::multi_miller_loop(&[(&pk_a, &h_prep)]);
    }
    if !ok {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    let g1_neg = -G1Affine::generator();
    let sig_prep = G2Prepared::from(*signature);
    ml = ml + Bls12::multi_miller_loop(&[(&g1_neg, &sig_prep)]);
    if ml.final_exponentiation() == Gt::identity() {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

// --- FFI: scalar ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_validate(scalar: *const u8, scalar_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_validate_impl(scalar, scalar_len))).unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_validate_impl(scalar: *const u8, scalar_len: usize) -> c_int {
    let s = match aead_common::fixed_input(
        scalar,
        scalar_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut arr = [0u8; BLS12_381_SCALAR_LEN];
    arr.copy_from_slice(s);
    if read_scalar(&arr).is_err() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_random(output: *mut u8, output_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_random_impl(output, output_len))).unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_random_impl(output: *mut u8, output_len: usize) -> c_int {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (output, output_len);
        return RUSTCRYPTO_ERR_RANDOM_FAILED;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let s = Scalar::random(&mut OsRng);
        out.copy_from_slice(&s.to_bytes());
        RUSTCRYPTO_OK
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_add(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_binop_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, |a, b| a + b)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_mul(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_binop_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, |a, b| a * b)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_binop_impl(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    op: impl FnOnce(Scalar, Scalar) -> Scalar,
) -> c_int {
    let lb = match aead_common::fixed_input(
        lhs,
        lhs_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let rb = match aead_common::fixed_input(
        rhs,
        rhs_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut la = [0u8; BLS12_381_SCALAR_LEN];
    let mut ra = [0u8; BLS12_381_SCALAR_LEN];
    la.copy_from_slice(lb);
    ra.copy_from_slice(rb);
    let a = match read_scalar(&la) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let b = match read_scalar(&ra) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
        Ok(o) => o,
        Err(e) => return e,
    };
    out.copy_from_slice(&op(a, b).to_bytes());
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_invert(
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_invert_impl(scalar, scalar_len, output, output_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_invert_impl(scalar: *const u8, scalar_len: usize, output: *mut u8, output_len: usize) -> c_int {
    let sb = match aead_common::fixed_input(
        scalar,
        scalar_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut arr = [0u8; BLS12_381_SCALAR_LEN];
    arr.copy_from_slice(sb);
    let s = match read_scalar(&arr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if bool::from(s.is_zero()) {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    let inv: Scalar = match Option::from(s.invert()) {
        Some(x) => x,
        None => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
        Ok(o) => o,
        Err(e) => return e,
    };
    out.copy_from_slice(&inv.to_bytes());
    RUSTCRYPTO_OK
}

// --- FFI: G1 / G2 generators ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_generator(
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let req = if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        };
        let out = match aead_common::output_buffer(output, output_len, req) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let g = G1Affine::generator();
        if g1_encode_affine(&g, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_generator(
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let req = if compressed {
            BLS12_381_G2_COMPRESSED_LEN
        } else {
            BLS12_381_G2_UNCOMPRESSED_LEN
        };
        let out = match aead_common::output_buffer(output, output_len, req) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let g = G2Affine::generator();
        if g2_encode_affine(&g, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

// --- validate / add / neg / mul ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_validate(
    point: *const u8,
    point_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let plen = if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        };
        let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
            Ok(b) => b,
            Err(e) => return e,
        };
        if g1_decode(pb, compressed).is_err() {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_validate(
    point: *const u8,
    point_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let plen = if compressed {
            BLS12_381_G2_COMPRESSED_LEN
        } else {
            BLS12_381_G2_UNCOMPRESSED_LEN
        };
        let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
            Ok(b) => b,
            Err(e) => return e,
        };
        if g2_decode(pb, compressed).is_err() {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_add(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        g1_g2_add_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, compressed, true)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_add(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        g1_g2_add_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, compressed, false)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g1_g2_add_impl(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
    is_g1: bool,
) -> c_int {
    let compressed = match compressed_flag(compressed) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let plen = if is_g1 {
        if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        }
    } else if compressed {
        BLS12_381_G2_COMPRESSED_LEN
    } else {
        BLS12_381_G2_UNCOMPRESSED_LEN
    };
    let lb = match aead_common::fixed_input(lhs, lhs_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let rb = match aead_common::fixed_input(rhs, rhs_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, plen) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if is_g1 {
        let a = match g1_decode(lb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let b = match g1_decode(rb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let sum = G1Projective::from(a) + G1Projective::from(b);
        let aff = sum.to_affine();
        if g1_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    } else {
        let a = match g2_decode(lb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let b = match g2_decode(rb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let sum = G2Projective::from(a) + G2Projective::from(b);
        let aff = sum.to_affine();
        if g2_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_neg(
    point: *const u8,
    point_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g_neg_impl(point, point_len, output, output_len, compressed, true)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_neg(
    point: *const u8,
    point_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g_neg_impl(point, point_len, output, output_len, compressed, false)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g_neg_impl(
    point: *const u8,
    point_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
    is_g1: bool,
) -> c_int {
    let compressed = match compressed_flag(compressed) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let plen = if is_g1 {
        if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        }
    } else if compressed {
        BLS12_381_G2_COMPRESSED_LEN
    } else {
        BLS12_381_G2_UNCOMPRESSED_LEN
    };
    let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, plen) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if is_g1 {
        let p = match g1_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let n = -G1Projective::from(p);
        let aff = n.to_affine();
        if g1_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    } else {
        let p = match g2_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let n = -G2Projective::from(p);
        let aff = n.to_affine();
        if g2_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_mul(
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g_mul_impl(point, point_len, scalar, scalar_len, output, output_len, compressed, true)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_mul(
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g_mul_impl(point, point_len, scalar, scalar_len, output, output_len, compressed, false)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g_mul_impl(
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
    is_g1: bool,
) -> c_int {
    let compressed = match compressed_flag(compressed) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let plen = if is_g1 {
        if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        }
    } else if compressed {
        BLS12_381_G2_COMPRESSED_LEN
    } else {
        BLS12_381_G2_UNCOMPRESSED_LEN
    };
    let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let sb = match aead_common::fixed_input(
        scalar,
        scalar_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut sa = [0u8; BLS12_381_SCALAR_LEN];
    sa.copy_from_slice(sb);
    let s = match read_scalar(&sa) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, plen) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if is_g1 {
        let p = match g1_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let r = G1Projective::from(p) * s;
        let aff = r.to_affine();
        if g1_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    } else {
        let p = match g2_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let r = G2Projective::from(p) * s;
        let aff = r.to_affine();
        if g2_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    }
    RUSTCRYPTO_OK
}

// --- pairing ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_pairing_eq(
    g1_lhs: *const u8,
    g1_lhs_len: usize,
    g2_lhs: *const u8,
    g2_lhs_len: usize,
    g1_rhs: *const u8,
    g1_rhs_len: usize,
    g2_rhs: *const u8,
    g2_rhs_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| pairing_eq_impl(
        g1_lhs, g1_lhs_len, g2_lhs, g2_lhs_len, g1_rhs, g1_rhs_len, g2_rhs, g2_rhs_len,
    )))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn pairing_eq_impl(
    g1_lhs: *const u8,
    g1_lhs_len: usize,
    g2_lhs: *const u8,
    g2_lhs_len: usize,
    g1_rhs: *const u8,
    g1_rhs_len: usize,
    g2_rhs: *const u8,
    g2_rhs_len: usize,
) -> c_int {
    let a1b = match aead_common::fixed_input(
        g1_lhs,
        g1_lhs_len,
        BLS12_381_G1_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let a2b = match aead_common::fixed_input(
        g2_lhs,
        g2_lhs_len,
        BLS12_381_G2_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let b1b = match aead_common::fixed_input(
        g1_rhs,
        g1_rhs_len,
        BLS12_381_G1_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let b2b = match aead_common::fixed_input(
        g2_rhs,
        g2_rhs_len,
        BLS12_381_G2_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let a1 = match g1_decode(a1b, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let a2 = match g2_decode(a2b, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let b1 = match g1_decode(b1b, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let b2 = match g2_decode(b2b, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let p1 = pairing(&a1, &a2);
    let p2 = pairing(&b1, &b2);
    if p1 == p2 {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_pairing_product_is_identity(
    g1_points: *const u8,
    g1_points_len: usize,
    g2_points: *const u8,
    g2_points_len: usize,
    pair_count: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| pairing_product_identity_impl(
        g1_points,
        g1_points_len,
        g2_points,
        g2_points_len,
        pair_count,
    )))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn pairing_product_identity_impl(
    g1_points: *const u8,
    g1_points_len: usize,
    g2_points: *const u8,
    g2_points_len: usize,
    pair_count: usize,
) -> c_int {
    if pair_count == 0 {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    let expect_g1 = match pair_count.checked_mul(BLS12_381_G1_COMPRESSED_LEN) {
        Some(v) => v,
        None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
    };
    let expect_g2 = match pair_count.checked_mul(BLS12_381_G2_COMPRESSED_LEN) {
        Some(v) => v,
        None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
    };
    if g1_points_len != expect_g1 || g2_points_len != expect_g2 {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    if g1_points.is_null() || g2_points.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }
    let g1s = unsafe { core::slice::from_raw_parts(g1_points, g1_points_len) };
    let g2s = unsafe { core::slice::from_raw_parts(g2_points, g2_points_len) };
    let mut g1_affines: Vec<G1Affine> = Vec::with_capacity(pair_count);
    let mut g2_prep: Vec<G2Prepared> = Vec::with_capacity(pair_count);
    for i in 0..pair_count {
        let g1b = &g1s[i * BLS12_381_G1_COMPRESSED_LEN..(i + 1) * BLS12_381_G1_COMPRESSED_LEN];
        let g2b = &g2s[i * BLS12_381_G2_COMPRESSED_LEN..(i + 1) * BLS12_381_G2_COMPRESSED_LEN];
        g1_affines.push(match g1_decode(g1b, true) {
            Ok(v) => v,
            Err(e) => return e,
        });
        let g2a = match g2_decode(g2b, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        g2_prep.push(G2Prepared::from(g2a));
    }
    let refs: Vec<(&G1Affine, &G2Prepared)> = g1_affines
        .iter()
        .zip(g2_prep.iter())
        .map(|(a, p)| (a, p))
        .collect();
    let ml = multi_miller_loop(&refs);
    if ml.final_exponentiation() == Gt::identity() {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

// --- BLS signatures (bls-signatures 0.15 style) ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_private_key_from_seed(
    seed: *const u8,
    seed_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let seed_sl = match aead_common::optional_input(seed, seed_len) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sk = match key_gen_from_ikm(seed_sl) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&sk.to_bytes());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_private_key_generate(output: *mut u8, output_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (output, output_len);
            return RUSTCRYPTO_ERR_RANDOM_FAILED;
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut ikm = [0u8; 32];
            if OsRng.try_fill_bytes(&mut ikm).is_err() {
                return RUSTCRYPTO_ERR_RANDOM_FAILED;
            }
            let sk = match key_gen_from_ikm(&ikm) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
                Ok(o) => o,
                Err(e) => return e,
            };
            out.copy_from_slice(&sk.to_bytes());
            RUSTCRYPTO_OK
        }
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_private_key_from_decimal_string(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let bytes = match aead_common::optional_input(input, input_len) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let s = match core::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
        };
        let sk = match Scalar::from_str_vartime(s) {
            Some(v) => v,
            None => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
        };
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&sk.to_bytes());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_public_key(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let kb = match aead_common::fixed_input(
            private_key,
            private_key_len,
            BLS12_381_SCALAR_LEN,
            RUSTCRYPTO_ERR_INVALID_PARAMETER,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let mut arr = [0u8; BLS12_381_SCALAR_LEN];
        arr.copy_from_slice(kb);
        let sk = match read_scalar(&arr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let pk = G1Projective::generator() * sk;
        let aff = pk.to_affine();
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G1_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&aff.to_compressed());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_hash(
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let msg = match aead_common::optional_input(message, message_len) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let h = hash_to_g2(msg);
        let aff = h.to_affine();
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G2_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&aff.to_compressed());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_sign(
    message: *const u8,
    message_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let msg = match aead_common::optional_input(message, message_len) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let kb = match aead_common::fixed_input(
            private_key,
            private_key_len,
            BLS12_381_SCALAR_LEN,
            RUSTCRYPTO_ERR_INVALID_PARAMETER,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let mut arr = [0u8; BLS12_381_SCALAR_LEN];
        arr.copy_from_slice(kb);
        let sk = match read_scalar(&arr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut sig = hash_to_g2(msg);
        sig *= sk;
        let aff = sig.to_affine();
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G2_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&aff.to_compressed());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_aggregate(
    signatures: *const u8,
    signatures_len: usize,
    signature_count: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if signature_count == 0 {
            return RUSTCRYPTO_ERR_INVALID_LENGTH;
        }
        let need = match signature_count.checked_mul(BLS12_381_G2_COMPRESSED_LEN) {
            Some(v) => v,
            None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
        };
        if signatures_len != need {
            return RUSTCRYPTO_ERR_INVALID_LENGTH;
        }
        if signatures.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        let slab = unsafe { core::slice::from_raw_parts(signatures, signatures_len) };
        let mut acc = G2Projective::identity();
        for i in 0..signature_count {
            let chunk = &slab[i * BLS12_381_G2_COMPRESSED_LEN..(i + 1) * BLS12_381_G2_COMPRESSED_LEN];
            let p = match g2_decode(chunk, true) {
                Ok(v) => v,
                Err(e) => return e,
            };
            acc += G2Projective::from(p);
        }
        let aff = acc.to_affine();
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G2_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&aff.to_compressed());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_verify(
    signature: *const u8,
    signature_len: usize,
    hashes: *const u8,
    hashes_len: usize,
    public_keys: *const u8,
    public_keys_len: usize,
    pair_count: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if pair_count == 0 {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        let sigb = match aead_common::fixed_input(
            signature,
            signature_len,
            BLS12_381_G2_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let need_h = pair_count * BLS12_381_G2_COMPRESSED_LEN;
        let need_pk = pair_count * BLS12_381_G1_COMPRESSED_LEN;
        if hashes_len != need_h || public_keys_len != need_pk {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        if hashes.is_null() || public_keys.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        let sig_a = match g2_decode(sigb, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let hslab = unsafe { core::slice::from_raw_parts(hashes, hashes_len) };
        let pkslab = unsafe { core::slice::from_raw_parts(public_keys, public_keys_len) };
        let mut hashes_p: Vec<G2Projective> = Vec::with_capacity(pair_count);
        let mut pks: Vec<G1Projective> = Vec::with_capacity(pair_count);
        for i in 0..pair_count {
            let hb = &hslab[i * BLS12_381_G2_COMPRESSED_LEN..(i + 1) * BLS12_381_G2_COMPRESSED_LEN];
            let pk = &pkslab[i * BLS12_381_G1_COMPRESSED_LEN..(i + 1) * BLS12_381_G1_COMPRESSED_LEN];
            let ha = match g2_decode(hb, true) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let pk_a = match g1_decode(pk, true) {
                Ok(v) => v,
                Err(e) => return e,
            };
            hashes_p.push(G2Projective::from(ha));
            pks.push(G1Projective::from(pk_a));
        }
        verify_aggregate_impl(&sig_a, &hashes_p, &pks)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_verify_messages(
    signature: *const u8,
    signature_len: usize,
    messages: *const *const u8,
    message_lens: *const usize,
    message_count: usize,
    public_keys: *const u8,
    public_keys_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if message_count == 0 {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        if public_keys_len != message_count * BLS12_381_G1_COMPRESSED_LEN {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        if messages.is_null() || message_lens.is_null() || public_keys.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        let sigb = match aead_common::fixed_input(
            signature,
            signature_len,
            BLS12_381_G2_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let sig_a = match g2_decode(sigb, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mptrs = unsafe { core::slice::from_raw_parts(messages, message_count) };
        let mlens = unsafe { core::slice::from_raw_parts(message_lens, message_count) };
        let pkslab = unsafe { core::slice::from_raw_parts(public_keys, public_keys_len) };
        let mut hashes_p: Vec<G2Projective> = Vec::with_capacity(message_count);
        let mut pks: Vec<G1Projective> = Vec::with_capacity(message_count);
        for i in 0..message_count {
            let msg = match aead_common::optional_input(mptrs[i], mlens[i]) {
                Ok(m) => m,
                Err(e) => return e,
            };
            hashes_p.push(hash_to_g2(msg));
            let pk = &pkslab[i * BLS12_381_G1_COMPRESSED_LEN..(i + 1) * BLS12_381_G1_COMPRESSED_LEN];
            let pk_a = match g1_decode(pk, true) {
                Ok(v) => v,
                Err(e) => return e,
            };
            pks.push(G1Projective::from(pk_a));
        }
        verify_aggregate_impl(&sig_a, &hashes_p, &pks)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls_signatures::{
        aggregate as bs_agg, hash as bs_hash, verify as bs_verify, PrivateKey, Serialize, Signature,
    };

    #[test]
    fn key_gen_matches_bls_signatures() {
        let material = b"hello world (it's a secret!) very secret stuff";
        let mut out = [0u8; 32];
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_signature_private_key_from_seed(
                material.as_ptr(),
                material.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        );
        let sk = PrivateKey::new(material);
        assert_eq!(out.as_slice(), sk.as_bytes().as_slice());
    }

    #[test]
    fn sign_verify_roundtrip_matches() {
        let msg = b"this is the message";
        let seed = b"this is the key and it is very secret";
        let mut sk = [0u8; 32];
        rustcrypto_bls12_381_signature_private_key_from_seed(seed.as_ptr(), seed.len(), sk.as_mut_ptr(), 32);
        let mut pk = [0u8; 48];
        rustcrypto_bls12_381_signature_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 48);
        let mut sig = [0u8; 96];
        rustcrypto_bls12_381_signature_sign(msg.as_ptr(), msg.len(), sk.as_ptr(), 32, sig.as_mut_ptr(), 96);
        let bs_sk = PrivateKey::new(seed);
        let bs_sig = bs_sk.sign(msg);
        assert_eq!(sig.as_slice(), bs_sig.as_bytes());
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_signature_verify_messages(
                sig.as_ptr(),
                96,
                [msg.as_ptr()].as_ptr(),
                [msg.len()].as_ptr(),
                1,
                pk.as_ptr(),
                48,
            )
        );
        let ref_pk = bls_signatures::PublicKey::from_bytes(&pk).unwrap();
        assert!(ref_pk.verify(bs_sig, msg));
        assert!(bs_verify(&bs_sig, &[bs_hash(msg)], &[ref_pk]));
    }

    #[test]
    fn pairing_bilinearity_smoke() {
        let mut g = [0u8; 48];
        rustcrypto_bls12_381_g1_generator(g.as_mut_ptr(), 48, 1);
        let s = Scalar::from(2u64);
        let mut g2 = [0u8; 48];
        rustcrypto_bls12_381_g1_mul(g.as_ptr(), 48, s.to_bytes().as_ptr(), 32, g2.as_mut_ptr(), 48, 1);
        let mut h = [0u8; 96];
        rustcrypto_bls12_381_g2_generator(h.as_mut_ptr(), 96, 1);
        let s_inv: Scalar = match Option::from(s.invert()) {
            Some(v) => v,
            None => panic!("invert"),
        };
        let mut h2 = [0u8; 96];
        rustcrypto_bls12_381_g2_mul(h.as_ptr(), 96, s_inv.to_bytes().as_ptr(), 32, h2.as_mut_ptr(), 96, 1);
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_pairing_eq(g.as_ptr(), 48, h.as_ptr(), 96, g2.as_ptr(), 48, h2.as_ptr(), 96)
        );
    }

    #[test]
    fn duplicate_message_fails() {
        let seed = [7u8; 40];
        let mut sk = [0u8; 32];
        rustcrypto_bls12_381_signature_private_key_from_seed(seed.as_ptr(), seed.len(), sk.as_mut_ptr(), 32);
        let mut pk = [0u8; 48];
        rustcrypto_bls12_381_signature_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 48);
        let msg = b"same";
        let mut sk2 = [0u8; 32];
        rustcrypto_bls12_381_signature_private_key_from_seed([8u8; 40].as_ptr(), 40, sk2.as_mut_ptr(), 32);
        let mut pk2 = [0u8; 48];
        rustcrypto_bls12_381_signature_public_key(sk2.as_ptr(), 32, pk2.as_mut_ptr(), 48);
        let mut s1 = [0u8; 96];
        let mut s2 = [0u8; 96];
        rustcrypto_bls12_381_signature_sign(msg.as_ptr(), msg.len(), sk.as_ptr(), 32, s1.as_mut_ptr(), 96);
        rustcrypto_bls12_381_signature_sign(msg.as_ptr(), msg.len(), sk2.as_ptr(), 32, s2.as_mut_ptr(), 96);
        let mut agg = [0u8; 96];
        let slab: Vec<u8> = s1.iter().chain(s2.iter()).copied().collect();
        let sig1 = Signature::from_bytes(&s1).unwrap();
        let sig2 = Signature::from_bytes(&s2).unwrap();
        let agg_bs = bs_agg(&[sig1, sig2]).unwrap();
        rustcrypto_bls12_381_signature_aggregate(slab.as_ptr(), slab.len(), 2, agg.as_mut_ptr(), 96);
        assert_eq!(agg.as_slice(), agg_bs.as_bytes().as_slice());
        let msgs = [msg.as_ptr(), msg.as_ptr()];
        let lens = [msg.len(), msg.len()];
        let mut pkb = [0u8; 96];
        pkb[..48].copy_from_slice(&pk);
        pkb[48..].copy_from_slice(&pk2);
        assert_eq!(
            RUSTCRYPTO_ERR_VERIFICATION_FAILED,
            rustcrypto_bls12_381_signature_verify_messages(
                agg.as_ptr(),
                96,
                msgs.as_ptr(),
                lens.as_ptr(),
                2,
                pkb.as_ptr(),
                96,
            )
        );
    }
}
