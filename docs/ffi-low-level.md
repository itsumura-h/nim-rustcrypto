# Low-level FFI (`algorithm/ffi`)

Module: `rustcrypto/algorithm/ffi`

This module binds the static Rust archive and exposes `importc` C ABI functions (`*Raw` suffix in many call sites inside the library). High-level Nim wrappers in `rustcrypto/algorithm/*` are preferred: they pack buffers, translate status codes into `ValueError`, and use fixed-size types.

## Platform

Supported targets are defined in `ffi.nim` (for example Linux x86_64, `wasm32-unknown-unknown`, and `wasm32-wasip1`); other combinations fail at compile time with an error from that module.

## BLS12-381 (`rustcrypto_bls12_381_*`)

Length constants are exported from `ffi.nim` as `Bls12381ScalarLen` (32), `Bls12381G1CompressedLen` (48), `Bls12381G2CompressedLen` (96), and the corresponding uncompressed sizes. Curve points use `BlsPointFormatCompressed` / `BlsPointFormatUncompressed` with the `*_g1_*` / `*_g2_*` functions. Signature helpers use the `rustcrypto_bls12_381_signature_*` prefix. Prefer the high-level `rustcrypto/algorithm/bls` module when possible.

## Typical pattern

1. Allocate output buffers with correct lengths (see `*Len` constants in the same module).
2. Pass pointers via `bytesPtr` from `rustcrypto/algorithm/common` for `string` and `openArray[byte]`.
3. Check the returned `cint` status against `RustCryptoOk`.

```nim
import rustcrypto/algorithm/ffi
import rustcrypto/algorithm/common

var outDigest: array[SHA256DigestLen, byte]
let st = sha256Raw(
  bytesPtr("abc"),
  csize_t(3),
  cast[ptr uint8](addr outDigest[0]),
  csize_t(outDigest.len),
)
if st != RustCryptoOk:
  raise newException(ValueError, "sha256Raw failed: " & $st)
```

`common.raiseRustCryptoStatus` is a small helper that throws on non-zero status.

## Status codes (subset)

The following are used across primitives (see `ffi.nim` for the full list):

| Constant | Meaning |
|----------|---------|
| `RustCryptoOk` | Success |
| `RustCryptoErrNullOutput` | Required output pointer was nil |
| `RustCryptoErrOutputTooShort` | Output buffer too small |
| `RustCryptoErrNullInputWithData` | Nil pointer with non-zero length |
| `RustCryptoErrAuthenticationFailed` | AEAD tag verification failed |
| `RustCryptoErrVerificationFailed` | Signature or password verify failed |
| `RustCryptoErrPanic` | Rust side caught a panic at the FFI boundary |

Prefer the typed wrappers (`sha256`, `aes256gcmEncrypt`, …) unless you are extending the library.
