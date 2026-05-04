# HKDF-SHA256

Module: `rustcrypto/algorithm/hkdf`

HKDF (RFC 5869) using HMAC-SHA256. Salt, IKM, and `info` are Nim `string` values. Output lengths are in bytes (`int`).

## Types

- `HkdfSha256Prk` — 32-byte pseudorandom key (PRK) from extract
- `HkdfSha256Okm` — `seq[byte]` output keying material from expand or one-shot derive

## Extract

```nim
import rustcrypto/algorithm/hkdf

let prk = hkdfSha256Extract("salt", "input-keying-material")
```

## Expand

```nim
let okm = hkdfSha256Expand(prk, "context-info", 32)
```

## One-shot (Extract + Expand)

```nim
let okm = hkdfSha256Derive("salt", "ikm", "info", 32)
```

Invalid lengths (negative or above the library maximum) raise `ValueError` before calling the FFI.
