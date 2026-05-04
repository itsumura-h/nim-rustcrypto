# P-256 (secp256r1) ECDSA

Module: `rustcrypto/algorithm/p256`

NIST P-256 ECDSA with SHA-256 message hashing, or pre-hashed P-256 digests. Keys and signatures are strongly typed arrays; PKCS#8 / SPKI DER import/export is supported.

## Keys and random material

```nim
import rustcrypto/algorithm/p256

let sk = randomSecretKey()
# or deterministic test keys:
let sk2 = fromHexSecretKey("...")
let pkComp = p256PublicKeyCompressed(sk)
let pkUncomp = p256PublicKeyUncompressed(sk)
```

## Sign / verify (message → SHA-256 → ECDSA)

```nim
let sig = p256EcdsaSignSha256("message", sk)

import rustcrypto/algorithm/ffi

discard p256EcdsaVerifySha256("message", pkComp, P256PublicKeyFormatCompressed, sig)
discard p256EcdsaVerifySha256("message", pkUncomp, P256PublicKeyFormatUncompressed, sig)
```

Public key format constants: `P256PublicKeyFormatCompressed`, `P256PublicKeyFormatUncompressed` in `rustcrypto/algorithm/ffi`.

## Pre-hashed API

When the message is already hashed to a P-256 digest:

```nim
let digest = fromHexMessageDigest("...")
let sig = p256EcdsaSignPrehash(digest, sk)
discard p256EcdsaVerifyPrehash(digest, pkComp, P256PublicKeyFormatCompressed, sig)
```

## PKCS#8 / SPKI

See [key-encoding-pkcs8-pem.md](./key-encoding-pkcs8-pem.md) for `p256PrivateKeyToPkcs8Der` and related symbols.

## JWT

P-256 is used by `jwtSignES256` / `jwtVerifyES256`. See [jwt-json-web-tokens.md](./jwt-json-web-tokens.md).
