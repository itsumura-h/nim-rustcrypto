# P-256 (secp256r1) ECDSA

Module: `rustcrypto/algorithm/p256`

NIST P-256 ECDSA with SHA-256 message hashing, or pre-hashed P-256 digests. Keys and signatures are strongly typed arrays; PKCS#8 / SPKI DER import/export is supported.

## Keys and random material

```nim
import rustcrypto/algorithm/p256

let sk = P256.generateSecretKey()
# or deterministic test keys:
let sk2 = fromHexSecretKey("...")
let pkComp = P256.publicKeyCompressed(sk)
let pkUncomp = P256.publicKeyUncompressed(sk)
```

## Sign / verify (message → SHA-256 → ECDSA)

```nim
let sig = P256.sign("message", sk)

import rustcrypto/algorithm/ffi

discard P256.verify("message", pkComp, sig)
discard P256.verify("message", pkUncomp, sig)
```

Public key format constants: `P256PublicKeyFormatCompressed`, `P256PublicKeyFormatUncompressed` in `rustcrypto/algorithm/ffi`.

## Pre-hashed API

When the message is already hashed to a P-256 digest:

```nim
let digest = fromHexMessageDigest("...")
let sig = P256.sign(digest, sk)
discard P256.verify(digest, pkComp, sig)
```

## PKCS#8 / SPKI

See [key-encoding-pkcs8-pem.md](./key-encoding-pkcs8-pem.md) for `P256.privateKeyToPkcs8Der` and related symbols.

## JWT

P-256 is used by `Jwt.sign(jwtES256, ...)` / `Jwt.verify(jwtES256, ...)`. See [jwt-json-web-tokens.md](./jwt-json-web-tokens.md).
