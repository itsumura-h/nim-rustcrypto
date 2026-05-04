# P-384 ECDSA

Module: `rustcrypto/algorithm/p384`

Same shape as P-256, but messages are hashed with SHA-384 for the message APIs, and prehash APIs use `P384MessageDigest`.

## Sign / verify with SHA-384

```nim
import rustcrypto/algorithm/p384
import rustcrypto/algorithm/ffi

let sk = P384.generateSecretKey()
let pk = P384.publicKeyCompressed(sk)
let sig = P384.sign("message", sk)
discard P384.verify("message", pk, sig)
```

Public key format constants: `P384PublicKeyFormatCompressed` / `P384PublicKeyFormatUncompressed` in `rustcrypto/algorithm/ffi`.

## Pre-hashed API

```nim
let digest = fromHexMessageDigest("...")
let sig = P384.sign(digest, sk)
discard P384.verify(digest, pk, sig)
```

## PKCS#8 / SPKI

See [key-encoding-pkcs8-pem.md](./key-encoding-pkcs8-pem.md).
