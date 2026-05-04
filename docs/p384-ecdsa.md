# P-384 ECDSA

Module: `rustcrypto/algorithm/p384`

Same shape as P-256, but messages are hashed with SHA-384 for the message APIs, and prehash APIs use `P384MessageDigest`.

## Sign / verify with SHA-384

```nim
import rustcrypto/algorithm/p384
import rustcrypto/algorithm/ffi

let sk = randomSecretKey()
let pk = p384PublicKeyCompressed(sk)
let sig = p384EcdsaSignSha384("message", sk)
discard p384EcdsaVerifySha384("message", pk, P384PublicKeyFormatCompressed, sig)
```

Public key format constants: `P384PublicKeyFormatCompressed` / `P384PublicKeyFormatUncompressed` in `rustcrypto/algorithm/ffi`.

## Pre-hashed API

```nim
let digest = fromHexMessageDigest("...")
let sig = p384EcdsaSignPrehash(digest, sk)
discard p384EcdsaVerifyPrehash(digest, pk, P384PublicKeyFormatCompressed, sig)
```

## PKCS#8 / SPKI

See [key-encoding-pkcs8-pem.md](./key-encoding-pkcs8-pem.md).
