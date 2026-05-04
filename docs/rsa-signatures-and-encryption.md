# RSA (signatures and encryption)

Module: `rustcrypto/algorithm/rsa`

RSA operations use **DER-encoded keys** as `openArray[byte]` (typically PKCS#8 for private keys and SPKI for public keys). Returned signatures and ciphertexts are `seq[byte]`.

## Key normalization helpers

These routines parse and re-encode RSA keys into a canonical PKCS#8 / SPKI DER form (`RsaPrivateKeyDer`, `RsaPublicKeyDer` are `seq[byte]` type aliases):

```nim
import rustcrypto/algorithm/rsa

let privNorm = rsaPrivateKeyToPkcs8Der(privateKeyDerFromFile)
let privRoundTrip = rsaPrivateKeyFromPkcs8Der(privNorm)

let pubNorm = rsaPublicKeyToSpkiDer(publicKeyDerFromFile)
let pubRoundTrip = rsaPublicKeyFromSpkiDer(pubNorm)
```

## RSASSA-PSS with SHA-256

```nim
let sig = rsaPssSignSha256("message", privateKeyDer)
discard rsaPssVerifySha256("message", publicKeyDer, sig)
```

## RSASSA-PKCS1-v1_5 with SHA-256

```nim
let sig = rsaPkcs1v15SignSha256("message", privateKeyDer)
discard rsaPkcs1v15VerifySha256("message", publicKeyDer, sig)
```

## RSA-OAEP (SHA-256)

Optional OAEP `label` string (often empty):

```nim
let ct = rsaOaepSha256Encrypt(plaintextBytes, publicKeyDer, label = "")
let pt = rsaOaepSha256Decrypt(ct, privateKeyDer, label = "")
```

## RSA PKCS#1 v1.5 encryption

```nim
let ct = rsaPkcs1v15Encrypt(plaintextBytes, publicKeyDer)
let pt = rsaPkcs1v15Decrypt(ct, privateKeyDer)
```

Decryption failures raise `ValueError`.
