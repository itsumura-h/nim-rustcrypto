# RSA (signatures and encryption)

Module: `rustcrypto/algorithm/rsa`

RSA operations use **DER-encoded keys** as `openArray[byte]` (typically PKCS#8 for private keys and SPKI for public keys). Returned signatures and ciphertexts are `seq[byte]`.

## Key normalization helpers

These routines parse and re-encode RSA keys into a canonical PKCS#8 / SPKI DER form (`RsaPrivateKeyDer`, `RsaPublicKeyDer` are `seq[byte]` type aliases):

```nim
import rustcrypto/algorithm/rsa

let privNorm = Rsa.privateKeyToPkcs8Der(privateKeyDerFromFile)
let privRoundTrip = Rsa.privateKeyFromPkcs8Der(privNorm)

let pubNorm = Rsa.publicKeyToSpkiDer(publicKeyDerFromFile)
let pubRoundTrip = Rsa.publicKeyFromSpkiDer(pubNorm)
```

## RSASSA-PSS with SHA-256

```nim
let sig = Rsa.pssSignSha256("message", privateKeyDer)
discard Rsa.pssVerifySha256("message", publicKeyDer, sig)
```

## RSASSA-PKCS1-v1_5 with SHA-256

```nim
let sig = Rsa.pkcs1v15SignSha256("message", privateKeyDer)
discard Rsa.pkcs1v15VerifySha256("message", publicKeyDer, sig)
```

## RSA-OAEP (SHA-256)

Optional OAEP `label` string (often empty):

```nim
let ct = Rsa.oaepSha256Encrypt(plaintextBytes, publicKeyDer, label = "")
let pt = Rsa.oaepSha256Decrypt(ct, privateKeyDer, label = "")
```

## RSA PKCS#1 v1.5 encryption

```nim
let ct = Rsa.pkcs1v15Encrypt(plaintextBytes, publicKeyDer)
let pt = Rsa.pkcs1v15Decrypt(ct, privateKeyDer)
```

Decryption failures raise `ValueError`.
