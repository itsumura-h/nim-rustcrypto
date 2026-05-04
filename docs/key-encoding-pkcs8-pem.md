# PKCS#8, SPKI, and PEM (keys)

Encoding helpers are split across modules by algorithm. All examples use DER (`seq[byte]` or fixed arrays) unless noted.

## Ed25519

Modules: `rustcrypto/algorithm/pkcs8`, `rustcrypto/algorithm/pem`, `rustcrypto/algorithm/ed25519`

```nim
import rustcrypto/algorithm/ed25519
import rustcrypto/algorithm/pkcs8
import rustcrypto/algorithm/pem

let sk = Ed25519.generateSecretKey()
let pk = Ed25519.publicKey(sk)

let skDer = Ed25519.privateKeyToPkcs8Der(sk)
let sk2 = Ed25519.privateKeyFromPkcs8Der(skDer)

let pkDer = Ed25519.publicKeyToSpkiDer(pk)
let pk2 = Ed25519.publicKeyFromSpkiDer(pkDer)

let skPem = Ed25519.privateKeyToPkcs8Pem(sk)
let skFromPem = Ed25519.privateKeyFromPkcs8Pem(skPem)

let pkPem = Ed25519.publicKeyToSpkiPem(pk)
let pkFromPem = Ed25519.publicKeyFromSpkiPem(pkPem)
```

## P-256 and P-384

Module: `rustcrypto/algorithm/p256` (and `p384` with `Sha384` names)

```nim
import rustcrypto/algorithm/p256
import rustcrypto/algorithm/ffi

let sk = P256.generateSecretKey()
let skDer = P256.privateKeyToPkcs8Der(sk)
let sk2 = P256.privateKeyFromPkcs8Der(skDer)

let pk = P256.publicKeyCompressed(sk)
let pkDer = P256.publicKeyToSpkiDer(pk)
let pkBytes = P256.publicKeyFromSpkiDer(pkDer, P256CompressedPublicKey)
```

Use the matching `P384*` symbols from `rustcrypto/algorithm/p384` for P-384.

## RSA

Module: `rustcrypto/algorithm/rsa`

RSA PKCS#8 / SPKI normalization is described in [rsa-signatures-and-encryption.md](./rsa-signatures-and-encryption.md).
