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

let skDer = ed25519PrivateKeyToPkcs8Der(sk)
let sk2 = ed25519PrivateKeyFromPkcs8Der(skDer)

let pkDer = ed25519PublicKeyToSpkiDer(pk)
let pk2 = ed25519PublicKeyFromSpkiDer(pkDer)

let skPem = ed25519PrivateKeyToPkcs8Pem(sk)
let skFromPem = ed25519PrivateKeyFromPkcs8Pem(skPem)

let pkPem = ed25519PublicKeyToSpkiPem(pk)
let pkFromPem = ed25519PublicKeyFromSpkiPem(pkPem)
```

## P-256 and P-384

Module: `rustcrypto/algorithm/p256` (and `p384` with `Sha384` names)

```nim
import rustcrypto/algorithm/p256
import rustcrypto/algorithm/ffi

let sk = P256.generateSecretKey()
let skDer = p256PrivateKeyToPkcs8Der(sk)
let sk2 = p256PrivateKeyFromPkcs8Der(skDer)

let pk = P256.publicKeyCompressed(sk)
let pkDer = p256PublicKeyToSpkiDer(pk, P256PublicKeyFormatCompressed)
let pkBytes = p256PublicKeyFromSpkiDer(pkDer, P256PublicKeyFormatCompressed)
```

Use the matching `P384*` symbols from `rustcrypto/algorithm/p384` for P-384.

## RSA

Module: `rustcrypto/algorithm/rsa`

RSA PKCS#8 / SPKI normalization is described in [rsa-signatures-and-encryption.md](./rsa-signatures-and-encryption.md).
