# secp256k1 ECDSA

Modules:

- `rustcrypto/algorithm/secp256k1` — keys, raw ECDSA over 32-byte digests, recoverable signatures
- `rustcrypto/algorithm/sha256` — `secp256k1EcdsaSignSha256` / `VerifySha256` (message `string`, SHA-256 inside FFI)
- `rustcrypto/algorithm/sha3` — SHA3-256 and Keccak-256 message helpers

## Types

- `Secp256k1SecretKey` — 32-byte array
- `Secp256k1CompressedPublicKey` / `Secp256k1UncompressedPublicKey`
- `Secp256k1MessageDigest` — 32-byte prehash for raw sign/verify
- `Secp256k1Signature` — 64-byte compact ECDSA
- `Secp256k1RecoverableSignature` — 65 bytes (last byte recovery id)

## Random secret key

```nim
import rustcrypto/algorithm/secp256k1

let sk = Secp256k1.generateSecretKey()
let pk = Secp256k1.publicKeyCompressed(sk)
```

## Secret key from 64-char hex

```nim
import rustcrypto/algorithm/common
import rustcrypto/algorithm/secp256k1
import rustcrypto/algorithm/ffi

const skHex = "0000000000000000000000000000000000000000000000000000000000000001"
let sk = fromHexDigest[Secp256k1SecretKey](skHex, Secp256k1SecretKeyLen)
```

## Sign / verify a 32-byte digest (raw)

Use a 32-byte digest (for example SHA-256 of your payload) as `Secp256k1MessageDigest`:

```nim
import rustcrypto/algorithm/common
import rustcrypto/algorithm/secp256k1
import rustcrypto/algorithm/ffi

const digestHex =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # SHA-256 of ""
let digest = fromHexDigest[Secp256k1MessageDigest](digestHex, Secp256k1MessageDigestLen)
let sig = Secp256k1.sign(digest, sk)
discard Secp256k1.verify(digest, pk, sig)
```

`secp256k1EcdsaVerify` is overloaded for compressed and uncompressed public keys.

## Sign / verify a message string (SHA-256)

```nim
import rustcrypto/algorithm/sha256

let sig = Secp256k1.sign("hello", sk)
discard Secp256k1.verify("hello", pk, sig)
```

## Recoverable signatures

```nim
let rsig = secp256k1EcdsaSignRecoverable(digest, sk)
discard secp256k1EcdsaRecoverableVerify(digest, pk, rsig)
```

Used by Bitcoin message signing and Ethereum personal signing helpers.

## DER encoding

See [secp256k1-ecdsa-der.md](./secp256k1-ecdsa-der.md).
