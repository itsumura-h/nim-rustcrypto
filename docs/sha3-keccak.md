# SHA3-256 and Keccak-256

Module: `rustcrypto/algorithm/sha3`

Provides SHA3-256 (NIST) and Keccak-256 (Ethereum-style, without the NIST padding tweak).

## Imports

```nim
import rustcrypto/algorithm/sha3
import rustcrypto/algorithm/common
```

## SHA3-256

```nim
let d = sha3_256("abc")
let hex = sha3_256Hex("abc")
let d2 = Sha3_256Digest.fromHexSha3_256(hex)
```

## Keccak-256

```nim
let k = keccak256("abc")
let khex = keccak256Hex("abc")
let k2 = Keccak256Digest.fromHexKeccak256(khex)
```

## secp256k1 ECDSA with SHA3 / Keccak

Use `Secp256k1.sign` / `Secp256k1.verify` with the digest overload if you want to sign a SHA3-256 or Keccak-256 digest explicitly.
