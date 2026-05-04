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

The same module re-exports message-based ECDSA helpers that hash with SHA3-256 or Keccak-256 before signing:

- `secp256k1EcdsaSignSha3_256` / `secp256k1EcdsaVerifySha3_256`
- `secp256k1EcdsaSignKeccak256` / `secp256k1EcdsaVerifyKeccak256`

See [secp256k1-ecdsa.md](./secp256k1-ecdsa.md).
