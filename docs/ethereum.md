# Ethereum helpers

Module: `rustcrypto/ethereum`

Keccak-256, address derivation from an uncompressed secp256k1 key, EIP-191 personal message hashing, EIP-712 digest hashing, and **recoverable ECDSA** signatures with Ethereum `v` encoding.

## Types

- `EthereumAddress` — 20 bytes
- `EthereumHash` — 32 bytes
- `EthereumSignature` — `r`, `s` (32 bytes each), `v` (chain-aware)
- `EthereumChainId` — `uint64` (`0` means legacy `v ∈ {27,28}`)

## Keccak-256

```nim
import rustcrypto/ethereum

let h = ethereumKeccak256(messageBytes)
```

## Address from uncompressed public key

```nim
let addr = ethereumAddress(uncompressedSecp256k1PubKey)
```

The public key must be a 65-byte SEC1 uncompressed point (`0x04 || X || Y`).

## EIP-191 personal message

```nim
let digest = ethereumPersonalMessageHash("Hello")
let sig = ethereumSignPersonalMessage("Hello", secretKey, chainId = 1)
discard ethereumVerifyPersonalMessage("Hello", uncompressedPubKey, sig)
```

`ethereumVerifyPersonalMessage` tries recovery ids internally; unsupported `v` raises `ValueError`.

## EIP-712 (precomputed hashes)

When you already have `domainSeparator` and `structHash` as `EthereumHash`:

```nim
let sig = ethereumSignTypedDataHash(domainSeparator, structHash, secretKey, chainId = 1)
discard ethereumVerifyTypedDataHash(domainSeparator, structHash, uncompressedPubKey, sig)
```

This module does **not** build EIP-712 structs from JSON or perform JSON canonicalization.
