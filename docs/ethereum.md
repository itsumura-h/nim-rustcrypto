# Ethereum helpers

Module: `rustcrypto/ethereum`

Keccak-256, address derivation from an uncompressed secp256k1 key, EIP-191 personal message hashing, EIP-712 digest hashing, and **recoverable ECDSA** signatures with Ethereum `v` encoding. Verification uses the wallet address, not the raw public key.

## Types

- `EthereumAddress` — 20 bytes
- `EthereumHash` — 32 bytes
- `EthereumSignature` — `r`, `s` (32 bytes each), `v` (chain-aware)
- `EthereumChainId` — `uint64` (`0` means legacy `v ∈ {27,28}`)

## Keccak-256

```nim
import rustcrypto/ethereum
import rustcrypto/algorithm/secp256k1

let h = Ethereum.keccak256(messageBytes)
```

## Address from uncompressed public key

```nim
let addr = Ethereum.address(uncompressedSecp256k1PubKey)
```

The public key must be a 65-byte SEC1 uncompressed point (`0x04 || X || Y`).

## EIP-191 personal message

```nim
let secretKey = Secp256k1.generateSecretKey()
let uncompressedPubKey = Secp256k1.publicKeyUncompressed(secretKey)
let walletAddress = Ethereum.address(uncompressedPubKey)
let sig = Ethereum.signPersonalMessage("Hello", secretKey, chainId = 1)
discard Ethereum.verifyPersonalMessage("Hello", walletAddress, sig)
```

`Ethereum.verifyPersonalMessage` tries recovery ids internally and compares the recovered wallet address; unsupported `v` raises `ValueError`.

## EIP-712 (precomputed hashes)

When you already have `domainSeparator` and `structHash` as `EthereumHash`:

```nim
let secretKey = Secp256k1.generateSecretKey()
let uncompressedPubKey = Secp256k1.publicKeyUncompressed(secretKey)
let walletAddress = Ethereum.address(uncompressedPubKey)
let sig = Ethereum.signTypedDataHash(domainSeparator, structHash, secretKey, chainId = 1)
discard Ethereum.verifyTypedDataHash(domainSeparator, structHash, walletAddress, sig)
```

This module does **not** build EIP-712 structs from JSON or perform JSON canonicalization.
