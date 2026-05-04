# Bitcoin helpers

Module: `rustcrypto/bitcoin`

Convenience types and procedures for Bitcoin-style message hashing, compact recoverable signatures, ECDSA over a provided digest, and Taproot-related Schnorr over a digest.

## Types

- `BitcoinMessageHash` — `Sha256Digest` (32 bytes)
- `BitcoinMessageSignature` — 65-byte compact recoverable form (header byte + 64-byte sig)
- `BitcoinEcdsaSignature` — raw 64-byte ECDSA (`Secp256k1Signature`)
- `BitcoinSchnorrSignature`, `BitcoinXOnlyPublicKey` — Schnorr types from `algorithm/schnorr`
- `BitcoinNetwork` — enum (`bitcoinMainnet`, `bitcoinTestnet`, `bitcoinRegtest`) (reserved for future network-specific formatting)

## Double SHA-256 (`hash256`)

```nim
import rustcrypto/bitcoin

let h = bitcoinHash256(someBytes)
```

## BIP-340 tagged hash

```nim
let h = bitcoinTaggedHash("TagName", messageBytes)
```

## Bitcoin Signed Message (legacy)

```nim
import rustcrypto/bitcoin
import rustcrypto/algorithm/secp256k1

let sig = bitcoinSignMessage("Hello", secretKey)
discard bitcoinVerifyMessage("Hello", compressedPubKey, sig)
```

## ECDSA on an arbitrary 32-byte digest

```nim
let digest: BitcoinMessageHash = bitcoinMessageHash("Hello")
let sig = bitcoinSignDigestEcdsa(digest, secretKey)
discard bitcoinVerifyDigestEcdsa(digest, compressedPubKey, sig)
```

## Schnorr on a 32-byte digest (Taproot signing workflows)

```nim
let sig = bitcoinSignTaprootDigest(digest, schnorrSecretKey)
discard bitcoinVerifyTaprootDigest(digest, xOnlyPubKey, sig)
```

This crate does **not** implement full wallets, transaction parsing, or script execution.
