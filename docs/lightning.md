# Lightning (BOLT-11 invoice signing)

Module: `rustcrypto/lightning`

Helpers for payment preimage hashing, node id derivation, and **BOLT-11 invoice signing hashes** with recoverable ECDSA signatures.

## Types

- `LightningPaymentPreimage` — 32 bytes
- `LightningPaymentHash` — `Sha256Digest`
- `LightningNodeId` — `Secp256k1CompressedPublicKey`
- `LightningInvoiceSignature` — `Secp256k1RecoverableSignature`

## Payment hash

```nim
import rustcrypto/lightning
import rustcrypto/algorithm/secp256k1

let paymentHash = Lightning.paymentHash(preimage32)
```

## Node id

```nim
let nodeId = Lightning.nodeId(secretKey)
```

## Invoice signing hash

The caller splits a BOLT-11 string into the **human-readable part (`hrp`)** and the **5-bit decoded data without the signature block**, then passes the raw data bytes:

```nim
let h = Lightning.invoiceSigningHash(hrpString, dataPartWithoutSignature)
```

## Sign / verify invoice material

```nim
let secretKey = Secp256k1.generateSecretKey()
let nodeId = Lightning.nodeId(secretKey)
let sig = Lightning.signInvoice(hrpString, dataPartWithoutSignature, secretKey)
discard Lightning.verifyInvoice(hrpString, dataPartWithoutSignature, nodeId, sig)
```

If you already computed the signing hash:

```nim
discard Lightning.verifyInvoiceHash(signingHash, nodeId, sig)
```

This is **not** a full BOLT-11 parser: you must supply `hrp` and the decoded payload bytes in the shape expected by BOLT-11.
