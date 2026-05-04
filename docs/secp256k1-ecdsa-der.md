# secp256k1 ECDSA (DER)

Module: `rustcrypto/algorithm/secp256k1_ecdsa_der`

Convert between the library’s fixed 64-byte raw ECDSA signature (`Secp256k1Signature`) and ASN.1 DER encoding.

## To DER

```nim
import rustcrypto/algorithm/secp256k1_ecdsa_der

let der = secp256k1EcdsaSignatureToDer(raw64ByteSignature)
```

## From DER

```nim
let raw = secp256k1EcdsaSignatureFromDer(derBytes)
```

Invalid DER raises `ValueError`.
