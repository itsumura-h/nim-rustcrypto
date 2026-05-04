# secp256k1 Schnorr (BIP340-style)

Module: `rustcrypto/algorithm/schnorr`

Schnorr signatures on secp256k1 with x-only public keys. **Not compatible** with ECDSA public keys or signatures on the same curve.

## Types

- `SchnorrSecretKey` — 32 bytes (same length as ECDSA secret scalars; different key handling)
- `SchnorrPublicKey` — x-only encoding
- `SchnorrSignature` — fixed-length signature bytes

## Random key

```nim
import rustcrypto/algorithm/schnorr

let sk = Schnorr.generateSecretKey()
let pk = Schnorr.publicKey(sk)
```

## Sign / verify

`message` overloads exist for `string` and `openArray[byte]`:

```nim
let sig = Schnorr.sign("hello", sk)
discard Schnorr.verify("hello", pk, sig)

let sig2 = Schnorr.sign(messageBytes, sk)
discard Schnorr.verify(messageBytes, pk, sig2)
```

## Bitcoin Taproot digest helpers

`rustcrypto/bitcoin` exposes `bitcoinSignTaprootDigest` / `bitcoinVerifyTaprootDigest`, which call these primitives on a precomputed 32-byte digest. See [bitcoin.md](./bitcoin.md).
