# JWT (JWS compact, selected algorithms)

Module: `rustcrypto/jwt`

Sign and verify JSON Web Tokens in **JWS Compact Serialization** form for:

- `HS256` — HMAC-SHA256
- `ES256` — ECDSA P-256 SHA-256 over the signing input
- `EdDSA` — Ed25519
- `RS256` — RSA PKCS#1 v1.5 with SHA-256
- `PS256` — RSA-PSS with SHA-256

## Header requirements

- Header JSON must be valid JSON with a string `"alg"` field matching the function you call.
- **`alg: none` is rejected** with `ValueError`.

## Build signing input

```nim
import rustcrypto/jwt

let signingInput = jwtSigningInput(headerJson, claimsJson)
```

## HS256

```nim
let token = jwtSignHS256(headerJson, claimsJson, secretBytes)
discard jwtVerifyHS256(token, secretBytes)
```

## ES256

```nim
import rustcrypto/algorithm/p256

let token = jwtSignES256(headerJson, claimsJson, secretKey)
discard jwtVerifyES256(token, compressedOrUncompressedPubKey)
```

## EdDSA

```nim
import rustcrypto/algorithm/ed25519

let token = jwtSignEdDSA(headerJson, claimsJson, secretKey)
discard jwtVerifyEdDSA(token, publicKey)
```

## RS256 / PS256

Pass PKCS#8 private key DER (sign) and SPKI public key DER (verify):

```nim
let token = jwtSignRS256(headerJson, claimsJson, rsaPrivateKeyDer)
discard jwtVerifyRS256(token, rsaPublicKeyDer)

let tokenPs = jwtSignPS256(headerJson, claimsJson, rsaPrivateKeyDer)
discard jwtVerifyPS256(tokenPs, rsaPublicKeyDer)
```

## Base64url helpers

`jwtBase64UrlEncode`, `jwtBase64UrlDecode`, and `jwtSigningInput` are exported for advanced callers.

## Out of scope

- Claim validation (`exp`, `aud`, …)
- JSON canonicalization beyond what you place in `headerJson` / `claimsJson`
- JWKS fetch and key rotation
