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
import std/json
import rustcrypto/jwt

let payload = %*{"sub": "1234567890", "admin": true}
let secretKey = Jwt.generateSecretKey(jwtHS256)
let token = Jwt.sign(jwtHS256, payload, secretKey)
discard Jwt.verify(jwtHS256, Jwt.publicKey(secretKey), token)
discard Jwt.decode(token)
```

## ES256

```nim
import std/json
import rustcrypto/algorithm/p256
import rustcrypto/jwt

let payload = %*{"sub": "1234567890", "admin": true}
let secretKey = Jwt.generateSecretKey(jwtES256)
let token = Jwt.sign(jwtES256, payload, secretKey)
discard Jwt.verify(jwtES256, Jwt.publicKey(secretKey), token)
```

## EdDSA

```nim
import std/json
import rustcrypto/algorithm/ed25519
import rustcrypto/jwt

let payload = %*{"sub": "1234567890", "admin": true}
let secretKey = Jwt.generateSecretKey(jwtEdDSA)
let token = Jwt.sign(jwtEdDSA, payload, secretKey)
discard Jwt.verify(jwtEdDSA, Jwt.publicKey(secretKey), token)
```

## RS256 / PS256

The legacy DER-based helpers remain available:

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
