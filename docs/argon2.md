# Argon2id

Module: `rustcrypto/algorithm/argon2`

Argon2id via Rust FFI: raw key derivation and PHC-string password hashing.

## Types

- `Argon2idOkm` — `seq[byte]` raw output
- `Argon2idPasswordHashString` — PHC-encoded string (for storage)

## Raw derive

```nim
import rustcrypto/algorithm/argon2
import rustcrypto/algorithm/common

let key = argon2idDerive(
  password = "password",
  salt = "somesaltbytes",
  mCost = 19456,   # KiB — example only
  tCost = 2,
  pCost = 1,
  hashLen = 32,
)
```

`mCost`, `tCost`, and `pCost` must be positive. `hashLen` must meet the library minimum (`Argon2idMinHashLen` in `rustcrypto/algorithm/ffi`).

## PHC password hash (encode)

You must supply an explicit salt string (the routine does not generate one for you):

```nim
let phc = argon2idHashPassword(
  password = "user-password",
  salt = "random-salt-bytes",
  mCost = 19456,
  tCost = 2,
  pCost = 1,
  hashLen = 32,
)
```

## PHC password verify

```nim
let ok = argon2idVerifyPassword("user-password", phc)
```

Returns `false` on password mismatch; invalid PHC format raises `ValueError`.
