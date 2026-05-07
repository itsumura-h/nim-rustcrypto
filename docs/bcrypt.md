# bcrypt

Module: `rustcrypto/algorithm/bcrypt`

bcrypt password hashing via the Rust `bcrypt` package and Rust FFI. This API uses bcrypt Modular Crypt Format strings such as `$2b$12$...`; these are not PHC strings.

## Types

- `Bcrypt` — marker type namespace
- `BcryptHashString` — bcrypt hash string for storage

## Hash

```nim
import rustcrypto/algorithm/bcrypt

let hash = Bcrypt.hashPassword("user-password")
```

The default cost is 12. You can pass an explicit cost in the bcrypt range 4..31:

```nim
let hash = Bcrypt.hashPassword("user-password", 12)
```

New hashes are emitted in `$2b$` format. Passwords that would be truncated by bcrypt are rejected with `ValueError`.

## Verify

```nim
let ok = Bcrypt.verifyPassword("user-password", hash)
```

Returns `false` on password mismatch. Invalid bcrypt hash format raises `ValueError`.

## Inspect

```nim
if Bcrypt.validateHash(hash):
  echo Bcrypt.cost(hash)

if Bcrypt.needsRehash(hash, 13):
  echo "rehash after successful login"
```

`needsRehash` returns `true` when the stored cost is lower than the target cost or when the hash is not in the current `$2b$` generation format.
