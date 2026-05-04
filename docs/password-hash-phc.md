# PHC password hash strings

Module: `rustcrypto/algorithm/passwordhash`

Helpers to validate and canonicalize PHC-encoded password hash strings (as produced by `argon2idHashPassword` and similar flows).

## Validate

```nim
import rustcrypto/algorithm/passwordhash

if passwordHashValidate(phcString):
  echo "format looks valid"
```

Returns `true` only when the FFI reports success; invalid format returns `false` (see implementation for edge cases).

## Canonicalize

```nim
let canonical: PasswordHashString = passwordHashCanonicalize(phcString)
```

Raises `ValueError` if the string cannot be canonicalized.

See also [argon2.md](./argon2.md).
