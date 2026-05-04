# PBKDF2-HMAC-SHA256

Module: `rustcrypto/algorithm/pbkdf2`

PBKDF2 with HMAC-SHA256. Password and salt are Nim `string` values. Iterations and output length are `int` (byte length of the derived key).

## Usage

```nim
import rustcrypto/algorithm/pbkdf2
import rustcrypto/algorithm/common

let okm = pbkdf2HmacSha256(
  password = "password",
  salt = "saltsaltsaltsalt",
  iterations = 100_000,
  okmLen = 32,
)
let hex = digestToHex(byte, okm)
```

## Validation

- `iterations` must be positive.
- `okmLen` must be non-negative.

Violations raise `ValueError`. FFI failures also raise `ValueError`.
