# scrypt

Module: `rustcrypto/algorithm/scrypt`

scrypt key derivation. Password and salt are Nim `string` values. The CPU/memory cost parameter `n` must be a power of two and at least 2. Parameters `r` and `p` must be positive. Output length is `okmLen` in bytes.

## Usage

```nim
import rustcrypto/algorithm/scrypt
import rustcrypto/algorithm/common

# n = 32768 (2^15), r = 8, p = 1 — example parameters only; tune for your threat model
let okm = scrypt(
  password = "password",
  salt = "saltsaltsaltsalt",
  n = 32768,
  r = 8,
  p = 1,
  okmLen = 32,
)
```

## Notes

- `n` must satisfy `(n and (n - 1)) == 0` (power of two).
- The library validates `n`, `r`, `p`, and `okmLen`; invalid combinations raise `ValueError`.

This API uses the raw scrypt `N` parameter (not `log2(N)`).
