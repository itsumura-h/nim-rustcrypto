# HMAC-SHA256

Module: `rustcrypto/algorithm/hmac`

HMAC-SHA256 where both key and message are Nim `string` values. The MAC is a fixed 32-byte array (`HmacSha256Mac`).

## Imports

```nim
import rustcrypto/algorithm/hmac
import rustcrypto/algorithm/common
```

## Compute MAC

```nim
let mac = hmacSha256("key-bytes-as-string", "message")
let hex = digestToHex(HmacSha256Mac, mac)
# or
let hex2 = hmacSha256Hex("key-bytes-as-string", "message")
```

Errors from the Rust FFI are raised as `ValueError` with an operation-specific message.
