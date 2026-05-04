# AES-256-GCM-SIV

Module: `rustcrypto/algorithm/aesgcmsiv`

AES-256-GCM-SIV (RFC 8452): misuse-resistant AEAD with deterministic encryption for a given `(key, nonce)` pair. API shape matches AES-GCM: typed key/nonce/tag arrays and `seq[byte]` payloads.

## Types

- `Aes256GcmSivKey` — 32 bytes
- `Aes256GcmSivNonce` — 12 bytes
- `Aes256GcmSivTag` — 16 bytes

Use `fromHexKey`, `fromHexNonce`, `fromHexTag`, or `fromHex` on each type.

## Encrypt / decrypt

```nim
import rustcrypto/algorithm/aesgcmsiv

let key = fromHexKey("...")
let nonce = fromHexNonce("...")
let plaintext: seq[byte] = @[...]
let aad: seq[byte] = @[]

let (ciphertext, tag) = aes256gcmsivEncrypt(key, nonce, plaintext, aad)
let recovered = aes256gcmsivDecrypt(key, nonce, ciphertext, tag, aad)
```

Tampering with ciphertext, tag, or AAD causes decryption to fail with `ValueError`.
