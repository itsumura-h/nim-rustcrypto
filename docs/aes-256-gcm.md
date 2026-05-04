# AES-256-GCM

Module: `rustcrypto/algorithm/aesgcm`

Authenticated encryption with AES-256-GCM. Keys, nonces, and tags are fixed-size byte arrays; plaintext and ciphertext are `seq[byte]` (and accept `openArray[byte]` for inputs).

## Types

- `Aes256GcmKey` — 32 bytes
- `Aes256GcmNonce` — 12 bytes
- `Aes256GcmTag` — 16 bytes

Helpers: `fromHexKey`, `fromHexNonce`, `fromHexTag`, or `Aes256GcmKey.fromHex(...)`, etc.

## Encrypt

```nim
import rustcrypto/algorithm/aesgcm

let key = fromHexKey("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
let nonce = fromHexNonce("000000000000000000000001")
let plaintext = @[byte('h'), byte('i')]
let aad = newSeq[byte]()

let (ciphertext, tag) = aes256gcmEncrypt(key, nonce, plaintext, aad)
```

## Decrypt

```nim
let recovered = aes256gcmDecrypt(key, nonce, ciphertext, tag, aad)
```

Authentication failure raises `ValueError` (`authentication failed`).
