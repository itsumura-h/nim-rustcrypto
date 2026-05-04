# ChaCha20-Poly1305

Module: `rustcrypto/algorithm/chacha20poly1305`

AEAD ChaCha20-Poly1305 (RFC 8439 style): 32-byte key, 12-byte nonce, 16-byte tag.

## Types

- `ChaCha20Poly1305Key`
- `ChaCha20Poly1305Nonce`
- `ChaCha20Poly1305Tag`

Hex helpers mirror AES-GCM (`fromHexKey`, etc.).

## Encrypt / decrypt

```nim
import rustcrypto/algorithm/chacha20poly1305

let key = fromHexKey("...")
let nonce = fromHexNonce("...")
let plaintext: seq[byte] = @[...]
let aad: seq[byte] = @[]

let (ciphertext, tag) = chacha20poly1305Encrypt(key, nonce, plaintext, aad)
let recovered = chacha20poly1305Decrypt(key, nonce, ciphertext, tag, aad)
```

Invalid lengths or authentication failure surface as `ValueError`.
