# BLAKE2b-512 and BLAKE2s-256

Module: `rustcrypto/algorithm/blake2`

One-shot hashing of a Nim `string` into fixed-size digests, with optional hex encoding helpers.

## Imports

```nim
import rustcrypto/algorithm/blake2
import rustcrypto/algorithm/common
```

## BLAKE2b-512

```nim
let d = blake2b512("message")
let hex = blake2b512Hex("message")
let d2 = Blake2b512Digest.fromHexBlake2b512(hex)
```

## BLAKE2s-256

```nim
let d = blake2s256("message")
let hex = blake2s256Hex("message")
let d2 = Blake2s256Digest.fromHexBlake2s256(hex)
```
