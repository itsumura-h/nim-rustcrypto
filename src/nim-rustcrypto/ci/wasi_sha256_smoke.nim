## CI 用: wasm32-wasip1 + WASI SDK で Nim から rustcrypto（FFI 経由）をリンクできることを検証する。
## `.github/workflows/test.yml` の wasm32-wasip1-smoke ジョブから参照される。
import rustcrypto/algorithm/sha256

proc main() =
  doAssert sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

when isMainModule:
  main()
