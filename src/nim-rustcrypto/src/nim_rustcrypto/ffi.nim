const rustCryptoStaticLib* = "../rustcrypto-ffi/target/release/librust_crypto_ffi.a"

{.passL: rustCryptoStaticLib.}

const
  SHA256DigestLen* = 32
  RustCryptoOk* = 0.cint
  RustCryptoErrNullOutput* = 1.cint
  RustCryptoErrOutputTooShort* = 2.cint
  RustCryptoErrNullInputWithData* = 3.cint
  RustCryptoErrPanic* = -1.cint

proc sha256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_sha256".}
