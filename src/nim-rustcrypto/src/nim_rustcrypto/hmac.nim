import ./ffi
import ./utils

type
  HmacSha256Mac* = array[HmacSha256MacLen, byte]

proc hmacSha256*(key, message: string): HmacSha256Mac =
  var output: HmacSha256Mac
  let status = hmacSha256Raw(
    bytesPtr(key),
    csize_t(key.len),
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(
    status,
    "rustcrypto_hmac_sha256",
    nullOutputMessage = "rustcrypto_hmac_sha256 failed: null output",
    outputTooShortMessage = "rustcrypto_hmac_sha256 failed: output too short",
    nullInputWithDataMessage = "rustcrypto_hmac_sha256 failed: null input with data",
    panicMessage = "rustcrypto_hmac_sha256 failed: panic",
  )
  output

proc hmacSha256Hex*(key, message: string): string =
  digestToHex(HmacSha256Mac, hmacSha256(key, message))
