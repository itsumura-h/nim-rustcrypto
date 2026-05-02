import ./ffi

type
  HmacSha256Mac* = array[HmacSha256MacLen, byte]

proc raiseIfError(status: cint) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: null input with data")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_hmac_sha256 failed: unexpected status " & $status,
    )

proc bytesPtr(data: string): ptr uint8 =
  if data.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr data[0])

proc digestToHex(digest: openArray[byte]): string =
  const hexDigits = "0123456789abcdef"
  result = newString(digest.len * 2)

  for i, value in digest:
    let byteValue = int(value)
    result[2 * i] = hexDigits[byteValue shr 4]
    result[2 * i + 1] = hexDigits[byteValue and 0x0F]

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
  raiseIfError(status)
  output

proc hmacSha256Hex*(key, message: string): string =
  digestToHex(hmacSha256(key, message))
