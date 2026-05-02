import ./ffi

proc bytesPtr*(data: string): ptr uint8 =
  ## Convert a string to a byte pointer. Returns `nil` for an empty string.
  if data.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr data[0])

proc digestToHex*[T](_: typedesc[T], digest: openArray[byte]): string =
  ## Convert a byte slice to a hexadecimal string.
  const hexDigits = "0123456789abcdef"
  result = newString(digest.len * 2)

  for i, value in digest:
    let byteValue = int(value)
    result[2 * i] = hexDigits[byteValue shr 4]
    result[2 * i + 1] = hexDigits[byteValue and 0x0F]

proc hexNibble(ch: char): int =
  ## Convert a single hexadecimal character to an integer.
  case ch
  of '0'..'9':
    ord(ch) - ord('0')
  of 'a'..'f':
    ord(ch) - ord('a') + 10
  of 'A'..'F':
    ord(ch) - ord('A') + 10
  else:
    raise newException(ValueError, "invalid hex digit")

proc fromHexDigest*[T](hex: string, digestLen: static[int]): T =
  ## Convert a hexadecimal string to a fixed-size byte array.
  doAssert hex.len == digestLen * 2

  var output: T
  for i in 0 ..< digestLen:
    let hi = hexNibble(hex[2 * i])
    let lo = hexNibble(hex[2 * i + 1])
    output[i] = byte((hi shl 4) or lo)

  output

proc raiseIfError*(
    status: cint,
    operation: string = "",
    nullOutputMessage: string = "",
    outputTooShortMessage: string = "",
    nullInputWithDataMessage: string = "",
    invalidSecretKeyMessage: string = "",
    invalidPublicKeyFormatMessage: string = "",
    panicMessage: string = "",
) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    if nullOutputMessage.len > 0:
      raise newException(ValueError, nullOutputMessage)
    elif operation.len > 0:
      raise newException(ValueError, operation & " failed: null output")
    else:
      raise newException(ValueError, "null output")
  of RustCryptoErrOutputTooShort:
    if outputTooShortMessage.len > 0:
      raise newException(ValueError, outputTooShortMessage)
    elif operation.len > 0:
      raise newException(ValueError, operation & " failed: output too short")
    else:
      raise newException(ValueError, "output too short")
  of RustCryptoErrNullInputWithData:
    if nullInputWithDataMessage.len > 0:
      raise newException(ValueError, nullInputWithDataMessage)
    elif operation.len > 0:
      raise newException(ValueError, operation & " failed: null input with data")
    else:
      raise newException(ValueError, "null input with data")
  of RustCryptoErrInvalidSecretKey:
    if invalidSecretKeyMessage.len > 0:
      raise newException(ValueError, invalidSecretKeyMessage)
    elif operation.len > 0:
      raise newException(ValueError, operation & " failed: invalid secret key")
    else:
      raise newException(ValueError, "invalid secret key")
  of RustCryptoErrInvalidPublicKeyFormat:
    if invalidPublicKeyFormatMessage.len > 0:
      raise newException(ValueError, invalidPublicKeyFormatMessage)
    elif operation.len > 0:
      raise newException(ValueError, operation & " failed: invalid public key format")
    else:
      raise newException(ValueError, "invalid public key format")
  of RustCryptoErrPanic:
    if panicMessage.len > 0:
      raise newException(ValueError, panicMessage)
    elif operation.len > 0:
      raise newException(ValueError, operation & " failed: panic")
    else:
      raise newException(ValueError, "panic")
  else:
    if operation.len > 0:
      raise newException(
        ValueError,
        operation & " failed: unexpected status " & $status,
      )
    else:
      raise newException(ValueError, "unexpected status " & $status)
