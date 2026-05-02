import ./ffi

type
  Sha256Digest* = array[SHA256DigestLen, byte]

proc fromHex*(_: type Sha256Digest, hex: string): Sha256Digest =
  doAssert hex.len == SHA256DigestLen * 2

  proc hexNibble(ch: char): int =
    case ch
    of '0'..'9':
      ord(ch) - ord('0')
    of 'a'..'f':
      ord(ch) - ord('a') + 10
    of 'A'..'F':
      ord(ch) - ord('A') + 10
    else:
      raise newException(ValueError, "invalid hex digit")

  var output: Sha256Digest
  for i in 0 ..< SHA256DigestLen:
    let hi = hexNibble(hex[2 * i])
    let lo = hexNibble(hex[2 * i + 1])
    output[i] = byte((hi shl 4) or lo)

  output

proc raiseIfError(status: cint) =
  if status != RustCryptoOk:
    raise newException(ValueError, "rustcrypto_sha256 failed with status " & $status)

proc messagePtr(message: string): ptr uint8 =
  if message.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr message[0])

proc digestToHex(digest: openArray[byte]): string =
  const hexDigits = "0123456789abcdef"
  result = newString(digest.len * 2)

  for i, value in digest:
    let byteValue = int(value)
    result[2 * i] = hexDigits[byteValue shr 4]
    result[2 * i + 1] = hexDigits[byteValue and 0x0F]

proc sha256*(message: string): Sha256Digest =
  var output: Sha256Digest
  let status = sha256Raw(
    messagePtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status)
  output

proc sha256Hex*(message: string): string =
  digestToHex(sha256(message))
