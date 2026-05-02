import ./ffi

type
  Sha3_256Digest* = array[Sha3_256DigestLen, byte]
  Keccak256Digest* = array[Keccak256DigestLen, byte]

proc fromHexSha3_256*(_: type Sha3_256Digest, hex: string): Sha3_256Digest =
  doAssert hex.len == Sha3_256DigestLen * 2

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

  var output: Sha3_256Digest
  for i in 0 ..< Sha3_256DigestLen:
    let hi = hexNibble(hex[2 * i])
    let lo = hexNibble(hex[2 * i + 1])
    output[i] = byte((hi shl 4) or lo)

  output

proc fromHexKeccak256*(_: type Keccak256Digest, hex: string): Keccak256Digest =
  doAssert hex.len == Keccak256DigestLen * 2

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

  var output: Keccak256Digest
  for i in 0 ..< Keccak256DigestLen:
    let hi = hexNibble(hex[2 * i])
    let lo = hexNibble(hex[2 * i + 1])
    output[i] = byte((hi shl 4) or lo)

  output

proc raiseIfError(status: cint; operation: string) =
  if status != RustCryptoOk:
    raise newException(ValueError, operation & " failed with status " & $status)

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

proc sha3_256*(message: string): Sha3_256Digest =
  var output: Sha3_256Digest
  let status = sha3_256Raw(
    messagePtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_sha3_256")
  output

proc sha3_256Hex*(message: string): string =
  digestToHex(sha3_256(message))

proc keccak256*(message: string): Keccak256Digest =
  var output: Keccak256Digest
  let status = keccak256Raw(
    messagePtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_keccak_256")
  output

proc keccak256Hex*(message: string): string =
  digestToHex(keccak256(message))
