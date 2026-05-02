import ./ffi
import ./utils

type
  Sha256Digest* = array[SHA256DigestLen, byte]

proc fromHex*(_: type Sha256Digest, hex: string): Sha256Digest =
  fromHexDigest[Sha256Digest](hex, SHA256DigestLen)

proc raiseIfError(status: cint) =
  if status != RustCryptoOk:
    raise newException(ValueError, "rustcrypto_sha256 failed with status " & $status)

proc sha256*(message: string): Sha256Digest =
  var output: Sha256Digest
  let status = sha256Raw(
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status)
  output

proc sha256Hex*(message: string): string =
  digestToHex(Sha256Digest, sha256(message))
