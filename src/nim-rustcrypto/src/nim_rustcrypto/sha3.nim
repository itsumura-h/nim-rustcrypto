import ./ffi
import ./utils

type
  Sha3_256Digest* = array[Sha3_256DigestLen, byte]
  Keccak256Digest* = array[Keccak256DigestLen, byte]

proc fromHexSha3_256*(_: type Sha3_256Digest, hex: string): Sha3_256Digest =
  fromHexDigest[Sha3_256Digest](hex, Sha3_256DigestLen)

proc fromHexKeccak256*(_: type Keccak256Digest, hex: string): Keccak256Digest =
  fromHexDigest[Keccak256Digest](hex, Keccak256DigestLen)

proc raiseIfError(status: cint; operation: string) =
  if status != RustCryptoOk:
    raise newException(ValueError, operation & " failed with status " & $status)

proc sha3_256*(message: string): Sha3_256Digest =
  var output: Sha3_256Digest
  let status = sha3_256Raw(
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_sha3_256")
  output

proc sha3_256Hex*(message: string): string =
  digestToHex(Sha3_256Digest, sha3_256(message))

proc keccak256*(message: string): Keccak256Digest =
  var output: Keccak256Digest
  let status = keccak256Raw(
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_keccak_256")
  output

proc keccak256Hex*(message: string): string =
  digestToHex(Keccak256Digest, keccak256(message))
