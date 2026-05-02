import ./ffi
import ./utils

type
  Secp256k1SecretKey* = array[Secp256k1SecretKeyLen, byte]
  Secp256k1CompressedPublicKey* = array[Secp256k1PublicKeyCompressedLen, byte]
  Secp256k1UncompressedPublicKey* = array[Secp256k1PublicKeyUncompressedLen, byte]

proc secp256k1PublicKeyCompressed*(secretKey: Secp256k1SecretKey): Secp256k1CompressedPublicKey =
  var output: Secp256k1CompressedPublicKey
  let status = secp256k1PublicKeyFromSecretKeyRaw(
    cast[ptr uint8](unsafeAddr secretKey[0]),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    Secp256k1PublicKeyFormatCompressed,
  )
  raiseIfError(status, "rustcrypto_secp256k1_public_key_from_secret_key")
  output

proc secp256k1PublicKeyUncompressed*(secretKey: Secp256k1SecretKey): Secp256k1UncompressedPublicKey =
  var output: Secp256k1UncompressedPublicKey
  let status = secp256k1PublicKeyFromSecretKeyRaw(
    cast[ptr uint8](unsafeAddr secretKey[0]),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    Secp256k1PublicKeyFormatUncompressed,
  )
  raiseIfError(status, "rustcrypto_secp256k1_public_key_from_secret_key")
  output
