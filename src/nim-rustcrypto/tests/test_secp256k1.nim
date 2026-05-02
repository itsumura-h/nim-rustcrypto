import unittest

import nim_rustcrypto

proc hexOf(bytes: openArray[byte]): string =
  const hexDigits = "0123456789abcdef"
  result = newString(bytes.len * 2)
  for i, value in bytes:
    let byteValue = int(value)
    result[2 * i] = hexDigits[byteValue shr 4]
    result[2 * i + 1] = hexDigits[byteValue and 0x0F]

proc basePointSecretKey(): Secp256k1SecretKey =
  result = default(Secp256k1SecretKey)
  result[Secp256k1SecretKeyLen - 1] = 1

suite "secp256k1":
  test "raw compressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoOk
    echo "compressed public key = ", hexOf(output)
    check hexOf(output) == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  test "raw uncompressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    var output: Secp256k1UncompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatUncompressed,
    )

    check status == RustCryptoOk
    echo "uncompressed public key = ", hexOf(output)
    check hexOf(output) == "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

  test "raw rejects null output":
    let secretKey = basePointSecretKey()

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      nil,
      csize_t(Secp256k1PublicKeyCompressedLen),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrNullOutput

  test "raw rejects short output buffer":
    let secretKey = basePointSecretKey()
    var output: array[Secp256k1PublicKeyCompressedLen - 1, byte]

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw rejects null input with data":
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      nil,
      csize_t(Secp256k1SecretKeyLen),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrNullInputWithData

  test "raw rejects invalid secret key":
    let secretKey = default(Secp256k1SecretKey)
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrInvalidSecretKey

  test "raw rejects invalid public key format":
    let secretKey = basePointSecretKey()
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      2,
    )

    check status == RustCryptoErrInvalidPublicKeyFormat

  test "high-level compressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)

    check hexOf(publicKey) == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  test "high-level uncompressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyUncompressed(secretKey)

    check hexOf(publicKey) == "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

  test "high-level rejects invalid secret key":
    let secretKey = default(Secp256k1SecretKey)

    expect ValueError:
      discard secp256k1PublicKeyCompressed(secretKey)
