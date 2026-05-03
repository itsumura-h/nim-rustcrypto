import unittest

import ./utils
import rustcrypto/algorithm/sha256
import rustcrypto/algorithm/secp256k1

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
    check $publicKey == hexOf(publicKey)

  test "random secret key can derive a public key and sign":
    let secretKey = randomSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)
    let signature = secp256k1EcdsaSignSha256("abc", secretKey)

    check secretKey.len == Secp256k1SecretKeyLen
    check publicKey.len == Secp256k1PublicKeyCompressedLen
    check $publicKey == hexOf(publicKey)
    check $signature == hexOf(signature)
    check secp256k1EcdsaVerifySha256("abc", publicKey, signature)

  test "raw ECDSA sign produces the known deterministic signature":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    var signature: Secp256k1Signature

    let status = secp256k1EcdsaSignRaw(
      cast[ptr uint8](unsafeAddr messageDigest[0]),
      csize_t(messageDigest.len),
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoOk
    check hexOf(signature) == "75601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c28ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"

  test "high-level ECDSA sign and verify accept the known vector":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let compressedPublicKey = secp256k1PublicKeyCompressed(secretKey)
    let uncompressedPublicKey = secp256k1PublicKeyUncompressed(secretKey)
    let signature = secp256k1EcdsaSign(messageDigest, secretKey)

    check hexOf(signature) == "75601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c28ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"
    check $signature == hexOf(signature)
    check secp256k1EcdsaVerify(messageDigest, compressedPublicKey, signature)
    check secp256k1EcdsaVerify(messageDigest, uncompressedPublicKey, signature)

  test "recoverable signature stringifies as hex":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let signature = secp256k1EcdsaSignRecoverable(messageDigest, secretKey)

    check $signature == hexOf(signature)

  test "raw ECDSA verify rejects tampered signatures":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)
    var signature = secp256k1EcdsaSign(messageDigest, secretKey)

    signature[0] = signature[0] xor 0x01

    let status = secp256k1EcdsaVerifyRaw(
      cast[ptr uint8](unsafeAddr messageDigest[0]),
      csize_t(messageDigest.len),
      cast[ptr uint8](unsafeAddr publicKey[0]),
      csize_t(publicKey.len),
      Secp256k1PublicKeyFormatCompressed,
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoErrVerificationFailed

  test "high-level ECDSA verify returns false for tampered signatures":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)
    var signature = secp256k1EcdsaSign(messageDigest, secretKey)

    signature[0] = signature[0] xor 0x01

    check not secp256k1EcdsaVerify(messageDigest, publicKey, signature)

  test "high-level rejects invalid secret key":
    let secretKey = default(Secp256k1SecretKey)

    expect ValueError:
      discard secp256k1PublicKeyCompressed(secretKey)
