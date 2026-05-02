import unittest

import ./utils
import nim_rustcrypto


suite "sha256":
  test "sha256 high-level abc matches the known vector":
    let expected = Sha256Digest.fromHex(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    let actual = sha256Hex("abc")

    check sha256("abc") == expected
    check actual == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

  test "sha256 high-level empty string matches the known vector":
    let expected = Sha256Digest.fromHex(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    check sha256("") == expected

  test "sha256 raw accepts empty input via null pointer":
    var output: Sha256Digest
    let status = sha256Raw(
      nil,
      0,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check output == Sha256Digest.fromHex(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

  test "sha256 raw rejects null input when length is non-zero":
    var output: Sha256Digest
    let status = sha256Raw(
      nil,
      1,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrNullInputWithData

  test "sha256 raw rejects null output":
    let message = "abc"
    let status = sha256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      nil,
      csize_t(SHA256DigestLen),
    )

    check status == RustCryptoErrNullOutput

  test "sha256 raw rejects short output buffer":
    let message = "abc"
    var output: array[SHA256DigestLen - 1, byte]
    let status = sha256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw SHA-256 sign matches the prehash signature":
    let message = "abc"
    let secretKey = basePointSecretKey()
    let messageDigest = sha256(message)
    let prehashSignature = secp256k1EcdsaSign(messageDigest, secretKey)
    var signature: Secp256k1Signature

    let status = secp256k1EcdsaSignSha256Raw(
      bytesPtr(message),
      csize_t(message.len),
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoOk
    check signature == prehashSignature

  test "high-level SHA-256 sign and verify accept the message text":
    let message = "abc"
    let secretKey = basePointSecretKey()
    let compressedPublicKey = secp256k1PublicKeyCompressed(secretKey)
    let uncompressedPublicKey = secp256k1PublicKeyUncompressed(secretKey)
    let messageDigest = sha256(message)
    let prehashSignature = secp256k1EcdsaSign(messageDigest, secretKey)
    let signature = secp256k1EcdsaSignSha256(message, secretKey)

    check signature == prehashSignature
    check secp256k1EcdsaVerifySha256(message, compressedPublicKey, signature)
    check secp256k1EcdsaVerifySha256(message, uncompressedPublicKey, signature)
    check not secp256k1EcdsaVerifySha256("abd", compressedPublicKey, signature)

  test "raw SHA-256 verify rejects tampering":
    let message = "abc"
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)
    let signature = secp256k1EcdsaSignSha256(message, secretKey)
    var tamperedSignature = signature
    tamperedSignature[0] = tamperedSignature[0] xor 0x01

    let status = secp256k1EcdsaVerifySha256Raw(
      bytesPtr(message),
      csize_t(message.len),
      cast[ptr uint8](unsafeAddr publicKey[0]),
      csize_t(publicKey.len),
      Secp256k1PublicKeyFormatCompressed,
      cast[ptr uint8](addr tamperedSignature[0]),
      csize_t(tamperedSignature.len),
    )

    check status == RustCryptoErrVerificationFailed
