import unittest

import ./utils
import nim_rustcrypto

suite "sha3 and keccak":
  test "sha3-256 high-level abc matches the known vector":
    let expected = Sha3_256Digest.fromHexSha3_256(
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    )

    check sha3_256("abc") == expected
    check sha3_256Hex("abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"

  test "sha3-256 high-level empty string matches the known vector":
    let expected = Sha3_256Digest.fromHexSha3_256(
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )

    check sha3_256("") == expected

  test "sha3-256 raw accepts empty input via null pointer":
    var output: Sha3_256Digest
    let status = sha3_256Raw(
      nil,
      0,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check output == Sha3_256Digest.fromHexSha3_256(
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )

  test "sha3-256 raw rejects null input when length is non-zero":
    var output: Sha3_256Digest
    let status = sha3_256Raw(
      nil,
      1,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrNullInputWithData

  test "sha3-256 raw rejects null output":
    let message = "abc"
    let status = sha3_256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      nil,
      csize_t(Sha3_256DigestLen),
    )

    check status == RustCryptoErrNullOutput

  test "sha3-256 raw rejects short output buffer":
    let message = "abc"
    var output: array[Sha3_256DigestLen - 1, byte]
    let status = sha3_256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "keccak-256 high-level abc matches the known vector":
    let expected = Keccak256Digest.fromHexKeccak256(
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )

    check keccak256("abc") == expected
    check keccak256Hex("abc") == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"

  test "keccak-256 high-level empty string matches the known vector":
    let expected = Keccak256Digest.fromHexKeccak256(
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )

    check keccak256("") == expected

  test "keccak-256 raw accepts empty input via null pointer":
    var output: Keccak256Digest
    let status = keccak256Raw(
      nil,
      0,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check output == Keccak256Digest.fromHexKeccak256(
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )

  test "keccak-256 raw rejects null input when length is non-zero":
    var output: Keccak256Digest
    let status = keccak256Raw(
      nil,
      1,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrNullInputWithData

  test "keccak-256 raw rejects null output":
    let message = "abc"
    let status = keccak256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      nil,
      csize_t(Keccak256DigestLen),
    )

    check status == RustCryptoErrNullOutput

  test "keccak-256 raw rejects short output buffer":
    let message = "abc"
    var output: array[Keccak256DigestLen - 1, byte]
    let status = keccak256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw SHA3-256 sign matches the prehash signature":
    let message = "abc"
    let secretKey = basePointSecretKey()
    let messageDigest = sha3_256(message)
    let prehashSignature = secp256k1EcdsaSign(messageDigest, secretKey)
    var signature: Secp256k1Signature

    let status = secp256k1EcdsaSignSha3_256Raw(
      bytesPtr(message),
      csize_t(message.len),
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoOk
    check signature == prehashSignature

  test "high-level SHA3-256 verify rejects Keccak signatures and tampering":
    let message = "abc"
    let secretKey = basePointSecretKey()
    let compressedPublicKey = secp256k1PublicKeyCompressed(secretKey)
    let uncompressedPublicKey = secp256k1PublicKeyUncompressed(secretKey)
    let signature = secp256k1EcdsaSignSha3_256(message, secretKey)

    check secp256k1EcdsaVerifySha3_256(message, compressedPublicKey, signature)
    check secp256k1EcdsaVerifySha3_256(message, uncompressedPublicKey, signature)
    check not secp256k1EcdsaVerifyKeccak256(message, compressedPublicKey, signature)
    check not secp256k1EcdsaVerifyKeccak256(message, uncompressedPublicKey, signature)

    var tamperedSignature = signature
    tamperedSignature[0] = tamperedSignature[0] xor 0x01
    check not secp256k1EcdsaVerifySha3_256(message, compressedPublicKey, tamperedSignature)
    check not secp256k1EcdsaVerifySha3_256(message, uncompressedPublicKey, tamperedSignature)

  test "raw Keccak-256 sign matches the prehash signature":
    let message = "abc"
    let secretKey = basePointSecretKey()
    let messageDigest = keccak256(message)
    let prehashSignature = secp256k1EcdsaSign(messageDigest, secretKey)
    var signature: Secp256k1Signature

    let status = secp256k1EcdsaSignKeccak256Raw(
      bytesPtr(message),
      csize_t(message.len),
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoOk
    check signature == prehashSignature

  test "high-level Keccak-256 verify rejects SHA3 signatures and tampering":
    let message = "abc"
    let secretKey = basePointSecretKey()
    let compressedPublicKey = secp256k1PublicKeyCompressed(secretKey)
    let uncompressedPublicKey = secp256k1PublicKeyUncompressed(secretKey)
    let signature = secp256k1EcdsaSignKeccak256(message, secretKey)

    check secp256k1EcdsaVerifyKeccak256(message, compressedPublicKey, signature)
    check secp256k1EcdsaVerifyKeccak256(message, uncompressedPublicKey, signature)
    check not secp256k1EcdsaVerifySha3_256(message, compressedPublicKey, signature)
    check not secp256k1EcdsaVerifySha3_256(message, uncompressedPublicKey, signature)

    var tamperedSignature = signature
    tamperedSignature[0] = tamperedSignature[0] xor 0x01
    check not secp256k1EcdsaVerifyKeccak256(message, compressedPublicKey, tamperedSignature)
    check not secp256k1EcdsaVerifyKeccak256(message, uncompressedPublicKey, tamperedSignature)
