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

proc bytesFromHex(hex: string): seq[byte] =
  doAssert hex.len mod 2 == 0

  proc nibble(ch: char): byte =
    case ch
    of '0'..'9':
      byte(ord(ch) - ord('0'))
    of 'a'..'f':
      byte(ord(ch) - ord('a') + 10)
    of 'A'..'F':
      byte(ord(ch) - ord('A') + 10)
    else:
      raise newException(ValueError, "invalid hex digit")

  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte((nibble(hex[2 * i]) shl 4) or nibble(hex[2 * i + 1]))

suite "ecdsa":
  test "raw sign produces the known deterministic signature":
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

  test "high-level sign and verify accept the known vector":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let compressedPublicKey = secp256k1PublicKeyCompressed(secretKey)
    let uncompressedPublicKey = secp256k1PublicKeyUncompressed(secretKey)
    let signature = secp256k1EcdsaSign(messageDigest, secretKey)

    check hexOf(signature) == "75601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c28ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"
    check secp256k1EcdsaVerify(messageDigest, compressedPublicKey, signature)
    check secp256k1EcdsaVerify(messageDigest, uncompressedPublicKey, signature)

  test "raw verify rejects tampered signatures":
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

  test "high-level verify returns false for tampered signatures":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)
    var signature = secp256k1EcdsaSign(messageDigest, secretKey)

    signature[0] = signature[0] xor 0x01

    check not secp256k1EcdsaVerify(messageDigest, publicKey, signature)

  test "raw signature converts to the known DER vector":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let signature = secp256k1EcdsaSign(messageDigest, secretKey)
    var output = newSeq[byte](Secp256k1SignatureDerMaxLen)
    var writtenLen: csize_t

    let status = secp256k1EcdsaSignatureToDerRaw(
      cast[ptr uint8](unsafeAddr signature[0]),
      csize_t(signature.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoOk
    output.setLen(int(writtenLen))
    check int(writtenLen) == 70
    check hexOf(output) ==
      "3044022075601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c022028ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"

  test "high-level DER conversion round-trips the known vector":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let signature = secp256k1EcdsaSign(messageDigest, secretKey)

    let der = secp256k1EcdsaSignatureToDer(signature)
    check hexOf(der) ==
      "3044022075601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c022028ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"
    check secp256k1EcdsaSignatureFromDer(der) == signature

  test "raw DER conversion rejects short output buffers":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let signature = secp256k1EcdsaSign(messageDigest, secretKey)
    var output = newSeq[byte](Secp256k1SignatureDerMaxLen - 3)
    var writtenLen: csize_t

    let status = secp256k1EcdsaSignatureToDerRaw(
      cast[ptr uint8](unsafeAddr signature[0]),
      csize_t(signature.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "DER input rejects malformed signatures":
    let der = bytesFromHex("3000")
    var output: Secp256k1Signature

    let status = secp256k1EcdsaSignatureFromDerRaw(
      cast[ptr uint8](unsafeAddr der[0]),
      csize_t(der.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidSignature
