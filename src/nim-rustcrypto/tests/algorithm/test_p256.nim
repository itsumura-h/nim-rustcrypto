import unittest

import ./utils
import rustcrypto/algorithm/p256
import rustcrypto/algorithm/sha256

suite "p256":
  const
    SecretKeyHex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    PublicKeyUncompressedHex =
      "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" &
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    PublicKeyCompressedHex =
      "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    SignatureHex =
      "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" &
      "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"

  test "public key derivation matches the RFC 6979 vector":
    let secretKey = fromHexSecretKey(SecretKeyHex)

    let compressed = p256PublicKeyCompressed(secretKey)
    let uncompressed = p256PublicKeyUncompressed(secretKey)

    check hexOf(compressed) == PublicKeyCompressedHex
    check hexOf(uncompressed) == PublicKeyUncompressedHex
    check $compressed == hexOf(compressed)
    check $uncompressed == hexOf(uncompressed)

  test "random secret key can derive public key and sign":
    let secretKey = randomSecretKey()
    let publicKey = p256PublicKeyCompressed(secretKey)
    let signature = p256EcdsaSignSha256("test", secretKey)

    check secretKey.len == P256SecretKeyLen
    check publicKey.len == P256PublicKeyCompressedLen
    check $publicKey == hexOf(publicKey)
    check $signature == hexOf(signature)
    check p256EcdsaVerifySha256("test", publicKey, P256PublicKeyFormatCompressed, signature)

  test "signing matches the RFC 6979 vector":
    let secretKey = fromHexSecretKey(SecretKeyHex)

    check hexOf(p256EcdsaSignSha256("test", secretKey)) == SignatureHex

  test "verify accepts the RFC 6979 vector":
    let publicKey = fromHexPublicKeyCompressed(PublicKeyCompressedHex)
    let signature = fromHexSignature(SignatureHex)

    check p256EcdsaVerifySha256("test", publicKey, P256PublicKeyFormatCompressed, signature)

  test "prehash signing matches the RFC 6979 vector":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    let digest = sha256("test")

    check hexOf(p256EcdsaSignPrehash(digest, secretKey)) == SignatureHex

  test "prehash verification accepts the RFC 6979 vector":
    let publicKey = fromHexPublicKeyUncompressed(PublicKeyUncompressedHex)
    let signature = fromHexSignature(SignatureHex)
    let digest = sha256("test")

    check p256EcdsaVerifyPrehash(digest, publicKey, P256PublicKeyFormatUncompressed, signature)

  test "public key SPKI round-trip preserves both encodings":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    let compressed = p256PublicKeyCompressed(secretKey)
    let uncompressed = p256PublicKeyUncompressed(secretKey)
    let compressedSpki = p256PublicKeyToSpkiDer(compressed, P256PublicKeyFormatCompressed)
    let uncompressedSpki = p256PublicKeyToSpkiDer(uncompressed, P256PublicKeyFormatUncompressed)

    check compressedSpki == uncompressedSpki
    check $compressedSpki == hexOf(compressedSpki)
    check $uncompressedSpki == hexOf(uncompressedSpki)
    check hexOf(p256PublicKeyFromSpkiDer(compressedSpki, P256PublicKeyFormatCompressed)) == PublicKeyCompressedHex
    check hexOf(p256PublicKeyFromSpkiDer(uncompressedSpki, P256PublicKeyFormatUncompressed)) == PublicKeyUncompressedHex

  test "private key PKCS#8 round-trip preserves the raw scalar":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    let der = p256PrivateKeyToPkcs8Der(secretKey)

    check p256PrivateKeyFromPkcs8Der(der) == secretKey

  test "raw signing rejects short output buffers":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    var output = newSeq[byte](P256SignatureLen - 1)

    let status = p256EcdsaSignSha256Raw(
      bytesPtr("test"),
      csize_t(4),
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw public key derivation rejects short output buffers":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    var output = newSeq[byte](P256PublicKeyCompressedLen - 1)

    let status = p256PublicKeyFromSecretKeyRaw(
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      bytesPtr(output),
      csize_t(output.len),
      P256PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw public key decoder rejects malformed DER":
    let der = bytesFromHex("3000")
    var output: P256CompressedPublicKey

    let status = p256PublicKeyFromSpkiDerRaw(
      bytesPtr(der),
      csize_t(der.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      P256PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrInvalidParameter
