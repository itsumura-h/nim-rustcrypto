import unittest

import ./utils
import rustcrypto/algorithm/p384

suite "p384":
  const
    SecretKeyHex = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8" &
      "96d5724e4c70a825f872c9ea60d2edf5"
    PublicKeyUncompressedHex =
      "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64" &
      "def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c6218967" &
      "08a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720"
    PublicKeyCompressedHex =
      "02ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64" &
      "def8f0ea9055866064a254515480bc13"
    SignatureHex =
      "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb" &
      "0542a7f0812998da8f1dd3ca3cf023dbddd0760448d42d8a43af45af836fce4d" &
      "e8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5"
    DigestHex =
      "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4" &
      "b7ef1ccb126255d196047dfedf17a0a9"

  test "public key derivation matches the RFC 6979 vector":
    let secretKey = fromHexSecretKey(SecretKeyHex)

    let compressed = p384PublicKeyCompressed(secretKey)
    let uncompressed = p384PublicKeyUncompressed(secretKey)

    check hexOf(compressed) == PublicKeyCompressedHex
    check hexOf(uncompressed) == PublicKeyUncompressedHex
    check $compressed == hexOf(compressed)
    check $uncompressed == hexOf(uncompressed)

  test "random secret key can derive public key and sign":
    let secretKey = randomSecretKey()
    let publicKey = p384PublicKeyCompressed(secretKey)
    let signature = p384EcdsaSignSha384("test", secretKey)

    check secretKey.len == P384SecretKeyLen
    check publicKey.len == P384PublicKeyCompressedLen
    check $publicKey == hexOf(publicKey)
    check $signature == hexOf(signature)
    check p384EcdsaVerifySha384("test", publicKey, P384PublicKeyFormatCompressed, signature)

  test "signing matches the RFC 6979 vector":
    let secretKey = fromHexSecretKey(SecretKeyHex)

    check hexOf(p384EcdsaSignSha384("test", secretKey)) == SignatureHex

  test "verify accepts the RFC 6979 vector":
    let publicKey = fromHexPublicKeyCompressed(PublicKeyCompressedHex)
    let signature = fromHexSignature(SignatureHex)

    check p384EcdsaVerifySha384("test", publicKey, P384PublicKeyFormatCompressed, signature)

  test "prehash signing matches the RFC 6979 vector":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    let digest = fromHexMessageDigest(DigestHex)

    check hexOf(p384EcdsaSignPrehash(digest, secretKey)) == SignatureHex

  test "prehash verification accepts the RFC 6979 vector":
    let publicKey = fromHexPublicKeyUncompressed(PublicKeyUncompressedHex)
    let signature = fromHexSignature(SignatureHex)
    let digest = fromHexMessageDigest(DigestHex)

    check p384EcdsaVerifyPrehash(digest, publicKey, P384PublicKeyFormatUncompressed, signature)

  test "public key SPKI round-trip preserves both encodings":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    let compressed = p384PublicKeyCompressed(secretKey)
    let uncompressed = p384PublicKeyUncompressed(secretKey)
    let compressedSpki = p384PublicKeyToSpkiDer(compressed, P384PublicKeyFormatCompressed)
    let uncompressedSpki = p384PublicKeyToSpkiDer(uncompressed, P384PublicKeyFormatUncompressed)

    check compressedSpki == uncompressedSpki
    check $compressedSpki == hexOf(compressedSpki)
    check $uncompressedSpki == hexOf(uncompressedSpki)
    check hexOf(p384PublicKeyFromSpkiDer(compressedSpki, P384PublicKeyFormatCompressed)) == PublicKeyCompressedHex
    check hexOf(p384PublicKeyFromSpkiDer(uncompressedSpki, P384PublicKeyFormatUncompressed)) == PublicKeyUncompressedHex

  test "private key PKCS#8 round-trip preserves the raw scalar":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    let der = p384PrivateKeyToPkcs8Der(secretKey)

    check p384PrivateKeyFromPkcs8Der(der) == secretKey

  test "raw signing rejects short output buffers":
    let secretKey = fromHexSecretKey(SecretKeyHex)
    var output = newSeq[byte](P384SignatureLen - 1)

    let status = p384EcdsaSignSha384Raw(
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
    var output = newSeq[byte](P384PublicKeyCompressedLen - 1)

    let status = p384PublicKeyFromSecretKeyRaw(
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      bytesPtr(output),
      csize_t(output.len),
      P384PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw public key decoder rejects malformed DER":
    let der = bytesFromHex("3000")
    var output: P384CompressedPublicKey

    let status = p384PublicKeyFromSpkiDerRaw(
      bytesPtr(der),
      csize_t(der.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      P384PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrInvalidParameter
