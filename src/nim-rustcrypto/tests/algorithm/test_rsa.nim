import unittest

import ./utils
import rustcrypto/algorithm/rsa

suite "rsa":
  test "private and public key DER normalize from the fixtures":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)

    check rsaPrivateKeyToPkcs8Der(privateKeyDer) == privateKeyDer
    check rsaPrivateKeyFromPkcs8Der(privateKeyDer) == privateKeyDer
    check rsaPublicKeyToSpkiDer(publicKeyDer) == publicKeyDer
    check rsaPublicKeyFromSpkiDer(publicKeyDer) == publicKeyDer
    check $publicKeyDer == hexOf(publicKeyDer)

  test "PSS signing and verification round-trip with the fixture key":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    let signature = rsaPssSignSha256("test", privateKeyDer)

    check signature.len == 256
    check $signature == hexOf(signature)
    check rsaPssVerifySha256("test", publicKeyDer, signature)
    check not rsaPssVerifySha256("test!", publicKeyDer, signature)

    var tampered = signature
    tampered[0] = tampered[0] xor 0x01
    check not rsaPssVerifySha256("test", publicKeyDer, tampered)

  test "PKCS#1 v1.5 signing and verification round-trip with the fixture key":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    let signature = rsaPkcs1v15SignSha256("test", privateKeyDer)

    check signature.len == 256
    check $signature == hexOf(signature)
    check rsaPkcs1v15VerifySha256("test", publicKeyDer, signature)
    check not rsaPkcs1v15VerifySha256("test!", publicKeyDer, signature)

  test "OAEP encrypt and decrypt round-trip with and without labels":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    let plaintext = bytesFromString("hello rsa")

    let ciphertext = rsaOaepSha256Encrypt(plaintext, publicKeyDer, "context")
    check ciphertext.len == 256
    check rsaOaepSha256Decrypt(ciphertext, privateKeyDer, "context") == plaintext

    expect ValueError:
      discard rsaOaepSha256Decrypt(ciphertext, privateKeyDer, "wrong")

  test "PKCS#1 v1.5 encrypt and decrypt round-trip":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    let plaintext = bytesFromString("legacy compat")

    let ciphertext = rsaPkcs1v15Encrypt(plaintext, publicKeyDer)
    check ciphertext.len == 256
    check rsaPkcs1v15Decrypt(ciphertext, privateKeyDer) == plaintext

  test "raw signing rejects short output buffers":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    var output = newSeq[byte](1)
    var writtenLen: csize_t

    let status = rsaPssSignSha256Raw(
      bytesPtr("test"),
      csize_t(4),
      bytesPtr(privateKeyDer),
      csize_t(privateKeyDer.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw verification rejects tampered signatures":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    var signature = rsaPssSignSha256("test", privateKeyDer)
    signature[0] = signature[0] xor 0x01

    let status = rsaPssVerifySha256Raw(
      bytesPtr("test"),
      csize_t(4),
      bytesPtr(publicKeyDer),
      csize_t(publicKeyDer.len),
      bytesPtr(signature),
      csize_t(signature.len),
    )

    check status == RustCryptoErrVerificationFailed

  test "raw decrypt rejects short output buffers":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    let ciphertext = rsaOaepSha256Encrypt(bytesFromString("hello rsa"), publicKeyDer, "context")
    var output = newSeq[byte](1)
    var writtenLen: csize_t

    let status = rsaOaepSha256DecryptRaw(
      bytesPtr(ciphertext),
      csize_t(ciphertext.len),
      bytesPtr(privateKeyDer),
      csize_t(privateKeyDer.len),
      bytesPtr("context"),
      csize_t("context".len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort
