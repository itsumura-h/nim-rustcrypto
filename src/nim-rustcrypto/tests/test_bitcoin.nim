import unittest

import ./utils
import rustcrypto/algorithm/sha256
import rustcrypto/algorithm/secp256k1
import rustcrypto/algorithm/schnorr
import rustcrypto/bitcoin

proc basePointSchnorrSecretKey(): SchnorrSecretKey =
  result = default(SchnorrSecretKey)
  result[Secp256k1SecretKeyLen - 1] = 1

suite "bitcoin":
  test "message hash matches the Bitcoin Signed Message vector":
    check hexOf(bitcoinMessageHash("abc")) ==
      "107a79deef4b17e0de11070a45433aebc60ab26cd3d3a0f3735accefd0fd373b"

  test "tagged hash matches the BIP340 style vector":
    check hexOf(bitcoinTaggedHash("TapTweak", bytesFromString("abc"))) ==
      "b4db0a539110ab84dac5af069f081eee7e3becbf970e6705d20f59ea9b4eb1f8"

  test "message signing and verification round-trip":
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)
    let signature = bitcoinSignMessage("abc", secretKey)

    check signature.len == 65
    check bitcoinVerifyMessage("abc", publicKey, signature)
    check not bitcoinVerifyMessage("abd", publicKey, signature)

  test "ECDSA digest signing and verification round-trip":
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyCompressed(secretKey)
    let digest = sha256("abc")
    let signature = bitcoinSignDigestEcdsa(digest, secretKey)

    check bitcoinVerifyDigestEcdsa(digest, publicKey, signature)

  test "Taproot digest signing and verification round-trip":
    let secretKey = basePointSchnorrSecretKey()
    let publicKey = schnorrPublicKey(secretKey)
    let digest = sha256("abc")
    let signature = bitcoinSignTaprootDigest(digest, secretKey)

    check bitcoinVerifyTaprootDigest(digest, publicKey, signature)
    var tampered = signature
    tampered[0] = tampered[0] xor 0x01
    check not bitcoinVerifyTaprootDigest(digest, publicKey, tampered)

  test "marker type API round-trips":
    let secretKey = Secp256k1.generateSecretKey()
    let publicKeyCompressed = Secp256k1.publicKeyCompressed(secretKey)
    let publicKeyUncompressed = Secp256k1.publicKeyUncompressed(secretKey)
    let messageSignature = Bitcoin.signMessage("abc", secretKey)
    let digest = Bitcoin.messageHash("abc")
    let digestSignature = Bitcoin.signDigestEcdsa(digest, secretKey)
    let taprootSecretKey = Schnorr.generateSecretKey()
    let taprootPublicKey = Schnorr.publicKey(taprootSecretKey)
    let taprootSignature = Bitcoin.signTaprootDigest(digest, taprootSecretKey)

    check Bitcoin.hash256(bytesFromString("abc")) == bitcoinHash256(bytesFromString("abc"))
    check Bitcoin.taggedHash("TapTweak", bytesFromString("abc")) == bitcoinTaggedHash("TapTweak", bytesFromString("abc"))
    check Bitcoin.messageHash("abc") == bitcoinMessageHash("abc")
    check Bitcoin.verifyMessage("abc", publicKeyCompressed, messageSignature)
    check Bitcoin.verifyDigestEcdsa(digest, publicKeyCompressed, digestSignature)
    check Bitcoin.verifyTaprootDigest(digest, taprootPublicKey, taprootSignature)
    check Secp256k1.generateSecretKey().len == Secp256k1SecretKeyLen
    check publicKeyUncompressed.len == Secp256k1PublicKeyUncompressedLen
