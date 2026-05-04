import unittest

import ./utils
import rustcrypto/algorithm/secp256k1
import rustcrypto/ethereum

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

suite "ethereum":
  test "address derivation matches the keccak tail of the uncompressed public key":
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyUncompressed(secretKey)
    let digest = ethereumKeccak256(publicKey[1 ..< publicKey.len])
    var expected: EthereumAddress
    for i in 0 ..< expected.len:
      expected[i] = digest[digest.len - expected.len + i]

    check ethereumAddress(publicKey) == expected

  test "personal message hashing matches the EIP-191 composition":
    let message = "abc"
    let expected = ethereumKeccak256(
      bytesFromString("\x19Ethereum Signed Message:\n" & $message.len & message)
    )

    check ethereumPersonalMessageHash(message) == expected

  test "typed data hashing matches the EIP-712 composition":
    let domain = fromHexDigest[EthereumHash](
      "1111111111111111111111111111111111111111111111111111111111111111",
      32,
    )
    let structHash = fromHexDigest[EthereumHash](
      "2222222222222222222222222222222222222222222222222222222222222222",
      32,
    )
    let expected = ethereumKeccak256(
      bytesFromString("\x19\x01" & bytesToString(domain) & bytesToString(structHash))
    )

    check ethereumTypedDataHash(domain, structHash) == expected

  test "personal message signing and verification round-trip":
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyUncompressed(secretKey)
    let signature = ethereumSignPersonalMessage("abc", secretKey)

    check signature.v == 27'u8 or signature.v == 28'u8
    check ethereumVerifyPersonalMessage("abc", publicKey, signature)
    check not ethereumVerifyPersonalMessage("abd", publicKey, signature)

    let signature155 = ethereumSignPersonalMessage("abc", secretKey, 1)
    check signature155.v == 37'u8 or signature155.v == 38'u8
    check ethereumVerifyPersonalMessage("abc", publicKey, signature155)

  test "typed data signing and verification round-trip":
    let secretKey = basePointSecretKey()
    let publicKey = secp256k1PublicKeyUncompressed(secretKey)
    let domain = fromHexDigest[EthereumHash](
      "1111111111111111111111111111111111111111111111111111111111111111",
      32,
    )
    let structHash = fromHexDigest[EthereumHash](
      "2222222222222222222222222222222222222222222222222222222222222222",
      32,
    )
    let signature = ethereumSignTypedDataHash(domain, structHash, secretKey, 5)

    check signature.v == 45'u8 or signature.v == 46'u8
    check ethereumVerifyTypedDataHash(domain, structHash, publicKey, signature)

    let tamperedStruct = fromHexDigest[EthereumHash](
      "3333333333333333333333333333333333333333333333333333333333333333",
      32,
    )
    check not ethereumVerifyTypedDataHash(domain, tamperedStruct, publicKey, signature)
