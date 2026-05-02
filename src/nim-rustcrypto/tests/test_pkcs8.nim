import unittest

import nim_rustcrypto

proc hexOf(bytes: openArray[byte]): string =
  const hexDigits = "0123456789abcdef"
  result = newString(bytes.len * 2)
  for i, value in bytes:
    let byteValue = int(value)
    result[2 * i] = hexDigits[byteValue shr 4]
    result[2 * i + 1] = hexDigits[byteValue and 0x0F]

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

suite "pkcs8":
  test "raw private key encodes to the RFC 8410 example":
    let privateKey = fromHexPrivateKey(
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    )
    let der = ed25519PrivateKeyToPkcs8Der(privateKey)
    check hexOf(der) ==
      "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"

  test "raw private key decodes from the RFC 8410 example":
    let der = bytesFromHex(
      "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    )
    let privateKey = ed25519PrivateKeyFromPkcs8Der(der)
    check hexOf(privateKey) ==
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"

  test "raw public key encodes to the RFC 8410 example":
    let publicKey = fromHexPublicKey(
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )
    let der = ed25519PublicKeyToSpkiDer(publicKey)
    check hexOf(der) ==
      "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"

  test "raw public key decodes from the RFC 8410 example":
    let der = bytesFromHex(
      "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )
    let publicKey = ed25519PublicKeyFromSpkiDer(der)
    check hexOf(publicKey) ==
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"

  test "raw private key encoder rejects short output buffers":
    let privateKey = fromHexPrivateKey(
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    )
    var output = newSeq[byte](Ed25519PrivateKeyDerMaxLen - 1)
    var writtenLen: csize_t

    let status = ed25519PrivateKeyToPkcs8DerRaw(
      bytesPtr(privateKey),
      csize_t(privateKey.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw public key encoder rejects short output buffers":
    let publicKey = fromHexPublicKey(
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )
    var output = newSeq[byte](Ed25519PublicKeyDerMaxLen - 1)
    var writtenLen: csize_t

    let status = ed25519PublicKeyToSpkiDerRaw(
      bytesPtr(publicKey),
      csize_t(publicKey.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw private key decoder rejects malformed DER":
    let der = bytesFromHex("3000")
    var output: Ed25519PrivateKey

    let status = ed25519PrivateKeyFromPkcs8DerRaw(
      bytesPtr(der),
      csize_t(der.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidParameter

  test "raw public key decoder rejects malformed DER":
    let der = bytesFromHex("3000")
    var output: Ed25519PublicKey

    let status = ed25519PublicKeyFromSpkiDerRaw(
      bytesPtr(der),
      csize_t(der.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidParameter
