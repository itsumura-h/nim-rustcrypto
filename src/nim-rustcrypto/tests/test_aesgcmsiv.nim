import unittest

import nim_rustcrypto
import nim_rustcrypto/aesgcmsiv

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

suite "aes-gcm-siv":
  test "raw encrypt matches the RFC 8452 vector":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let plaintext = bytesFromHex("0100000000000000")
    var ciphertext = newSeq[byte](plaintext.len)
    var tag: Aes256GcmSivTag

    let status = aes256GcmSivEncryptRaw(
      bytesPtr(key),
      csize_t(key.len),
      bytesPtr(nonce),
      csize_t(nonce.len),
      bytesPtr(aad),
      csize_t(aad.len),
      bytesPtr(plaintext),
      csize_t(plaintext.len),
      bytesPtr(ciphertext),
      csize_t(ciphertext.len),
      cast[ptr uint8](addr tag[0]),
      csize_t(tag.len),
    )

    check status == RustCryptoOk
    check hexOf(ciphertext) == "c2ef328e5c71c83b"
    check hexOf(tag) == "843122130f7364b761e0b97427e3df28"

  test "raw decrypt matches the RFC 8452 vector":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let ciphertext = bytesFromHex("c2ef328e5c71c83b")
    let tag = aesgcmsiv.fromHexTag("843122130f7364b761e0b97427e3df28")
    var plaintext = newSeq[byte](ciphertext.len)

    let status = aes256GcmSivDecryptRaw(
      bytesPtr(key),
      csize_t(key.len),
      bytesPtr(nonce),
      csize_t(nonce.len),
      bytesPtr(aad),
      csize_t(aad.len),
      bytesPtr(ciphertext),
      csize_t(ciphertext.len),
      cast[ptr uint8](unsafeAddr tag[0]),
      csize_t(tag.len),
      bytesPtr(plaintext),
      csize_t(plaintext.len),
    )

    check status == RustCryptoOk
    check hexOf(plaintext) == "0100000000000000"

  test "raw decrypt rejects tampered tag":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let ciphertext = bytesFromHex("c2ef328e5c71c83b")
    var tag = aesgcmsiv.fromHexTag("843122130f7364b761e0b97427e3df28")
    var plaintext = newSeq[byte](ciphertext.len)
    tag[0] = tag[0] xor 0x01

    let status = aes256GcmSivDecryptRaw(
      bytesPtr(key),
      csize_t(key.len),
      bytesPtr(nonce),
      csize_t(nonce.len),
      bytesPtr(aad),
      csize_t(aad.len),
      bytesPtr(ciphertext),
      csize_t(ciphertext.len),
      cast[ptr uint8](addr tag[0]),
      csize_t(tag.len),
      bytesPtr(plaintext),
      csize_t(plaintext.len),
    )

    check status == RustCryptoErrAuthenticationFailed

  test "high-level encrypt and decrypt match the RFC 8452 vector":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let plaintext = bytesFromHex("0100000000000000")

    let (ciphertext, tag) = aes256gcmsivEncrypt(key, nonce, plaintext, aad)
    check hexOf(ciphertext) == "c2ef328e5c71c83b"
    check hexOf(tag) == "843122130f7364b761e0b97427e3df28"
    check aes256gcmsivDecrypt(key, nonce, ciphertext, tag, aad) == plaintext
