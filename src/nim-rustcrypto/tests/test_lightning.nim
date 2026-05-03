import unittest

import ./utils
import nim_rustcrypto/algorithm/sha256
import nim_rustcrypto/algorithm/secp256k1
import nim_rustcrypto/lightning

proc packFiveBitWords(words: openArray[byte]): string =
  var buffer: uint64 = 0
  var bits = 0
  result = newStringOfCap((words.len * 5 + 7) div 8)

  for value in words:
    buffer = (buffer shl 5) or uint64(value)
    bits += 5
    while bits >= 8:
      bits -= 8
      result.add(char((buffer shr bits) and 0xff))
      if bits > 0:
        buffer = buffer and ((uint64(1) shl bits) - 1)
      else:
        buffer = 0

  if bits > 0 and buffer != 0:
    result.add(char((buffer shl (8 - bits)) and 0xff))

suite "lightning":
  test "payment hash matches SHA-256 of the preimage":
    let preimage = default(LightningPaymentPreimage)
    check hexOf(lightningPaymentHash(preimage)) ==
      "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"

  test "node id matches the compressed secp256k1 public key":
    let secretKey = basePointSecretKey()
    check lightningNodeId(secretKey) == secp256k1PublicKeyCompressed(secretKey)

  test "invoice signing hash matches the BOLT 11 composition":
    let hrp = "lnbc"
    let dataPart = @[1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 31'u8]
    let expected = sha256(hrp & packFiveBitWords(dataPart))

    check lightningInvoiceSigningHash(hrp, dataPart) == expected

  test "invoice signing and verification round-trip":
    let hrp = "lnbc"
    let dataPart = @[1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 31'u8]
    let secretKey = basePointSecretKey()
    let nodeId = lightningNodeId(secretKey)
    let signature = lightningSignInvoice(hrp, dataPart, secretKey)

    check signature.len == 65
    check lightningVerifyInvoice(hrp, dataPart, nodeId, signature)
    check lightningVerifyInvoiceHash(lightningInvoiceSigningHash(hrp, dataPart), nodeId, signature)

    var tampered = dataPart
    tampered[0] = tampered[0] xor 0x01
    check not lightningVerifyInvoice(hrp, tampered, nodeId, signature)
