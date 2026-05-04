import ./algorithm/sha256
import ./algorithm/secp256k1

type
  Lightning* = object
  LightningPaymentPreimage* = array[32, byte]
  LightningPaymentHash* = Sha256Digest
  LightningPaymentSecret* = array[32, byte]
  LightningNodeId* = Secp256k1CompressedPublicKey
  LightningInvoiceSignature* = Secp256k1RecoverableSignature

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

proc packFiveBitWords(words: openArray[byte]): string =
  var buffer: uint64 = 0
  var bits = 0
  result = newStringOfCap((words.len * 5 + 7) div 8)

  for value in words:
    if value > 31:
      raise newException(ValueError, "lightning invoice data part contains a non-5-bit value")
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

proc lightningPaymentHash(preimage: LightningPaymentPreimage): LightningPaymentHash =
  sha256(bytesToString(preimage))

proc paymentHash*(T: type Lightning, preimage: LightningPaymentPreimage): LightningPaymentHash =
  lightningPaymentHash(preimage)

proc lightningNodeId(secretKey: Secp256k1SecretKey): LightningNodeId =
  Secp256k1.publicKeyCompressed(secretKey)

proc nodeId*(T: type Lightning, secretKey: Secp256k1SecretKey): LightningNodeId =
  lightningNodeId(secretKey)

proc lightningInvoiceSigningHash(
    hrp: string,
    dataPartWithoutSignature: openArray[byte],
  ): Sha256Digest =
  sha256(hrp & packFiveBitWords(dataPartWithoutSignature))

proc invoiceSigningHash*(
    T: type Lightning,
    hrp: string,
    dataPartWithoutSignature: openArray[byte],
  ): Sha256Digest =
  lightningInvoiceSigningHash(hrp, dataPartWithoutSignature)

proc lightningSignInvoice(
    hrp: string,
    dataPartWithoutSignature: openArray[byte],
    secretKey: Secp256k1SecretKey,
  ): LightningInvoiceSignature =
  let digest = lightningInvoiceSigningHash(hrp, dataPartWithoutSignature)
  Secp256k1.signRecoverable(digest, secretKey)

proc signInvoice*(
    T: type Lightning,
    hrp: string,
    dataPartWithoutSignature: openArray[byte],
    secretKey: Secp256k1SecretKey,
  ): LightningInvoiceSignature =
  lightningSignInvoice(hrp, dataPartWithoutSignature, secretKey)

proc lightningVerifyInvoice(
    hrp: string,
    dataPartWithoutSignature: openArray[byte],
    nodeId: LightningNodeId,
    signature: LightningInvoiceSignature,
  ): bool =
  let digest = lightningInvoiceSigningHash(hrp, dataPartWithoutSignature)
  Secp256k1.verifyRecoverable(digest, nodeId, signature)

proc verifyInvoice*(
    T: type Lightning,
    hrp: string,
    dataPartWithoutSignature: openArray[byte],
    nodeId: LightningNodeId,
    signature: LightningInvoiceSignature,
  ): bool =
  lightningVerifyInvoice(hrp, dataPartWithoutSignature, nodeId, signature)

proc lightningVerifyInvoiceHash(
    signingHash: Sha256Digest,
    nodeId: LightningNodeId,
    signature: LightningInvoiceSignature,
  ): bool =
  Secp256k1.verifyRecoverable(signingHash, nodeId, signature)

proc verifyInvoiceHash*(
    T: type Lightning,
    signingHash: Sha256Digest,
    nodeId: LightningNodeId,
    signature: LightningInvoiceSignature,
  ): bool =
  lightningVerifyInvoiceHash(signingHash, nodeId, signature)
