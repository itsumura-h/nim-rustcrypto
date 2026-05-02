import ./ffi
import ./sha256
import ./secp256k1
import ./utils

type
  Secp256k1MessageDigest* = Sha256Digest
  Secp256k1Signature* = array[Secp256k1SignatureLen, byte]
  Secp256k1DerSignature* = seq[byte]

proc raiseSignError(status: cint) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_sign_prehash failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_sign_prehash failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_sign_prehash failed: null input with data")
  of RustCryptoErrInvalidMessageDigest:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_sign_prehash failed: invalid message digest")
  of RustCryptoErrInvalidSecretKey:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_sign_prehash failed: invalid secret key")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_sign_prehash failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_secp256k1_ecdsa_sign_prehash failed: unexpected status " & $status,
    )

proc verifyStatus(status: cint): bool =
  case status
  of RustCryptoOk:
    true
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_verify_prehash failed: null input with data")
  of RustCryptoErrInvalidMessageDigest:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_verify_prehash failed: invalid message digest")
  of RustCryptoErrInvalidPublicKeyFormat:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_verify_prehash failed: invalid public key format")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_verify_prehash failed: invalid signature")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_secp256k1_ecdsa_verify_prehash failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_secp256k1_ecdsa_verify_prehash failed: unexpected status " & $status,
    )

proc raiseSignatureDerError(status: cint; operation: string) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, operation & " failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, operation & " failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, operation & " failed: invalid signature")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc secp256k1EcdsaSign*(
    messageDigest: Secp256k1MessageDigest,
    secretKey: Secp256k1SecretKey,
  ): Secp256k1Signature =
  var output: Secp256k1Signature
  let status = secp256k1EcdsaSignRaw(
    cast[ptr uint8](unsafeAddr messageDigest[0]),
    csize_t(messageDigest.len),
    cast[ptr uint8](unsafeAddr secretKey[0]),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status)
  output

proc secp256k1EcdsaVerify*(
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1CompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  let status = secp256k1EcdsaVerifyRaw(
    cast[ptr uint8](unsafeAddr messageDigest[0]),
    csize_t(messageDigest.len),
    cast[ptr uint8](unsafeAddr publicKey[0]),
    csize_t(publicKey.len),
    Secp256k1PublicKeyFormatCompressed,
    cast[ptr uint8](unsafeAddr signature[0]),
    csize_t(signature.len),
  )
  verifyStatus(status)

proc secp256k1EcdsaVerify*(
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  let status = secp256k1EcdsaVerifyRaw(
    cast[ptr uint8](unsafeAddr messageDigest[0]),
    csize_t(messageDigest.len),
    cast[ptr uint8](unsafeAddr publicKey[0]),
    csize_t(publicKey.len),
    Secp256k1PublicKeyFormatUncompressed,
    cast[ptr uint8](unsafeAddr signature[0]),
    csize_t(signature.len),
  )
  verifyStatus(status)

proc secp256k1EcdsaSignatureToDer*(
    signature: Secp256k1Signature,
  ): Secp256k1DerSignature =
  var output = newSeq[byte](Secp256k1SignatureDerMaxLen)
  var writtenLen: csize_t
  let status = secp256k1EcdsaSignatureToDerRaw(
    bytesPtr(signature),
    csize_t(signature.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseSignatureDerError(status, "rustcrypto_secp256k1_ecdsa_signature_to_der")
  output.setLen(int(writtenLen))
  output

proc secp256k1EcdsaSignatureFromDer*(
    signatureDer: openArray[byte],
  ): Secp256k1Signature =
  var output: Secp256k1Signature
  let status = secp256k1EcdsaSignatureFromDerRaw(
    bytesPtr(signatureDer),
    csize_t(signatureDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignatureDerError(status, "rustcrypto_secp256k1_ecdsa_signature_from_der")
  output
