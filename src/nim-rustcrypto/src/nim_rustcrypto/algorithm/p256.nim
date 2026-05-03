import ./ecdsa_common
import ./ffi
import ./common

type
  P256SecretKey* = array[P256SecretKeyLen, byte]
  P256CompressedPublicKey* = array[P256PublicKeyCompressedLen, byte]
  P256UncompressedPublicKey* = array[P256PublicKeyUncompressedLen, byte]
  P256Signature* = array[P256SignatureLen, byte]
  P256MessageDigest* = array[P256MessageDigestLen, byte]
  P256PrivateKeyPkcs8Der* = seq[byte]
  P256PublicKeySpkiDer* = seq[byte]

proc fromHexSecretKey*(hex: string): P256SecretKey =
  fromHexDigest[P256SecretKey](hex, P256SecretKeyLen)

proc fromHexPublicKeyCompressed*(hex: string): P256CompressedPublicKey =
  fromHexDigest[P256CompressedPublicKey](hex, P256PublicKeyCompressedLen)

proc fromHexPublicKeyUncompressed*(hex: string): P256UncompressedPublicKey =
  fromHexDigest[P256UncompressedPublicKey](hex, P256PublicKeyUncompressedLen)

proc fromHexSignature*(hex: string): P256Signature =
  fromHexDigest[P256Signature](hex, P256SignatureLen)

proc fromHexMessageDigest*(hex: string): P256MessageDigest =
  fromHexDigest[P256MessageDigest](hex, P256MessageDigestLen)

proc basePointSecretKey*(): P256SecretKey =
  result = default(P256SecretKey)
  result[P256SecretKeyLen - 1] = 1

proc raiseIfError(status: cint; operation: string) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, operation & " failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, operation & " failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidSecretKey:
    raise newException(ValueError, operation & " failed: invalid secret key")
  of RustCryptoErrInvalidPublicKeyFormat:
    raise newException(ValueError, operation & " failed: invalid public key format")
  of RustCryptoErrInvalidMessageDigest:
    raise newException(ValueError, operation & " failed: invalid message digest")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, operation & " failed: invalid signature")
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, operation & " failed: invalid length")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc p256PublicKeyCompressed*(secretKey: P256SecretKey): P256CompressedPublicKey =
  var output: P256CompressedPublicKey
  let status = p256PublicKeyFromSecretKeyRaw(
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P256PublicKeyFormatCompressed,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_from_secret_key")
  output

proc p256PublicKeyUncompressed*(secretKey: P256SecretKey): P256UncompressedPublicKey =
  var output: P256UncompressedPublicKey
  let status = p256PublicKeyFromSecretKeyRaw(
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P256PublicKeyFormatUncompressed,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_from_secret_key")
  output

proc p256EcdsaSignSha256*(message: string; secretKey: P256SecretKey): P256Signature =
  var output: P256Signature
  let status = p256EcdsaSignSha256Raw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p256_ecdsa_sign_sha256")
  output

proc p256EcdsaVerifySha256*(
    message: string,
    publicKey: openArray[byte],
    publicKeyFormat: cint,
    signature: openArray[byte],
  ): bool =
  let status = p256EcdsaVerifySha256Raw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    publicKeyFormat,
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p256_ecdsa_verify_sha256")

proc p256EcdsaSignPrehash*(
    messageDigest: P256MessageDigest,
    secretKey: P256SecretKey,
): P256Signature =
  var output: P256Signature
  let status = p256EcdsaSignPrehashRaw(
    bytesPtr(messageDigest),
    csize_t(messageDigest.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p256_ecdsa_sign_prehash")
  output

proc p256EcdsaVerifyPrehash*(
    messageDigest: P256MessageDigest,
    publicKey: openArray[byte],
    publicKeyFormat: cint,
    signature: openArray[byte],
): bool =
  let status = p256EcdsaVerifyPrehashRaw(
    bytesPtr(messageDigest),
    csize_t(messageDigest.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    publicKeyFormat,
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p256_ecdsa_verify_prehash")

proc p256PrivateKeyToPkcs8Der*(privateKey: P256SecretKey): P256PrivateKeyPkcs8Der =
  var output = newSeq[byte](P256PrivateKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p256PrivateKeyToPkcs8DerRaw(
    bytesPtr(privateKey),
    csize_t(privateKey.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p256_private_key_to_pkcs8_der")
  output.setLen(int(writtenLen))
  output

proc p256PrivateKeyFromPkcs8Der*(privateKeyDer: openArray[byte]): P256SecretKey =
  var output: P256SecretKey
  let status = p256PrivateKeyFromPkcs8DerRaw(
    bytesPtr(privateKeyDer),
    csize_t(privateKeyDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_p256_private_key_from_pkcs8_der")
  output

proc p256PublicKeyToSpkiDer*(
    publicKey: openArray[byte],
    publicKeyFormat: cint,
  ): P256PublicKeySpkiDer =
  var output = newSeq[byte](P256PublicKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p256PublicKeyToSpkiDerRaw(
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    publicKeyFormat,
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_to_spki_der")
  output.setLen(int(writtenLen))
  output

proc p256PublicKeyFromSpkiDer*(
    publicKeyDer: openArray[byte],
    outputFormat: cint,
): seq[byte] =
  let outputLen = case outputFormat
    of P256PublicKeyFormatCompressed:
      P256PublicKeyCompressedLen
    of P256PublicKeyFormatUncompressed:
      P256PublicKeyUncompressedLen
    else:
      raise newException(ValueError, "rustcrypto_p256_public_key_from_spki_der failed: invalid public key format")

  var output = newSeq[byte](outputLen)
  let status = p256PublicKeyFromSpkiDerRaw(
    bytesPtr(publicKeyDer),
    csize_t(publicKeyDer.len),
    bytesPtr(output),
    csize_t(output.len),
    outputFormat,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_from_spki_der")
  output
