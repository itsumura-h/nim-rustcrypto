import ./ecdsa_common
import ./ffi
import ./common

type
  P384SecretKey* = array[P384SecretKeyLen, byte]
  P384CompressedPublicKey* = array[P384PublicKeyCompressedLen, byte]
  P384UncompressedPublicKey* = array[P384PublicKeyUncompressedLen, byte]
  P384Signature* = array[P384SignatureLen, byte]
  P384MessageDigest* = array[P384MessageDigestLen, byte]
  P384PrivateKeyPkcs8Der* = seq[byte]
  P384PublicKeySpkiDer* = seq[byte]

proc fromHexSecretKey*(hex: string): P384SecretKey =
  fromHexDigest[P384SecretKey](hex, P384SecretKeyLen)

proc fromHexPublicKeyCompressed*(hex: string): P384CompressedPublicKey =
  fromHexDigest[P384CompressedPublicKey](hex, P384PublicKeyCompressedLen)

proc fromHexPublicKeyUncompressed*(hex: string): P384UncompressedPublicKey =
  fromHexDigest[P384UncompressedPublicKey](hex, P384PublicKeyUncompressedLen)

proc fromHexSignature*(hex: string): P384Signature =
  fromHexDigest[P384Signature](hex, P384SignatureLen)

proc fromHexMessageDigest*(hex: string): P384MessageDigest =
  fromHexDigest[P384MessageDigest](hex, P384MessageDigestLen)

proc basePointSecretKey*(): P384SecretKey =
  result = default(P384SecretKey)
  result[P384SecretKeyLen - 1] = 1

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

proc p384PublicKeyCompressed*(secretKey: P384SecretKey): P384CompressedPublicKey =
  var output: P384CompressedPublicKey
  let status = p384PublicKeyFromSecretKeyRaw(
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P384PublicKeyFormatCompressed,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_from_secret_key")
  output

proc p384PublicKeyUncompressed*(secretKey: P384SecretKey): P384UncompressedPublicKey =
  var output: P384UncompressedPublicKey
  let status = p384PublicKeyFromSecretKeyRaw(
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P384PublicKeyFormatUncompressed,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_from_secret_key")
  output

proc p384EcdsaSignSha384*(message: string; secretKey: P384SecretKey): P384Signature =
  var output: P384Signature
  let status = p384EcdsaSignSha384Raw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p384_ecdsa_sign_sha384")
  output

proc p384EcdsaVerifySha384*(
    message: string,
    publicKey: openArray[byte],
    publicKeyFormat: cint,
    signature: openArray[byte],
  ): bool =
  let status = p384EcdsaVerifySha384Raw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    publicKeyFormat,
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p384_ecdsa_verify_sha384")

proc p384EcdsaSignPrehash*(
    messageDigest: P384MessageDigest,
    secretKey: P384SecretKey,
): P384Signature =
  var output: P384Signature
  let status = p384EcdsaSignPrehashRaw(
    bytesPtr(messageDigest),
    csize_t(messageDigest.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p384_ecdsa_sign_prehash")
  output

proc p384EcdsaVerifyPrehash*(
    messageDigest: P384MessageDigest,
    publicKey: openArray[byte],
    publicKeyFormat: cint,
    signature: openArray[byte],
): bool =
  let status = p384EcdsaVerifyPrehashRaw(
    bytesPtr(messageDigest),
    csize_t(messageDigest.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    publicKeyFormat,
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p384_ecdsa_verify_prehash")

proc p384PrivateKeyToPkcs8Der*(privateKey: P384SecretKey): P384PrivateKeyPkcs8Der =
  var output = newSeq[byte](P384PrivateKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p384PrivateKeyToPkcs8DerRaw(
    bytesPtr(privateKey),
    csize_t(privateKey.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p384_private_key_to_pkcs8_der")
  output.setLen(int(writtenLen))
  output

proc p384PrivateKeyFromPkcs8Der*(privateKeyDer: openArray[byte]): P384SecretKey =
  var output: P384SecretKey
  let status = p384PrivateKeyFromPkcs8DerRaw(
    bytesPtr(privateKeyDer),
    csize_t(privateKeyDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_p384_private_key_from_pkcs8_der")
  output

proc p384PublicKeyToSpkiDer*(
    publicKey: openArray[byte],
    publicKeyFormat: cint,
  ): P384PublicKeySpkiDer =
  var output = newSeq[byte](P384PublicKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p384PublicKeyToSpkiDerRaw(
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    publicKeyFormat,
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_to_spki_der")
  output.setLen(int(writtenLen))
  output

proc p384PublicKeyFromSpkiDer*(
    publicKeyDer: openArray[byte],
    outputFormat: cint,
): seq[byte] =
  let outputLen = case outputFormat
    of P384PublicKeyFormatCompressed:
      P384PublicKeyCompressedLen
    of P384PublicKeyFormatUncompressed:
      P384PublicKeyUncompressedLen
    else:
      raise newException(ValueError, "rustcrypto_p384_public_key_from_spki_der failed: invalid public key format")

  var output = newSeq[byte](outputLen)
  let status = p384PublicKeyFromSpkiDerRaw(
    bytesPtr(publicKeyDer),
    csize_t(publicKeyDer.len),
    bytesPtr(output),
    csize_t(output.len),
    outputFormat,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_from_spki_der")
  output
