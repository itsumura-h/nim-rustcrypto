import ./ecdsa_common
import ./ffi
import ./common

type
  Secp256k1SecretKey* = array[Secp256k1SecretKeyLen, byte]
  Secp256k1CompressedPublicKey* = array[Secp256k1PublicKeyCompressedLen, byte]
  Secp256k1UncompressedPublicKey* = array[Secp256k1PublicKeyUncompressedLen, byte]
  Secp256k1MessageDigest* = ecdsa_common.Secp256k1MessageDigest
  Secp256k1Signature* = ecdsa_common.Secp256k1Signature
  Secp256k1DerSignature* = ecdsa_common.Secp256k1DerSignature

proc raiseIfError(status: cint) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, "rustcrypto_secp256k1_public_key_from_secret_key failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, "rustcrypto_secp256k1_public_key_from_secret_key failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_secp256k1_public_key_from_secret_key failed: null input with data")
  of RustCryptoErrInvalidSecretKey:
    raise newException(ValueError, "rustcrypto_secp256k1_public_key_from_secret_key failed: invalid secret key")
  of RustCryptoErrInvalidPublicKeyFormat:
    raise newException(ValueError, "rustcrypto_secp256k1_public_key_from_secret_key failed: invalid public key format")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_secp256k1_public_key_from_secret_key failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_secp256k1_public_key_from_secret_key failed: unexpected status " & $status,
    )

proc secp256k1PublicKeyCompressed*(secretKey: Secp256k1SecretKey): Secp256k1CompressedPublicKey =
  var output: Secp256k1CompressedPublicKey
  let status = secp256k1PublicKeyFromSecretKeyRaw(
    cast[ptr uint8](unsafeAddr secretKey[0]),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    Secp256k1PublicKeyFormatCompressed,
  )
  raiseIfError(status)
  output

proc secp256k1PublicKeyUncompressed*(secretKey: Secp256k1SecretKey): Secp256k1UncompressedPublicKey =
  var output: Secp256k1UncompressedPublicKey
  let status = secp256k1PublicKeyFromSecretKeyRaw(
    cast[ptr uint8](unsafeAddr secretKey[0]),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    Secp256k1PublicKeyFormatUncompressed,
  )
  raiseIfError(status)
  output

proc secp256k1EcdsaSign*(
    messageDigest: Secp256k1MessageDigest,
    secretKey: Secp256k1SecretKey,
  ): Secp256k1Signature =
  secp256k1EcdsaSignMessage(
    secp256k1EcdsaSignRaw,
    messageDigest,
    secretKey,
    "rustcrypto_secp256k1_ecdsa_sign_prehash",
  )

proc secp256k1EcdsaVerify*(
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1CompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  secp256k1EcdsaVerifyMessage(
    secp256k1EcdsaVerifyRaw,
    messageDigest,
    publicKey,
    signature,
    Secp256k1PublicKeyFormatCompressed,
    "rustcrypto_secp256k1_ecdsa_verify_prehash",
  )

proc secp256k1EcdsaVerify*(
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  secp256k1EcdsaVerifyMessage(
    secp256k1EcdsaVerifyRaw,
    messageDigest,
    publicKey,
    signature,
    Secp256k1PublicKeyFormatUncompressed,
    "rustcrypto_secp256k1_ecdsa_verify_prehash",
  )
