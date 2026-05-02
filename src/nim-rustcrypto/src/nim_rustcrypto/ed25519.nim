import ./ffi
import ./pkcs8
import ./utils

type
  Ed25519SecretKey* = pkcs8.Ed25519PrivateKey
  Ed25519PublicKey* = pkcs8.Ed25519PublicKey
  Ed25519Signature* = array[Ed25519SignatureLen, byte]

proc fromHexSecretKey*(hex: string): Ed25519SecretKey =
  fromHexDigest[Ed25519SecretKey](hex, Ed25519PrivateKeyLen)

proc fromHexPublicKey*(hex: string): Ed25519PublicKey =
  fromHexDigest[Ed25519PublicKey](hex, Ed25519PublicKeyLen)

proc fromHexSignature*(hex: string): Ed25519Signature =
  fromHexDigest[Ed25519Signature](hex, Ed25519SignatureLen)

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
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, operation & " failed: invalid signature")
  of RustCryptoErrVerificationFailed:
    raise newException(ValueError, operation & " failed: verification failed")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc verifyStatus(status: cint): bool =
  case status
  of RustCryptoOk:
    true
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_ed25519_verify failed: null input with data")
  of RustCryptoErrInvalidPublicKeyFormat:
    raise newException(ValueError, "rustcrypto_ed25519_verify failed: invalid public key format")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, "rustcrypto_ed25519_verify failed: invalid signature")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_ed25519_verify failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_ed25519_verify failed: unexpected status " & $status,
    )

proc ed25519PublicKeyFromSecretKey*(
    secretKey: Ed25519SecretKey,
  ): Ed25519PublicKey =
  var output: Ed25519PublicKey
  let status = ed25519PublicKeyFromSecretKeyRaw(
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_ed25519_public_key_from_secret_key")
  output

proc ed25519Sign*(
    message: string,
    secretKey: Ed25519SecretKey,
  ): Ed25519Signature =
  var output: Ed25519Signature
  let status = ed25519SignRaw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_ed25519_sign")
  output

proc ed25519Verify*(
    message: string,
    publicKey: Ed25519PublicKey,
    signature: Ed25519Signature,
  ): bool =
  let status = ed25519VerifyRaw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status)
