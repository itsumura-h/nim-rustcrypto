import ./common
import ./ecdsa_common
import ./ffi

type
  SchnorrSecretKey* = array[Secp256k1SecretKeyLen, byte]
  SchnorrPublicKey* = array[SchnorrPublicKeyLen, byte]
  SchnorrSignature* = array[SchnorrSignatureLen, byte]

proc `$`*(value: SchnorrPublicKey): string =
  bytesToHexString(value)

proc `$`*(value: SchnorrSignature): string =
  bytesToHexString(value)

proc randomSecretKey*(): SchnorrSecretKey =
  while true:
    result = urandomBytes[Secp256k1SecretKeyLen]()
    var publicKey: SchnorrPublicKey
    let status = schnorrPublicKeyFromSecretKeyRaw(
      bytesPtr(result),
      csize_t(result.len),
      cast[ptr uint8](addr publicKey[0]),
      csize_t(publicKey.len),
    )
    case status
    of RustCryptoOk:
      return result
    of RustCryptoErrInvalidSecretKey:
      discard
    of RustCryptoErrPanic:
      raise newException(ValueError, "rustcrypto_secp256k1_random_secret_key failed: panic")
    else:
      raise newException(
        ValueError,
        "rustcrypto_secp256k1_random_secret_key failed: unexpected status " & $status,
      )

proc schnorrPublicKey*(secretKey: SchnorrSecretKey): SchnorrPublicKey =
  var output: SchnorrPublicKey
  let status = schnorrPublicKeyFromSecretKeyRaw(
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_secp256k1_schnorr_public_key_from_secret_key")
  output

proc schnorrSign*(message: string, secretKey: SchnorrSecretKey): SchnorrSignature =
  var output: SchnorrSignature
  let status = schnorrSignRaw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_secp256k1_schnorr_sign")
  output

proc schnorrSign*(message: openArray[byte], secretKey: SchnorrSecretKey): SchnorrSignature =
  var output: SchnorrSignature
  let status = schnorrSignRaw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_secp256k1_schnorr_sign")
  output

proc schnorrVerify*(message: string, publicKey: SchnorrPublicKey, signature: SchnorrSignature): bool =
  let status = schnorrVerifyRaw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_secp256k1_schnorr_verify")

proc schnorrVerify*(message: openArray[byte], publicKey: SchnorrPublicKey, signature: SchnorrSignature): bool =
  let status = schnorrVerifyRaw(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_secp256k1_schnorr_verify")
