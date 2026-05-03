import ./common
import ./ecdsa_common
import ./ffi

type
  SchnorrSecretKey* = array[Secp256k1SecretKeyLen, byte]
  SchnorrPublicKey* = array[SchnorrPublicKeyLen, byte]
  SchnorrSignature* = array[SchnorrSignatureLen, byte]

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
