import ./algorithm/sha3
import ./algorithm/secp256k1

type
  Ethereum* = object
  EthereumAddress* = array[20, byte]
  EthereumHash* = array[32, byte]
  EthereumSignature* = object
    r*: array[32, byte]
    s*: array[32, byte]
    v*: byte
  EthereumChainId* = uint64

const EthereumRecoverableSignatureLen = 65

proc ethereumKeccak256(data: openArray[byte]): EthereumHash
proc ethereumAddress(publicKey: Secp256k1UncompressedPublicKey): EthereumAddress
proc ethereumPersonalMessageHash(message: string): EthereumHash
proc ethereumTypedDataHash(domainSeparator: EthereumHash; structHash: EthereumHash): EthereumHash
proc ethereumSignPersonalMessage(
    message: string,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature
proc ethereumVerifyPersonalMessage(
    message: string,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: EthereumSignature,
  ): bool
proc ethereumSignTypedDataHash(
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature
proc ethereumVerifyTypedDataHash(
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: EthereumSignature,
  ): bool

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

proc ethereumKeccak256(data: openArray[byte]): EthereumHash =
  keccak256(bytesToString(data))

proc keccak256*(T: type Ethereum, data: openArray[byte]): EthereumHash =
  ethereumKeccak256(data)

proc ethereumAddress(publicKey: Secp256k1UncompressedPublicKey): EthereumAddress =
  if publicKey[0] != 0x04:
    raise newException(ValueError, "ethereum address requires an uncompressed SEC1 public key")

  let digest = ethereumKeccak256(publicKey[1 ..< publicKey.len])
  for i in 0 ..< result.len:
    result[i] = digest[digest.len - result.len + i]

proc address*(T: type Ethereum, publicKey: Secp256k1UncompressedPublicKey): EthereumAddress =
  ethereumAddress(publicKey)

proc ethereumPersonalMessageHash(message: string): EthereumHash =
  keccak256("\x19Ethereum Signed Message:\n" & $message.len & message)

proc personalMessageHash*(T: type Ethereum, message: string): EthereumHash =
  ethereumPersonalMessageHash(message)

proc ethereumTypedDataHash(domainSeparator: EthereumHash; structHash: EthereumHash): EthereumHash =
  keccak256("\x19\x01" & bytesToString(domainSeparator) & bytesToString(structHash))

proc typedDataHash*(
    T: type Ethereum,
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
  ): EthereumHash =
  ethereumTypedDataHash(domainSeparator, structHash)

proc ethereumSignatureFromRecoverable(
  signature: Secp256k1RecoverableSignature,
    chainId: EthereumChainId,
  ): EthereumSignature =
  let recoveryId = signature[EthereumRecoverableSignatureLen - 1]
  let parity = recoveryId and 1
  let vValue =
    if chainId == 0:
      27'u64 + uint64(parity)
    else:
      35'u64 + chainId * 2'u64 + uint64(parity)

  if vValue > high(byte).uint64:
    raise newException(ValueError, "ethereum recovery id is too large to encode in v")

  result.v = byte(vValue)
  for i in 0 ..< 32:
    result.r[i] = signature[i]
    result.s[i] = signature[32 + i]

proc ethereumRecoverableSignature(
    signature: EthereumSignature,
  ): tuple[signature: Secp256k1RecoverableSignature, valid: bool] =
  if signature.v == 27'u8 or signature.v == 28'u8:
    let parity = signature.v - 27
    for i in 0 ..< 32:
      result.signature[i] = signature.r[i]
      result.signature[32 + i] = signature.s[i]
    result.signature[64] = parity
    result.valid = true
  elif signature.v >= 35:
    let parity = signature.v and 1
    for i in 0 ..< 32:
      result.signature[i] = signature.r[i]
      result.signature[32 + i] = signature.s[i]
    result.signature[64] = parity
    result.valid = true
  else:
    result.valid = false

proc signPersonalMessage*(
    T: type Ethereum,
    message: string,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature =
  ethereumSignPersonalMessage(message, secretKey, chainId)

proc verifyPersonalMessage*(
    T: type Ethereum,
    message: string,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: EthereumSignature,
  ): bool =
  ethereumVerifyPersonalMessage(message, publicKey, signature)

proc signTypedDataHash*(
    T: type Ethereum,
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature =
  ethereumSignTypedDataHash(domainSeparator, structHash, secretKey, chainId)

proc verifyTypedDataHash*(
    T: type Ethereum,
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: EthereumSignature,
  ): bool =
  ethereumVerifyTypedDataHash(domainSeparator, structHash, publicKey, signature)

proc ethereumSignPersonalMessage(
    message: string,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature =
  let digest = ethereumPersonalMessageHash(message)
  ethereumSignatureFromRecoverable(Secp256k1.signRecoverable(digest, secretKey), chainId)

proc ethereumVerifyPersonalMessage(
    message: string,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: EthereumSignature,
  ): bool =
  let digest = ethereumPersonalMessageHash(message)
  let recovered = ethereumRecoverableSignature(signature)
  if not recovered.valid:
    raise newException(ValueError, "ethereum signature has an unsupported v value")

  for candidate in [0'u8, 1'u8, 2'u8, 3'u8]:
    var trial = recovered.signature
    trial[64] = candidate
    if Secp256k1.verifyRecoverable(digest, publicKey, trial):
      return true

  false

proc ethereumSignTypedDataHash(
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature =
  let digest = ethereumTypedDataHash(domainSeparator, structHash)
  ethereumSignatureFromRecoverable(Secp256k1.signRecoverable(digest, secretKey), chainId)

proc ethereumVerifyTypedDataHash(
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: EthereumSignature,
  ): bool =
  let digest = ethereumTypedDataHash(domainSeparator, structHash)
  let recovered = ethereumRecoverableSignature(signature)
  if not recovered.valid:
    raise newException(ValueError, "ethereum signature has an unsupported v value")

  for candidate in [0'u8, 1'u8, 2'u8, 3'u8]:
    var trial = recovered.signature
    trial[64] = candidate
    if Secp256k1.verifyRecoverable(digest, publicKey, trial):
      return true

  false
