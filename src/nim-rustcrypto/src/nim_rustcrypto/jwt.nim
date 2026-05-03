import std/json
import std/strutils

import ./algorithm/ed25519
import ./algorithm/hmac
import ./algorithm/p256
import ./algorithm/rsa

type
  JwtAlgorithm* = enum
    jwtHS256,
    jwtES256,
    jwtEdDSA,
    jwtRS256,
    jwtPS256
  JwtCompact* = string
  JwtHeaderJson* = string
  JwtClaimsJson* = string
  JwtSecret* = seq[byte]

const
  JwtEcdsaSignatureLen = 64
  JwtEd25519SignatureLen = 64
  JwtP256PublicKeyFormatUncompressed = 0.cint
  JwtP256PublicKeyFormatCompressed = 1.cint

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

proc stringToBytes(data: string): seq[byte] =
  result = newSeq[byte](data.len)
  for i, ch in data:
    result[i] = byte(ord(ch))

proc jwtAlgorithmName(algorithm: JwtAlgorithm): string =
  case algorithm
  of jwtHS256:
    "HS256"
  of jwtES256:
    "ES256"
  of jwtEdDSA:
    "EdDSA"
  of jwtRS256:
    "RS256"
  of jwtPS256:
    "PS256"

proc jwtHeaderAlg(headerJson: string): string =
  let node = parseJson(headerJson)
  if node.kind != JObject or not node.hasKey("alg") or node["alg"].kind != JString:
    raise newException(ValueError, "JWT header must contain a string alg field")
  node["alg"].getStr()

proc requireHeaderAlg(headerJson: string; expectedAlg: string; operation: string) =
  let headerAlg = jwtHeaderAlg(headerJson)
  if headerAlg == "none":
    raise newException(ValueError, operation & " failed: alg none is not supported")
  if headerAlg != expectedAlg:
    raise newException(
      ValueError,
      operation & " failed: header alg " & headerAlg & " does not match " & expectedAlg,
    )

proc tokenAlgMatches(tokenHeaderJson: string; expectedAlg: string; operation: string): bool =
  let headerAlg = jwtHeaderAlg(tokenHeaderJson)
  if headerAlg == "none":
    raise newException(ValueError, operation & " failed: alg none is not supported")
  headerAlg == expectedAlg

proc base64UrlValue(ch: char): int =
  case ch
  of 'A'..'Z':
    ord(ch) - ord('A')
  of 'a'..'z':
    ord(ch) - ord('a') + 26
  of '0'..'9':
    ord(ch) - ord('0') + 52
  of '-':
    62
  of '_':
    63
  else:
    -1

proc jwtBase64UrlEncode*(data: openArray[byte]): string =
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  result = newStringOfCap((data.len * 4 + 2) div 3)
  var i = 0
  while i < data.len:
    let b0 = uint32(data[i])
    let b1 = if i + 1 < data.len: uint32(data[i + 1]) else: 0'u32
    let b2 = if i + 2 < data.len: uint32(data[i + 2]) else: 0'u32
    let triple = (b0 shl 16) or (b1 shl 8) or b2

    result.add(alphabet[int((triple shr 18) and 0x3f)])
    result.add(alphabet[int((triple shr 12) and 0x3f)])
    if i + 1 < data.len:
      result.add(alphabet[int((triple shr 6) and 0x3f)])
    if i + 2 < data.len:
      result.add(alphabet[int(triple and 0x3f)])

    i += 3

proc jwtBase64UrlEncode*(data: string): string =
  jwtBase64UrlEncode(stringToBytes(data))

proc jwtBase64UrlDecode*(data: string): seq[byte] =
  if data.len mod 4 == 1:
    raise newException(ValueError, "invalid base64url length")

  var buffer: uint32 = 0
  var bits = 0
  result = @[]

  for ch in data:
    let value = base64UrlValue(ch)
    if value < 0:
      raise newException(ValueError, "invalid base64url character")

    buffer = (buffer shl 6) or uint32(value)
    bits += 6

    while bits >= 8:
      bits -= 8
      result.add(byte((buffer shr bits) and 0xff))
      if bits > 0:
        buffer = buffer and ((uint32(1) shl bits) - 1)
      else:
        buffer = 0

  if bits > 0 and buffer != 0:
    raise newException(ValueError, "invalid base64url padding")

proc jwtSigningInput*(headerJson: string; claimsJson: string): string =
  jwtBase64UrlEncode(headerJson) & "." & jwtBase64UrlEncode(claimsJson)

proc jwtCompactParts(token: string): tuple[header, claims, signature: string] =
  let first = token.find('.')
  let last = token.rfind('.')
  if first <= 0 or last <= first or last == token.len - 1:
    raise newException(ValueError, "invalid JWS compact serialization")

  result.header = token[0 ..< first]
  result.claims = token[first + 1 ..< last]
  result.signature = token[last + 1 ..< token.len]

proc jwtSignedToken(signingInput: string; signature: openArray[byte]): JwtCompact =
  signingInput & "." & jwtBase64UrlEncode(signature)

proc jwtCompactSignatureBytes(tokenSignature: string): seq[byte] =
  jwtBase64UrlDecode(tokenSignature)

proc jwtVerifyAlg(tokenHeaderPart: string; expectedAlg: string; operation: string): bool =
  let headerJson = bytesToString(jwtBase64UrlDecode(tokenHeaderPart))
  tokenAlgMatches(headerJson, expectedAlg, operation)

proc sameBytes(actual: seq[byte]; expected: openArray[byte]): bool =
  if actual.len != expected.len:
    return false
  for i in 0 ..< actual.len:
    if actual[i] != expected[i]:
      return false
  true

proc jwtSignHS256*(headerJson: string; claimsJson: string; secret: openArray[byte]): JwtCompact =
  requireHeaderAlg(headerJson, jwtAlgorithmName(jwtHS256), "jwtSignHS256")
  let signingInput = jwtSigningInput(headerJson, claimsJson)
  let mac = hmacSha256(bytesToString(secret), signingInput)
  jwtSignedToken(signingInput, mac)

proc jwtVerifyHS256*(token: JwtCompact; secret: openArray[byte]): bool =
  let parts = jwtCompactParts(token)
  if not jwtVerifyAlg(parts.header, jwtAlgorithmName(jwtHS256), "jwtVerifyHS256"):
    return false

  let signingInput = parts.header & "." & parts.claims
  let expected = hmacSha256(bytesToString(secret), signingInput)
  let actual = jwtCompactSignatureBytes(parts.signature)
  if actual.len != expected.len:
    raise newException(ValueError, "jwtVerifyHS256 failed: invalid signature length")
  sameBytes(actual, expected)

proc jwtSignES256*(headerJson: string; claimsJson: string; secretKey: P256SecretKey): JwtCompact =
  requireHeaderAlg(headerJson, jwtAlgorithmName(jwtES256), "jwtSignES256")
  let signingInput = jwtSigningInput(headerJson, claimsJson)
  let signature = p256EcdsaSignSha256(signingInput, secretKey)
  jwtSignedToken(signingInput, signature)

proc jwtVerifyES256*(token: JwtCompact; publicKey: P256CompressedPublicKey): bool =
  let parts = jwtCompactParts(token)
  if not jwtVerifyAlg(parts.header, jwtAlgorithmName(jwtES256), "jwtVerifyES256"):
    return false

  let signingInput = parts.header & "." & parts.claims
  let signature = jwtCompactSignatureBytes(parts.signature)
  if signature.len != JwtEcdsaSignatureLen:
    raise newException(ValueError, "jwtVerifyES256 failed: invalid signature length")
  p256EcdsaVerifySha256(signingInput, publicKey, JwtP256PublicKeyFormatCompressed, signature)

proc jwtVerifyES256*(token: JwtCompact; publicKey: P256UncompressedPublicKey): bool =
  let parts = jwtCompactParts(token)
  if not jwtVerifyAlg(parts.header, jwtAlgorithmName(jwtES256), "jwtVerifyES256"):
    return false

  let signingInput = parts.header & "." & parts.claims
  let signature = jwtCompactSignatureBytes(parts.signature)
  if signature.len != JwtEcdsaSignatureLen:
    raise newException(ValueError, "jwtVerifyES256 failed: invalid signature length")
  p256EcdsaVerifySha256(signingInput, publicKey, JwtP256PublicKeyFormatUncompressed, signature)

proc jwtSignEdDSA*(headerJson: string; claimsJson: string; secretKey: Ed25519SecretKey): JwtCompact =
  requireHeaderAlg(headerJson, jwtAlgorithmName(jwtEdDSA), "jwtSignEdDSA")
  let signingInput = jwtSigningInput(headerJson, claimsJson)
  let signature = ed25519Sign(signingInput, secretKey)
  jwtSignedToken(signingInput, signature)

proc jwtVerifyEdDSA*(token: JwtCompact; publicKey: Ed25519PublicKey): bool =
  let parts = jwtCompactParts(token)
  if not jwtVerifyAlg(parts.header, jwtAlgorithmName(jwtEdDSA), "jwtVerifyEdDSA"):
    return false

  let signingInput = parts.header & "." & parts.claims
  let signature = jwtCompactSignatureBytes(parts.signature)
  if signature.len != JwtEd25519SignatureLen:
    raise newException(ValueError, "jwtVerifyEdDSA failed: invalid signature length")
  var fixedSignature: Ed25519Signature
  for i in 0 ..< JwtEd25519SignatureLen:
    fixedSignature[i] = signature[i]
  ed25519Verify(signingInput, publicKey, fixedSignature)

proc jwtSignRS256*(headerJson: string; claimsJson: string; privateKeyDer: openArray[byte]): JwtCompact =
  requireHeaderAlg(headerJson, jwtAlgorithmName(jwtRS256), "jwtSignRS256")
  let signingInput = jwtSigningInput(headerJson, claimsJson)
  let signature = rsaPkcs1v15SignSha256(signingInput, privateKeyDer)
  jwtSignedToken(signingInput, signature)

proc jwtVerifyRS256*(token: JwtCompact; publicKeyDer: openArray[byte]): bool =
  let parts = jwtCompactParts(token)
  if not jwtVerifyAlg(parts.header, jwtAlgorithmName(jwtRS256), "jwtVerifyRS256"):
    return false

  let signingInput = parts.header & "." & parts.claims
  let signature = jwtCompactSignatureBytes(parts.signature)
  rsaPkcs1v15VerifySha256(signingInput, publicKeyDer, signature)

proc jwtSignPS256*(headerJson: string; claimsJson: string; privateKeyDer: openArray[byte]): JwtCompact =
  requireHeaderAlg(headerJson, jwtAlgorithmName(jwtPS256), "jwtSignPS256")
  let signingInput = jwtSigningInput(headerJson, claimsJson)
  let signature = rsaPssSignSha256(signingInput, privateKeyDer)
  jwtSignedToken(signingInput, signature)

proc jwtVerifyPS256*(token: JwtCompact; publicKeyDer: openArray[byte]): bool =
  let parts = jwtCompactParts(token)
  if not jwtVerifyAlg(parts.header, jwtAlgorithmName(jwtPS256), "jwtVerifyPS256"):
    return false

  let signingInput = parts.header & "." & parts.claims
  let signature = jwtCompactSignatureBytes(parts.signature)
  rsaPssVerifySha256(signingInput, publicKeyDer, signature)
