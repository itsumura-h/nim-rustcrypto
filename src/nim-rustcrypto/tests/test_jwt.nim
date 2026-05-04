import std/json
import std/strutils
import unittest

import ./utils
import rustcrypto/algorithm/ed25519
import rustcrypto/algorithm/p256
import rustcrypto/jwt

const
  Hs256Header = """{"alg":"HS256","typ":"JWT"}"""
  Es256Header = """{"alg":"ES256","typ":"JWT"}"""
  EdDsaHeader = """{"alg":"EdDSA","typ":"JWT"}"""
  Rs256Header = """{"alg":"RS256","typ":"JWT"}"""
  Ps256Header = """{"alg":"PS256","typ":"JWT"}"""
  ClaimsJson = """{"sub":"1234567890","name":"John Doe","admin":true}"""
  P256SecretKeyHex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
  Ed25519SecretKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

suite "jwt":
  test "base64url encoding omits padding":
    check jwtBase64UrlEncode(bytesFromString("foo")) == "Zm9v"
    check jwtBase64UrlEncode(bytesFromString("fo")) == "Zm8"
    check jwtBase64UrlDecode("Zm9v") == bytesFromString("foo")
    check jwtBase64UrlDecode("Zm8") == bytesFromString("fo")

  test "signing input is the dot-joined base64url payload":
    let input = jwtSigningInput(Hs256Header, ClaimsJson)

    check input == jwtBase64UrlEncode(Hs256Header) & "." & jwtBase64UrlEncode(ClaimsJson)

  test "HS256 signing and verification round-trip":
    let secret = bytesFromString("super-secret")
    let token = jwtSignHS256(Hs256Header, ClaimsJson, secret)

    check jwtVerifyHS256(token, secret)

    let tamperedHeader = jwtBase64UrlEncode("""{"alg":"ES256","typ":"JWT"}""")
    let parts = token.split('.')
    check not jwtVerifyHS256(tamperedHeader & "." & parts[1] & "." & parts[2], secret)

    expect ValueError:
      discard jwtSignHS256("""{"alg":"none","typ":"JWT"}""", ClaimsJson, secret)

  test "ES256 signing and verification round-trip":
    let secretKey = fromHexDigest[P256SecretKey](P256SecretKeyHex, 32)
    let compressedPublicKey = p256PublicKeyCompressed(secretKey)
    let uncompressedPublicKey = p256PublicKeyUncompressed(secretKey)
    let token = jwtSignES256(Es256Header, ClaimsJson, secretKey)

    check jwtVerifyES256(token, compressedPublicKey)
    check jwtVerifyES256(token, uncompressedPublicKey)

    let tamperedHeader = jwtBase64UrlEncode(Hs256Header)
    let parts = token.split('.')
    check not jwtVerifyES256(tamperedHeader & "." & parts[1] & "." & parts[2], compressedPublicKey)

  test "EdDSA signing and verification round-trip":
    let secretKey = ed25519.fromHexSecretKey(Ed25519SecretKeyHex)
    let publicKey = ed25519PublicKeyFromSecretKey(secretKey)
    let token = jwtSignEdDSA(EdDsaHeader, ClaimsJson, secretKey)

    check jwtVerifyEdDSA(token, publicKey)

  test "RS256 signing and verification round-trip":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    let token = jwtSignRS256(Rs256Header, ClaimsJson, privateKeyDer)

    check jwtVerifyRS256(token, publicKeyDer)

  test "PS256 signing and verification round-trip":
    let privateKeyDer = bytesFromString(Rsa2048PrivateKeyDerFixture)
    let publicKeyDer = bytesFromString(Rsa2048PublicKeyDerFixture)
    let token = jwtSignPS256(Ps256Header, ClaimsJson, privateKeyDer)

    check jwtVerifyPS256(token, publicKeyDer)

  test "marker type API round-trips with JWKs":
    let payload = %*{
      "sub": 1234567890,
      "name": "John Doe",
      "admin": true
    }

    let hsSecret = Jwt.generateSecretKey(jwtHS256)
    let hsPublic = Jwt.publicKey(hsSecret)
    let hsToken = Jwt.sign(jwtHS256, payload, hsSecret)
    let hsJwk = parseJson($hsSecret)
    let hsPublicJwk = parseJson($hsPublic)

    check hsJwk["kty"].getStr() == "oct"
    check not hsJwk.hasKey("d")
    check hsPublicJwk == hsJwk
    check Jwt.verify(jwtHS256, hsPublic, hsToken)
    check Jwt.decode(hsToken) == payload

    let esSecret = Jwt.generateSecretKey(jwtES256)
    let esPublic = Jwt.publicKey(esSecret)
    let esToken = Jwt.sign(jwtES256, payload, esSecret)
    let esJwk = parseJson($esSecret)
    let esPublicJwk = parseJson($esPublic)

    check esJwk["kty"].getStr() == "EC"
    check esJwk["crv"].getStr() == "P-256"
    check esJwk.hasKey("d")
    check not esPublicJwk.hasKey("d")
    check Jwt.verify(jwtES256, esPublic, esToken)
    check Jwt.decode(esToken) == payload

    let edSecret = Jwt.generateSecretKey(jwtEdDSA)
    let edPublic = Jwt.publicKey(edSecret)
    let edToken = Jwt.sign(jwtEdDSA, payload, edSecret)
    let edJwk = parseJson($edSecret)
    let edPublicJwk = parseJson($edPublic)

    check edJwk["kty"].getStr() == "OKP"
    check edJwk["crv"].getStr() == "Ed25519"
    check edJwk.hasKey("d")
    check not edPublicJwk.hasKey("d")
    check Jwt.verify(jwtEdDSA, edPublic, edToken)
    check Jwt.decode(edToken) == payload
