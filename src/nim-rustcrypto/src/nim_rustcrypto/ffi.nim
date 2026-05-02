const rustCryptoStaticLib* = "../rustcrypto-ffi/target/release/librust_crypto_ffi.a"

{.passL: rustCryptoStaticLib.}

const
  SHA256DigestLen* = 32
  HmacSha256MacLen* = 32
  Sha3_256DigestLen* = 32
  Keccak256DigestLen* = 32
  Secp256k1SecretKeyLen* = 32
  Secp256k1PublicKeyCompressedLen* = 33
  Secp256k1PublicKeyUncompressedLen* = 65
  Secp256k1SignatureLen* = 64
  Secp256k1SignatureDerMaxLen* = 72
  Secp256k1MessageDigestLen* = 32
  Ed25519PrivateKeyLen* = 32
  Ed25519PublicKeyLen* = 32
  Ed25519SignatureLen* = 64
  Ed25519PrivateKeyDerMaxLen* = 48
  Ed25519PublicKeyDerMaxLen* = 44
  Ed25519PrivateKeyPemMaxLen* = 119
  Ed25519PublicKeyPemMaxLen* = 113
  ChaCha20Poly1305KeyLen* = 32
  ChaCha20Poly1305NonceLen* = 12
  ChaCha20Poly1305TagLen* = 16
  RustCryptoOk* = 0.cint
  RustCryptoErrNullOutput* = 1.cint
  RustCryptoErrOutputTooShort* = 2.cint
  RustCryptoErrNullInputWithData* = 3.cint
  RustCryptoErrInvalidSecretKey* = 4.cint
  RustCryptoErrInvalidPublicKeyFormat* = 5.cint
  RustCryptoErrInvalidMessageDigest* = 6.cint
  RustCryptoErrInvalidSignature* = 7.cint
  RustCryptoErrVerificationFailed* = 8.cint
  RustCryptoErrInvalidLength* = 9.cint
  RustCryptoErrInvalidPrkLength* = 10.cint
  RustCryptoErrAuthenticationFailed* = 11.cint
  RustCryptoErrInvalidKeyLength* = 12.cint
  RustCryptoErrInvalidNonceLength* = 13.cint
  RustCryptoErrInvalidTagLength* = 14.cint
  RustCryptoErrInvalidParameter* = 15.cint
  RustCryptoErrPanic* = -1.cint
  Secp256k1PublicKeyFormatUncompressed* = 0.cint
  Secp256k1PublicKeyFormatCompressed* = 1.cint
  HkdfSha256PrkLen* = 32
  HkdfSha256MaxOkmLen* = 32 * 255

proc sha256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_sha256".}

proc hmacSha256Raw*(
    key: ptr uint8,
    keyLen: csize_t,
    message: ptr uint8,
    messageLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hmac_sha256".}

proc pbkdf2HmacSha256Raw*(
    password: ptr uint8,
    passwordLen: csize_t,
    salt: ptr uint8,
    saltLen: csize_t,
    iterations: cuint,
    output: ptr uint8,
    outputLen: csize_t,
    derivedLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_pbkdf2_hmac_sha256".}

proc hkdfSha256ExtractRaw*(
    salt: ptr uint8,
    saltLen: csize_t,
    ikm: ptr uint8,
    ikmLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hkdf_sha256_extract".}

proc hkdfSha256ExpandRaw*(
    prk: ptr uint8,
    prkLen: csize_t,
    info: ptr uint8,
    infoLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hkdf_sha256_expand".}

proc hkdfSha256DeriveRaw*(
    salt: ptr uint8,
    saltLen: csize_t,
    ikm: ptr uint8,
    ikmLen: csize_t,
    info: ptr uint8,
    infoLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hkdf_sha256_derive".}

proc chacha20Poly1305EncryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_chacha20poly1305_encrypt".}

proc chacha20Poly1305DecryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_chacha20poly1305_decrypt".}

proc sha3_256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_sha3_256".}

proc keccak256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_keccak_256".}

proc secp256k1PublicKeyFromSecretKeyRaw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_public_key_from_secret_key".}

proc secp256k1EcdsaSignRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_sign_prehash".}

proc secp256k1EcdsaVerifyRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_verify_prehash".}

proc secp256k1EcdsaSignatureToDerRaw*(
    signature: ptr uint8,
    signatureLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_signature_to_der".}

proc secp256k1EcdsaSignatureFromDerRaw*(
    derSignature: ptr uint8,
    derSignatureLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_signature_from_der".}

proc ed25519PrivateKeyToPkcs8DerRaw*(
    privateKey: ptr uint8,
    privateKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_to_pkcs8_der".}

proc ed25519PrivateKeyFromPkcs8DerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_from_pkcs8_der".}

proc ed25519PublicKeyToSpkiDerRaw*(
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_to_spki_der".}

proc ed25519PublicKeyFromSpkiDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_from_spki_der".}

proc ed25519PublicKeyFromSecretKeyRaw*(
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_from_secret_key".}

proc ed25519SignRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_sign".}

proc ed25519VerifyRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_verify".}

proc ed25519PrivateKeyToPkcs8PemRaw*(
    privateKey: ptr uint8,
    privateKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_to_pkcs8_pem".}

proc ed25519PrivateKeyFromPkcs8PemRaw*(
    pem: ptr uint8,
    pemLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_from_pkcs8_pem".}

proc ed25519PublicKeyToSpkiPemRaw*(
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_to_spki_pem".}

proc ed25519PublicKeyFromSpkiPemRaw*(
    pem: ptr uint8,
    pemLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_from_spki_pem".}
